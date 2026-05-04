"""Origin IP discovery — find the real server behind CDN/WAF.

Techniques:
- Subdomain IP leakage (subdomains not behind CDN)
- SSL certificate inspection
- Historical DNS via ViewDNS.info
- Favicon hash matching via Shodan/FOFA/ZoomEye
- GitHub repository leak searching
- Censys certificate search
- SecurityTrails historical DNS
"""

import re
import ssl
import socket
import hashlib
import base64
import concurrent.futures
from cryptography import x509
from cryptography.x509.oid import NameOID

try:
    import mmh3
except ImportError:
    mmh3 = None

from . import dns_resolver, asn_lookup, api_keys

# Subdomains commonly NOT behind CDN protection
LEAK_SUBDOMAINS = [
    "direct", "origin", "backend", "server", "real",
    "mail", "smtp", "pop", "imap", "webmail", "mx",
    "ftp", "sftp", "ssh", "vpn",
    "admin", "panel", "cpanel", "whm", "webdisk",
    "autodiscover",
    "dev", "staging", "stage", "test", "qa",
    "internal", "intranet", "local",
    "api", "api2", "api-v2", "graphql",
    "old", "legacy", "backup", "bak",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "ns1", "ns2", "ns3",
    "cdn", "assets", "static", "media", "img",
    "monitor", "status", "health",
]

CDN_CERT_ISSUERS = [
    "cloudflare", "amazon", "fastly", "akamai",
    "incapsula", "imperva", "sucuri", "stackpath",
    "google trust", "digicert",  # digicert is common but not always CDN
]


def find_origins(domain, cdn_ips=None, max_workers=20, timeout=3):
    """Scan for origin IPs via subdomain leakage.

    Args:
        domain: base domain (e.g. example.com)
        cdn_ips: set of IPs known to be CDN (to filter out)
        max_workers: thread pool size
        timeout: DNS resolution timeout per subdomain

    Returns:
        list of dicts: ip, source, subdomain, asn_info
    """
    cdn_ips = cdn_ips or set()
    candidates = []
    seen_ips = set()

    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        ips = dns_resolver.resolve_ip(fqdn)
        results = []
        for ip in ips:
            if ip not in cdn_ips and ip not in seen_ips:
                seen_ips.add(ip)
                results.append({
                    "ip": ip,
                    "source": f"subdomain:{fqdn}",
                    "subdomain": sub,
                    "asn_info": None,
                })
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check_sub, sub): sub for sub in LEAK_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures, timeout=60):
            try:
                results = future.result(timeout=timeout)
                candidates.extend(results)
            except Exception:
                pass

    # Enrich with ASN info
    if candidates:
        ips = [c["ip"] for c in candidates]
        asn_records = asn_lookup.lookup_asn_bulk(ips)
        for candidate, asn_rec in zip(candidates, asn_records):
            candidate["asn_info"] = asn_rec
            # Filter: if ASN says CDN, lower value
            candidate["is_cdn"] = asn_rec.get("classification") == "CDN"

    # Sort: non-CDN first, then CDN
    candidates.sort(key=lambda c: (c.get("is_cdn", False), c["ip"]))
    return candidates


def check_ssl_cert(ip, hostname, timeout=5):
    """Connect to IP on port 443 and extract SSL certificate info.

    Returns dict with: common_name, issuer, alt_names, is_cdn_issued
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return None

                cert = x509.load_der_x509_certificate(der_cert)

                # Common Name
                cn = ""
                try:
                    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if cn_attr:
                        cn = cn_attr[0].value
                except Exception:
                    pass

                # Issuer Organization
                issuer = ""
                try:
                    org_attr = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                    if org_attr:
                        issuer = org_attr[0].value
                except Exception:
                    pass

                # Subject Alternative Names
                alt_names = []
                try:
                    san_ext = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    alt_names = san_ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass

                is_cdn_issued = any(
                    kw in issuer.lower() for kw in CDN_CERT_ISSUERS
                )

                return {
                    "common_name": cn,
                    "issuer": issuer,
                    "alt_names": alt_names,
                    "is_cdn_issued": is_cdn_issued,
                }

    except Exception:
        return None


def fetch_historical_ips(domain, timeout=10):
    """Query ViewDNS.info + SecurityTrails for historical IP records.

    Returns list of dicts: ip, location, owner, last_seen
    """
    import requests

    results = []

    # ViewDNS.info (no API key needed)
    url = f"https://viewdns.info/iphistory/?domain={domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            rows = re.findall(r"<tr>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*</tr>",
                              resp.text, re.DOTALL)
            for ip, location, owner, last_seen in rows:
                ip = ip.strip()
                if asn_lookup.is_ip(ip):
                    results.append({
                        "ip": ip,
                        "location": location.strip(),
                        "owner": owner.strip(),
                        "last_seen": last_seen.strip(),
                        "source": "viewdns",
                    })
    except Exception:
        pass

    # SecurityTrails historical DNS (API key required)
    st_results = _securitytrails_history(domain, timeout=timeout)
    seen = {r["ip"] for r in results}
    for r in st_results:
        if r["ip"] not in seen:
            seen.add(r["ip"])
            results.append(r)

    return results


def _securitytrails_history(domain, timeout=10):
    """Fetch historical A records from SecurityTrails API."""
    import requests

    key = api_keys.get("securitytrails_key")
    if not key:
        return []

    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": key, "Accept": "application/json"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for record in data.get("records", []):
            for val in record.get("values", []):
                ip = val.get("ip", "")
                if asn_lookup.is_ip(ip):
                    results.append({
                        "ip": ip,
                        "location": "",
                        "owner": record.get("organizations", [""])[0] if record.get("organizations") else "",
                        "last_seen": record.get("last_seen", ""),
                        "source": "securitytrails",
                    })
        return results
    except Exception:
        return []


def fetch_favicon_hash_from_url(url, timeout=10):
    """Fetch a favicon from a specific URL and compute its MMH3 hash.

    Returns dict: hash (int), hash_str, favicon_url, size, or None.
    """
    import requests

    if mmh3 is None:
        return None

    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=timeout, verify=False, allow_redirects=True,
        )
        if resp.status_code == 200 and 0 < len(resp.content) < 1_000_000:
            favicon_b64 = base64.encodebytes(resp.content)
            fav_hash = mmh3.hash(favicon_b64)
            return {
                "hash": fav_hash,
                "hash_str": str(fav_hash),
                "favicon_url": url,
                "size": len(resp.content),
            }
    except Exception:
        pass
    return None


def fetch_favicon_hash(domain, timeout=10):
    """Fetch the target's favicon and compute its Shodan-style MMH3 hash.

    Returns dict: hash (int), hash_str, favicon_url, or None if not found.
    Requires: pip install mmh3
    """
    import requests

    if mmh3 is None:
        return None

    favicon_urls = [
        f"https://{domain}/favicon.ico",
        f"http://{domain}/favicon.ico",
    ]

    # Also try to find favicon link in HTML
    try:
        resp = requests.get(
            f"https://{domain}/",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=timeout, verify=False, allow_redirects=True,
        )
        if resp.status_code == 200:
            link_match = re.search(
                r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)',
                resp.text, re.IGNORECASE,
            )
            if link_match:
                href = link_match.group(1)
                if href.startswith("//"):
                    href = f"https:{href}"
                elif href.startswith("/"):
                    href = f"https://{domain}{href}"
                elif not href.startswith("http"):
                    href = f"https://{domain}/{href}"
                favicon_urls.insert(0, href)
    except Exception:
        pass

    for fav_url in favicon_urls:
        try:
            resp = requests.get(
                fav_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                timeout=timeout, verify=False, allow_redirects=True,
            )
            if resp.status_code == 200 and len(resp.content) > 0 and len(resp.content) < 1_000_000:
                # Shodan-style: base64 encode the raw bytes, then mmh3 hash
                favicon_b64 = base64.encodebytes(resp.content)
                fav_hash = mmh3.hash(favicon_b64)
                return {
                    "hash": fav_hash,
                    "hash_str": str(fav_hash),
                    "favicon_url": fav_url,
                    "size": len(resp.content),
                }
        except Exception:
            continue

    return None


def search_by_favicon_hash(fav_hash, domain=None, timeout=15):
    """Search Shodan/FOFA/ZoomEye for servers with the same favicon hash.

    Returns list of dicts: ip, port, source, info
    """
    import requests

    results = []
    seen_ips = set()

    # Shodan
    shodan_key = api_keys.get("shodan_api_key")
    if shodan_key:
        try:
            resp = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": shodan_key, "query": f"http.favicon.hash:{fav_hash}"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get("matches", []):
                    ip = match.get("ip_str", "")
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        results.append({
                            "ip": ip,
                            "port": match.get("port", 0),
                            "source": "shodan",
                            "org": match.get("org", ""),
                            "hostnames": match.get("hostnames", []),
                        })
        except Exception:
            pass

    # FOFA
    fofa_email = api_keys.get("fofa_email")
    fofa_key = api_keys.get("fofa_key")
    if fofa_email and fofa_key:
        try:
            query = f'icon_hash="{fav_hash}"'
            query_b64 = base64.b64encode(query.encode()).decode()
            resp = requests.get(
                "https://fofa.info/api/v1/search/all",
                params={"email": fofa_email, "key": fofa_key, "qbase64": query_b64, "size": 100},
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                for row in data.get("results", []):
                    # FOFA returns [host, ip, port]
                    if len(row) >= 2:
                        ip = row[1] if len(row) > 1 else row[0]
                        if asn_lookup.is_ip(ip) and ip not in seen_ips:
                            seen_ips.add(ip)
                            results.append({
                                "ip": ip,
                                "port": int(row[2]) if len(row) > 2 else 0,
                                "source": "fofa",
                                "org": "",
                                "hostnames": [row[0]] if row[0] != ip else [],
                            })
        except Exception:
            pass

    # ZoomEye
    zoomeye_key = api_keys.get("zoomeye_key")
    if zoomeye_key:
        try:
            resp = requests.get(
                "https://api.zoomeye.org/web/search",
                params={"query": f'iconhash:"{fav_hash}"'},
                headers={"API-KEY": zoomeye_key},
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get("matches", []):
                    ip_list = match.get("ip", [])
                    if isinstance(ip_list, str):
                        ip_list = [ip_list]
                    for ip in ip_list:
                        if asn_lookup.is_ip(ip) and ip not in seen_ips:
                            seen_ips.add(ip)
                            results.append({
                                "ip": ip,
                                "port": match.get("portinfo", {}).get("port", 0),
                                "source": "zoomeye",
                                "org": "",
                                "hostnames": [],
                            })
        except Exception:
            pass

    return results


def search_github_leaks(domain, timeout=15):
    """Search GitHub code for leaked origin IPs or config files referencing the domain.

    Looks for hardcoded IPs, AWS configs, .env files, nginx/Apache configs, etc.
    No API key needed for basic search (rate-limited), but authenticated search is better.
    Returns list of dicts: ip, source, context, url
    """
    import requests

    results = []
    seen_ips = set()

    # Search queries that commonly leak origin IPs
    queries = [
        f'"{domain}" "server_addr" OR "origin" OR "real_ip" OR "backend"',
        f'"{domain}" filename:.env OR filename:.ini OR filename:config',
        f'"{domain}" "upstream" filename:nginx.conf OR filename:.conf',
        f'"{domain}" "ProxyPass" OR "ProxyPassReverse" filename:apache OR filename:.conf',
        f'"{domain}" "A record" OR "ip_address" OR "server_ip"',
    ]

    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "User-Agent": "WhatTheWAF-Origin-Scanner",
    }

    for query in queries:
        try:
            resp = requests.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 10},
                headers=headers,
                timeout=timeout,
            )
            if resp.status_code != 200:
                continue

            data = resp.json()
            for item in data.get("items", []):
                text_matches = item.get("text_matches", [])
                for tm in text_matches:
                    fragment = tm.get("fragment", "")
                    # Extract IPs from the matched fragment
                    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', fragment)
                    for ip in ips:
                        if asn_lookup.is_ip(ip) and ip not in seen_ips:
                            # Skip private/reserved IPs
                            if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                              "172.20.", "172.21.", "172.22.", "172.23.",
                                              "172.24.", "172.25.", "172.26.", "172.27.",
                                              "172.28.", "172.29.", "172.30.", "172.31.",
                                              "192.168.", "127.", "0.", "255.")):
                                continue
                            seen_ips.add(ip)
                            results.append({
                                "ip": ip,
                                "source": "github",
                                "context": fragment[:200],
                                "url": item.get("html_url", ""),
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "path": item.get("path", ""),
                            })
        except Exception:
            continue

    return results


def search_censys(domain, timeout=15):
    """Search Censys for certificates matching the domain to find origin IPs.

    Returns list of dicts: ip, source, info
    """
    return search_censys_query(
        f"services.tls.certificates.leaf.names: {domain}", timeout=timeout,
    )


def search_censys_query(query, timeout=15):
    """Run a raw Censys host search query.

    Returns list of dicts: ip, source, services, autonomous_system
    """
    import requests

    censys_id = api_keys.get("censys_api_id")
    censys_secret = api_keys.get("censys_api_secret")
    if not censys_id or not censys_secret:
        return []

    results = []
    seen_ips = set()

    try:
        resp = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": query, "per_page": 50},
            auth=(censys_id, censys_secret),
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []

        data = resp.json()
        for hit in data.get("result", {}).get("hits", []):
            ip = hit.get("ip", "")
            if asn_lookup.is_ip(ip) and ip not in seen_ips:
                seen_ips.add(ip)
                results.append({
                    "ip": ip,
                    "source": "censys",
                    "services": [s.get("service_name", "") for s in hit.get("services", [])],
                    "autonomous_system": hit.get("autonomous_system", {}).get("description", ""),
                })
    except Exception:
        pass

    return results


def search_shodan_domain(domain, timeout=15):
    """Search Shodan for hosts associated with the domain.

    Returns list of dicts: ip, port, source, info
    """
    import requests

    shodan_key = api_keys.get("shodan_api_key")
    if not shodan_key:
        return []

    results = []
    seen_ips = set()

    try:
        resp = requests.get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": shodan_key},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("data", []):
                if record.get("type") == "A":
                    ip = record.get("value", "")
                    if asn_lookup.is_ip(ip) and ip not in seen_ips:
                        seen_ips.add(ip)
                        results.append({
                            "ip": ip,
                            "source": "shodan",
                            "subdomain": record.get("subdomain", ""),
                            "last_seen": record.get("last_seen", ""),
                        })
    except Exception:
        pass

    return results


def search_shodan_query(query, timeout=15):
    """Run a raw Shodan host search query.

    Returns list of dicts: ip, port, source, org, hostnames
    """
    import requests

    shodan_key = api_keys.get("shodan_api_key")
    if not shodan_key:
        return []

    results = []
    seen_ips = set()

    try:
        resp = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": shodan_key, "query": query},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            for match in data.get("matches", []):
                ip = match.get("ip_str", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    results.append({
                        "ip": ip,
                        "port": match.get("port", 0),
                        "source": "shodan",
                        "org": match.get("org", ""),
                        "hostnames": match.get("hostnames", []),
                        "product": match.get("product", ""),
                        "os": match.get("os", ""),
                    })
    except Exception:
        pass

    return results


def search_virustotal(domain, timeout=15):
    """Query VirusTotal for domain resolutions (historical A records).

    Returns list of dicts: ip, source, last_seen
    """
    import requests

    vt_key = api_keys.get("virustotal_api_key")
    if not vt_key:
        return []

    results = []
    seen_ips = set()

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
            headers={"x-apikey": vt_key},
            params={"limit": 40},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []

        data = resp.json()
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            ip = attrs.get("ip_address", "")
            if asn_lookup.is_ip(ip) and ip not in seen_ips:
                seen_ips.add(ip)
                results.append({
                    "ip": ip,
                    "source": "virustotal",
                    "last_seen": attrs.get("date", ""),
                })
    except Exception:
        pass

    return results


def search_dnstrails(domain, timeout=15):
    """Query DNSTrails API for historical DNS records and subdomains.

    DNSTrails (now part of SecurityTrails) provides historical A records
    and subdomain enumeration.
    Returns list of dicts: ip, source, subdomain/last_seen
    """
    import requests

    key = api_keys.get("dnstrails_api_key")
    if not key:
        return []

    results = []
    seen_ips = set()

    # Historical A records
    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": key, "Accept": "application/json"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("records", []):
                for val in record.get("values", []):
                    ip = val.get("ip", "")
                    if asn_lookup.is_ip(ip) and ip not in seen_ips:
                        seen_ips.add(ip)
                        results.append({
                            "ip": ip,
                            "source": "dnstrails",
                            "type": "history",
                            "last_seen": record.get("last_seen", ""),
                        })
    except Exception:
        pass

    # Subdomains
    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": key, "Accept": "application/json"},
            params={"children_only": "false"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            subs = data.get("subdomains", [])
            for sub in subs[:30]:
                fqdn = f"{sub}.{domain}"
                try:
                    ips = dns_resolver.resolve_ip(fqdn)
                    for ip in ips:
                        if asn_lookup.is_ip(ip) and ip not in seen_ips:
                            seen_ips.add(ip)
                            results.append({
                                "ip": ip,
                                "source": "dnstrails",
                                "type": "subdomain",
                                "subdomain": fqdn,
                            })
                except Exception:
                    continue
    except Exception:
        pass

    return results


def search_whoxy(domain, timeout=15):
    """Use Whoxy to find sibling domains (same registrant) and resolve them for origin IPs.

    Flow: WHOIS lookup -> registrant email -> reverse WHOIS -> resolve sibling domains.
    Returns dict with: whois_info, sibling_domains, ips
    """
    import requests

    key = api_keys.get("whoxy_api_key")
    if not key:
        return {}

    result = {
        "whois": {},
        "registrant_email": "",
        "registrant_name": "",
        "registrant_company": "",
        "sibling_domains": [],
        "ips": [],
    }

    # Step 1: WHOIS lookup on the target domain
    try:
        resp = requests.get(
            "https://api.whoxy.com/",
            params={"key": key, "whois": domain},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return result
        data = resp.json()
        if data.get("status") != 1:
            return result

        result["whois"] = {
            "registrar": data.get("registrar", {}).get("registrar_name", ""),
            "create_date": data.get("create_date", ""),
            "update_date": data.get("update_date", ""),
            "expiry_date": data.get("expiry_date", ""),
            "nameservers": data.get("name_servers", []),
        }

        reg = data.get("registrant_contact", {})
        result["registrant_email"] = reg.get("email_address", "")
        result["registrant_name"] = reg.get("full_name", "")
        result["registrant_company"] = reg.get("company_name", "")
    except Exception:
        return result

    # Step 2: Reverse WHOIS by registrant email to find sibling domains
    email = result["registrant_email"]
    company = result["registrant_company"]
    if not email and not company:
        return result

    try:
        params = {"key": key, "reverse": "whois", "mode": "micro"}
        if email and "redacted" not in email.lower() and "privacy" not in email.lower():
            params["email"] = email
        elif company and "redacted" not in company.lower() and "privacy" not in company.lower():
            params["company"] = company
        else:
            return result

        resp = requests.get("https://api.whoxy.com/", params=params, timeout=timeout)
        if resp.status_code != 200:
            return result
        data = resp.json()
        if data.get("status") != 1:
            return result

        siblings = []
        for entry in data.get("search_result", []):
            sibling = entry.get("domain_name", "")
            if sibling and sibling != domain:
                siblings.append(sibling)
        result["sibling_domains"] = siblings[:50]
    except Exception:
        return result

    # Step 3: Resolve sibling domains to find shared origin IPs
    seen_ips = set()
    ips = []
    for sibling in result["sibling_domains"][:20]:
        try:
            resolved = dns_resolver.resolve_ip(sibling)
            for ip in resolved:
                if asn_lookup.is_ip(ip) and ip not in seen_ips:
                    seen_ips.add(ip)
                    ips.append({
                        "ip": ip,
                        "source": "whoxy",
                        "sibling_domain": sibling,
                    })
        except Exception:
            continue
    result["ips"] = ips

    return result
