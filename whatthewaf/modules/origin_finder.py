"""Origin IP discovery — find the real server behind CDN/WAF.

Techniques inspired by CloakQuest3r:
- Subdomain IP leakage (subdomains not behind CDN)
- SSL certificate inspection
- Historical DNS via ViewDNS.info
"""

import re
import ssl
import socket
import concurrent.futures
from cryptography import x509
from cryptography.x509.oid import NameOID

from . import dns_resolver, asn_lookup

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
    """Query ViewDNS.info for historical IP records (no API key needed).

    Returns list of dicts: ip, location, owner, last_seen
    """
    import requests

    url = f"https://viewdns.info/iphistory/?domain={domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return []

        # Parse HTML table — ViewDNS returns a simple table
        results = []
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
                })
        return results

    except Exception:
        return []
