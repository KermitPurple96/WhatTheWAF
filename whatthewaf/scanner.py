"""Core scanner — orchestrates WAF detection, bypass, and evasion analysis."""

import hashlib
import concurrent.futures
import httpx
from .modules import (
    dns_resolver, asn_lookup, waf_signatures, origin_finder,
    waf_bypass, error_pages, tls_fingerprint, waf_evasion, proxy_manager,
)

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"


def fetch_response(url, timeout=10, user_agent=None, proxy=None):
    try:
        client_kwargs = {
            "timeout": timeout, "follow_redirects": True, "verify": False,
            "headers": {"User-Agent": user_agent or DEFAULT_UA},
        }
        if proxy:
            client_kwargs["proxy"] = proxy
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(url)
        headers = dict(resp.headers)
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        cookies = set_cookies if set_cookies else [f"{k}={v}" for k, v in resp.cookies.items()]
        return {"status": resp.status_code, "headers": headers, "cookies": cookies,
                "body": _smart_body_cap(resp.text), "url": str(resp.url)}
    except Exception as e:
        return {"error": str(e)}


def _smart_body_cap(body, max_size=200000):
    if len(body) <= max_size:
        return body
    return body[:150000] + "\n<!-- truncated -->\n" + body[-50000:]


def origins_scan(inputs):
    """Quick origins scan — DNS + ASN classification."""
    all_pairs = []
    for inp in inputs:
        inp = inp.strip()
        if not inp:
            continue
        if asn_lookup.is_ip(inp):
            all_pairs.append(("(direct IP)", inp))
        else:
            domain = dns_resolver._clean_domain(inp)
            ips = dns_resolver.resolve_ip(domain)
            for ip in ips:
                all_pairs.append((domain, ip))
    if not all_pairs:
        return []
    ip_list = [pair[1] for pair in all_pairs]
    asn_records = asn_lookup.lookup_asn_bulk(ip_list)
    rows = []
    for (domain, ip), asn_rec in zip(all_pairs, asn_records):
        rows.append({
            "domain": domain, "ip": ip,
            "provider": asn_rec.get("provider", "unknown"),
            "classification": asn_rec.get("classification", "UNKNOWN"),
            "country": asn_rec.get("country", "??"),
            "asn": asn_rec.get("asn"),
            "bgp_prefix": asn_rec.get("bgp_prefix", ""),
            "registry": asn_rec.get("registry", ""),
            "allocated": asn_rec.get("allocated", ""),
        })
    return rows


def _noop_status(*a, **kw):
    pass


def full_scan(target, timeout=10, scan_subs=True, check_cert=True,
              check_history=False, user_agent=None, proxy=None, delay=0,
              on_status=None, check_tls=True, check_evasion=False,
              proxy_chain=None, use_proton=False, only_modules=None):
    """Full WAF-focused scan.

    only_modules: if set, only run these modules. Valid values:
        ips, waf, errors, tls, evasion, bypass, cert, subs, history, proxy
    DNS + ASN + HTTP are always run as they're needed by other modules.
    """
    status = on_status or _noop_status
    domain = dns_resolver._clean_domain(target)
    url = target if target.startswith("http") else f"https://{domain}"

    def _should_run(module_name):
        if only_modules is None:
            return True
        return module_name in only_modules

    report = {
        "target": target, "domain": domain,
        "dns": {}, "ips": [], "cnames": [],
        "http": {}, "waf": [],
        "error_pages": {},
        "tls_fingerprint": {},
        "waf_evasion": {},
        "proxy_effectiveness": {},
        "origin_candidates": [], "cert_info": None,
        "historical_ips": [],
        "waf_bypass": {},
        "response_hash": "",
        "cdn_detected": False, "waf_detected": False,
        "summary": "",
    }

    # 1. DNS (always runs)
    status("dns", f"Resolving {domain}")
    dns_info = dns_resolver.resolve_domain(domain)
    report["dns"] = dns_info
    report["cnames"] = dns_info.get("cnames", [])
    a_records = dns_info.get("a_records", [])

    # 2. ASN (always runs)
    if a_records:
        status("asn", f"ASN classification for {len(a_records)} IP(s)")
        asn_records = asn_lookup.lookup_asn_bulk(a_records)
        report["ips"] = asn_records
        cdn_ips = {r["ip"] for r in asn_records if r["classification"] == "CDN"}
        report["cdn_detected"] = len(cdn_ips) > 0
    else:
        asn_records = []
        cdn_ips = set()

    # 3. HTTP fetch + WAF detection
    if _should_run("waf") or _should_run("errors") or _should_run("bypass") or _should_run("evasion") or only_modules is None:
        status("http", f"Fetching {url}")
        resp = fetch_response(url, timeout=timeout, user_agent=user_agent, proxy=proxy)
        if "error" not in resp:
            report["http"] = {
                "status": resp["status"],
                "server": resp["headers"].get("server", resp["headers"].get("Server", "")),
                "content_type": resp["headers"].get("content-type", ""),
                "url": resp.get("url", url),
            }
            report["response_hash"] = hashlib.sha256(
                resp["body"].encode("utf-8", errors="replace")
            ).hexdigest()

            if _should_run("waf"):
                status("waf", "WAF/CDN signature matching")
                report["waf"] = waf_signatures.detect_waf(
                    resp["headers"], resp["cookies"], resp["body"], resp["status"]
                )
                report["waf_detected"] = any(
                    d["category"] in ("WAF", "CDN/WAF") for d in report["waf"]
                )
        else:
            report["http"] = {"error": resp.get("error", "unknown")}

    # 4. Error page probing
    if _should_run("errors"):
        status("errors", "Probing error pages for WAF signatures")
        ep = error_pages.probe_error_pages(url, timeout=timeout, user_agent=user_agent, proxy=proxy)
        report["error_pages"] = ep

        # Merge WAF detections from error pages
        homepage_waf_names = {d["name"] for d in report.get("waf", [])}
        for probe in ep.get("probes", []):
            for waf_name in probe.get("waf_hits", []):
                if waf_name not in homepage_waf_names:
                    report["waf"].append({
                        "name": waf_name, "category": "WAF", "confidence": 0.5,
                        "evidence": [f"error page {probe['path']} [{probe.get('status', '?')}]"],
                    })
                    homepage_waf_names.add(waf_name)
        report["waf_detected"] = any(d["category"] in ("WAF", "CDN/WAF") for d in report["waf"])

    # 5. TLS fingerprint analysis
    if _should_run("tls") and check_tls:
        status("tls", f"TLS fingerprint analysis for {domain}")
        report["tls_fingerprint"] = tls_fingerprint.analyze_tls_fingerprint(domain, timeout=timeout)

    # 6. WAF evasion analysis
    if _should_run("evasion") and (check_evasion or only_modules):
        status("evasion", "WAF evasion analysis (UA, encoding, methods)")
        report["waf_evasion"] = waf_evasion.analyze_waf_detection(
            domain, timeout=timeout, user_agent=user_agent, proxy=proxy
        )

    # 7. Proxy effectiveness
    if _should_run("proxy"):
        proxies = proxy_manager.get_proxy_chain(proxy_chain, use_proton)
        if proxies:
            status("proxy", f"Testing {len(proxies)} proxy(ies) against WAF")
            report["proxy_effectiveness"] = proxy_manager.test_proxy_effectiveness(
                domain, proxies, timeout=timeout
            )

    # 8. SSL certificate (for CDN detection)
    if _should_run("cert") and check_cert and a_records:
        status("cert", f"SSL certificate for {domain}")
        report["cert_info"] = origin_finder.check_ssl_cert(a_records[0], domain, timeout=timeout)

    # 9. Origin discovery
    if _should_run("subs") and scan_subs and report["cdn_detected"]:
        status("origins", "Subdomain origin leakage scan")
        candidates = origin_finder.find_origins(domain, cdn_ips=cdn_ips)
        report["origin_candidates"] = [c for c in candidates if not c.get("is_cdn")]

    # 10. Historical DNS
    if _should_run("history") and (check_history or only_modules):
        status("history", "Historical DNS lookup")
        report["historical_ips"] = origin_finder.fetch_historical_ips(domain)

    # 11. WAF bypass testing
    if _should_run("bypass"):
        bypass_ips = []
        for rec in asn_records:
            if rec["ip"] not in bypass_ips:
                bypass_ips.append(rec["ip"])
        for c in report.get("origin_candidates", []):
            if c["ip"] not in bypass_ips:
                bypass_ips.append(c["ip"])
        if bypass_ips:
            status("bypass", f"WAF bypass testing ({len(bypass_ips)} IP(s))")
            report["waf_bypass"] = waf_bypass.test_bypass(
                domain, bypass_ips, timeout=timeout, user_agent=user_agent, proxy=proxy,
            )

    # Build summary
    parts = []
    if report["cdn_detected"]:
        cdn_names = list({r["provider"] for r in asn_records if r["classification"] == "CDN"})
        parts.append(f"CDN: {', '.join(cdn_names)}")
    if report["waf_detected"]:
        waf_names = [d["name"] for d in report["waf"] if d["category"] in ("WAF", "CDN/WAF")]
        parts.append(f"WAF: {', '.join(waf_names)}")
    if report["origin_candidates"]:
        parts.append(f"{len(report['origin_candidates'])} potential origin IP(s)")
    bypass_findings = report.get("waf_bypass", {}).get("findings", [])
    critical_bypasses = [f for f in bypass_findings if f.get("severity") in ("critical", "high")]
    if critical_bypasses:
        parts.append(f"{len(critical_bypasses)} WAF bypass(es) found!")
    tls = report.get("tls_fingerprint", {})
    if tls.get("recommendations"):
        parts.append(f"{len(tls['recommendations'])} TLS evasion hint(s)")
    evasion = report.get("waf_evasion", {})
    if evasion.get("findings"):
        parts.append(f"{len(evasion['findings'])} evasion finding(s)")
    if not parts:
        parts.append("No CDN/WAF detected — likely direct to origin")
    report["summary"] = " | ".join(parts)

    if delay:
        import time
        time.sleep(delay)

    return report


def direct_ip_scan(domain, ip, timeout=10, user_agent=None, on_status=None, path="/"):
    """Connect directly to an IP with Host header set to domain — WAF bypass PoC.

    This bypasses DNS resolution entirely, connecting to the IP and sending
    the domain as Host header. Useful to prove origin is accessible without WAF.
    """
    import ssl
    import socket

    status = on_status or _noop_status
    ua = user_agent or DEFAULT_UA
    domain = dns_resolver._clean_domain(domain)
    report = {
        "target": domain, "ip": ip, "path": path, "mode": "direct-ip",
        "dns_resolution": {}, "direct_http": {}, "direct_https": {},
        "comparison": {}, "waf_via_cdn": [], "waf_direct": [],
        "bypass_confirmed": False, "summary": "",
    }

    # 1. Normal DNS resolution (through CDN) for comparison
    status("dns", f"Resolving {domain} via DNS (CDN path)")
    dns_info = dns_resolver.resolve_domain(domain)
    a_records = dns_info.get("a_records", [])
    report["dns_resolution"] = {
        "domain": domain,
        "resolved_ips": a_records,
        "cnames": dns_info.get("cnames", []),
    }

    # ASN for DNS-resolved IPs
    cdn_provider = None
    if a_records:
        asn_records = asn_lookup.lookup_asn_bulk(a_records)
        cdn_ips = [r for r in asn_records if r["classification"] == "CDN"]
        if cdn_ips:
            cdn_provider = cdn_ips[0].get("provider", "CDN")
        report["dns_resolution"]["asn"] = asn_records

    # ASN for the direct IP
    status("asn", f"ASN lookup for {ip}")
    direct_asn = asn_lookup.lookup_asn_bulk([ip])
    report["direct_ip_asn"] = direct_asn[0] if direct_asn else {}

    # 2. Fetch via CDN (normal resolution)
    status("http", f"Fetching https://{domain} via CDN")
    cdn_resp = fetch_response(f"https://{domain}{path}", timeout=timeout, user_agent=ua)
    if "error" not in cdn_resp:
        report["cdn_response"] = {
            "status": cdn_resp["status"],
            "server": cdn_resp["headers"].get("server", cdn_resp["headers"].get("Server", "")),
            "headers": cdn_resp["headers"],
            "body_hash": hashlib.sha256(cdn_resp["body"].encode("utf-8", errors="replace")).hexdigest()[:16],
            "body_length": len(cdn_resp["body"]),
        }
        report["waf_via_cdn"] = waf_signatures.detect_waf(
            cdn_resp["headers"], cdn_resp["cookies"], cdn_resp["body"], cdn_resp["status"]
        )
    else:
        report["cdn_response"] = {"error": cdn_resp["error"]}

    # 3. Direct HTTPS connection to IP with Host header
    # Use httpx transport with custom DNS to resolve domain → IP directly
    # This is equivalent to curl --resolve domain:443:ip https://domain/
    status("bypass", f"Direct HTTPS connection to {ip} with Host: {domain}")
    try:
        import httpcore
        client_kwargs = {
            "timeout": timeout, "follow_redirects": True, "verify": False,
            "headers": {"User-Agent": ua},
        }
        # Override DNS: make domain resolve to our target IP
        original_create_connection = httpcore._backends.sync.SyncBackend.connect_tcp
        def _patched_connect(self, host, port, **kwargs):
            if str(host) == domain:
                host = ip
            return original_create_connection(self, host, port, **kwargs)
        httpcore._backends.sync.SyncBackend.connect_tcp = _patched_connect
        try:
            with httpx.Client(**client_kwargs) as client:
                resp = client.get(f"https://{domain}{path}")
        finally:
            httpcore._backends.sync.SyncBackend.connect_tcp = original_create_connection
        headers = dict(resp.headers)
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        cookies = set_cookies if set_cookies else [f"{k}={v}" for k, v in resp.cookies.items()]
        body = _smart_body_cap(resp.text)

        # Extract title from HTML
        import re
        title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        page_title = title_match.group(1).strip() if title_match else None

        # Pick interesting headers
        interesting = [
            "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
            "x-frame-options", "x-content-type-options", "x-xss-protection",
            "content-security-policy", "strict-transport-security",
            "access-control-allow-origin", "www-authenticate",
            "x-default-vhost", "x-cache", "x-cdn", "cf-ray",
            "x-request-id", "x-correlation-id", "remote-addr",
        ]
        notable_headers = {k: v for k, v in headers.items() if k.lower() in interesting}

        report["direct_https"] = {
            "status": resp.status_code,
            "server": headers.get("server", headers.get("Server", "")),
            "headers": headers,
            "notable_headers": notable_headers,
            "title": page_title,
            "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16],
            "body_length": len(body),
            "content_type": headers.get("content-type", ""),
            "body": body,
        }
        report["waf_direct"] = waf_signatures.detect_waf(headers, cookies, body, resp.status_code)
    except Exception as e:
        report["direct_https"] = {"error": str(e)}

    # 4. Direct HTTP connection (port 80)
    status("bypass", f"Direct HTTP connection to {ip}:80 with Host: {domain}")
    try:
        client_kwargs = {
            "timeout": timeout, "follow_redirects": True, "verify": False,
            "headers": {"User-Agent": ua},
        }
        # Same DNS override trick for HTTP
        original_create_connection2 = httpcore._backends.sync.SyncBackend.connect_tcp
        def _patched_connect2(self, host, port, **kwargs):
            if str(host) == domain:
                host = ip
            return original_create_connection2(self, host, port, **kwargs)
        httpcore._backends.sync.SyncBackend.connect_tcp = _patched_connect2
        try:
            with httpx.Client(**client_kwargs) as client:
                resp = client.get(f"http://{domain}{path}")
        finally:
            httpcore._backends.sync.SyncBackend.connect_tcp = original_create_connection2
        headers = dict(resp.headers)
        body = _smart_body_cap(resp.text)
        report["direct_http"] = {
            "status": resp.status_code,
            "server": headers.get("server", headers.get("Server", "")),
            "headers": headers,
            "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16],
            "body_length": len(body),
            "body_preview": body[:500],
        }
    except Exception as e:
        report["direct_http"] = {"error": str(e)}

    # 5. Compare and determine bypass
    cdn_status = report.get("cdn_response", {}).get("status")
    direct_status = report.get("direct_https", {}).get("status")
    direct_server = report.get("direct_https", {}).get("server", "")
    cdn_server = report.get("cdn_response", {}).get("server", "")
    direct_err = report.get("direct_https", {}).get("error")

    cdn_waf_names = {d["name"] for d in report.get("waf_via_cdn", [])}
    direct_waf_names = {d["name"] for d in report.get("waf_direct", [])}

    # Determine if DNS-resolved IPs go through a CDN/WAF
    dns_asn = report.get("dns_resolution", {}).get("asn", [])
    dns_has_cdn = any(r.get("classification") == "CDN" for r in dns_asn)
    # CDN/WAF providers: traffic goes through their network and they can inspect/block requests
    # If DNS resolves to these, direct IP access = WAF bypass
    cdn_waf_providers = {
        # Major CDN/WAF
        "cloudflare", "akamai", "fastly", "cloudfront", "edgecast",
        # WAF-specific
        "imperva", "incapsula", "sucuri", "radware", "f5", "barracuda",
        "fortinet", "citrix", "wallarm", "signal sciences", "reblaze",
        "prophaze", "templarbit", "perimeterx", "human security",
        "datadome", "shape security",
        # CDN with WAF capabilities
        "stackpath", "limelight", "verizon", "cdn77", "keycdn", "maxcdn",
        "bunny", "bunnycdn", "gcore", "g-core", "medianova",
        "cachefly", "belugacdn", "quantil", "chinacache", "cdnetworks",
        "azion", "section.io", "section",
        # Cloud with built-in WAF/CDN edge
        "azure front door", "azure cdn", "aws shield", "aws waf",
        "google cloud armor", "google cloud cdn",
        # DDoS protection / proxy
        "ddos-guard", "ddos guard", "qrator", "stormwall", "nsfocus",
        "link11", "myra", "neustar", "arbor", "netscout",
        # Hosting with CDN/proxy layer
        "netlify", "vercel", "shopify", "salesforce",
        "wpengine", "wp engine", "siteground", "kinsta", "pressable",
        "pantheon", "flywheel", "pagely",
    }
    # Cloud hosting providers: traffic goes directly to origin, NOT a proxy/WAF
    # If DNS resolves to these, direct IP access = just direct access, not a bypass
    # (these are excluded from WAF bypass detection)
    _hosting_providers = {
        "amazon", "aws", "google", "gcp", "google cloud platform",
        "azure", "microsoft", "digitalocean", "linode", "akamai linode",
        "vultr", "hetzner", "ovh", "scaleway", "oracle cloud",
        "ibm cloud", "softlayer", "rackspace", "godaddy",
        "hostinger", "bluehost", "dreamhost", "ionos", "1and1",
        "strato", "contabo", "kamatera", "upcloud", "cherry servers",
        "leaseweb", "online.net", "iliad", "aruba",
    }
    dns_has_waf = False
    dns_cdn_name = ""
    for r in dns_asn:
        if r.get("classification") == "CDN":
            provider_lower = r.get("provider", "").lower()
            dns_cdn_name = r.get("provider", "CDN")
            if any(w in provider_lower for w in cdn_waf_providers):
                dns_has_waf = True
                break

    # --- Determination logic based on response hashes ---

    cdn_hash = report.get("cdn_response", {}).get("body_hash")
    direct_hash = report.get("direct_https", {}).get("body_hash")
    same_hash = cdn_hash and direct_hash and cdn_hash == direct_hash

    # Detect default/parking pages (not real content from the target domain)
    default_vhost_signatures = [
        "default server vhost", "default web page", "welcome to nginx",
        "apache2 default page", "it works!", "test page for",
        "parking page", "domain is not pointed", "still propagating",
        "domain has been registered", "this domain is parked",
        "future home of", "coming soon", "under construction",
        "cpanel", "plesk", "directadmin default", "webmin",
        "congrats! you have created", "default page",
        "siteground", "hostinger", "bluehost", "godaddy parking",
    ]
    direct_body = report.get("direct_https", {}).get("body", "")
    direct_title = (report.get("direct_https", {}).get("title") or "").lower()
    is_default_vhost = False
    for sig in default_vhost_signatures:
        if sig in direct_body.lower() or sig in direct_title:
            is_default_vhost = True
            report["default_vhost"] = True
            break
    direct_headers = report.get("direct_https", {}).get("headers", {})
    if direct_headers.get("x-default-vhost"):
        is_default_vhost = True
        report["default_vhost"] = True

    # Store hash comparison in report
    report["hash_match"] = same_hash

    if direct_err:
        report["bypass_confirmed"] = False
        report["summary"] = f"Direct connection failed: {direct_err}"
    elif is_default_vhost:
        # Default/parking page — not the target domain
        report["bypass_confirmed"] = False
        report["summary"] = "DEFAULT VHOST — IP responds with a default/parking page, not the target domain"
    elif not direct_status or direct_status == 0:
        report["bypass_confirmed"] = False
        report["summary"] = "Could not determine bypass status"
    elif same_hash:
        # Hashes match — same content via CDN and direct IP
        # This is the strongest confirmation: the origin serves the same content
        if dns_has_waf:
            report["bypass_confirmed"] = True
            report["summary"] = (f"WAF BYPASS CONFIRMED — Same content hash via CDN and direct IP "
                                 f"(hash: {direct_hash}, bypasses {dns_cdn_name})")
        else:
            report["bypass_confirmed"] = True
            report["summary"] = (f"DIRECT ACCESS CONFIRMED — Same content hash via domain and direct IP "
                                 f"(hash: {direct_hash})")
    else:
        # Hashes don't match — content differs between CDN and direct IP
        # Could be: different vhost, WAF blocking, different app version, etc.
        if dns_has_waf and direct_status in (200, 301, 302):
            # Server responds with real content (not an error) but different from CDN
            # Likely the origin without CDN transformations (minification, caching, etc.)
            report["bypass_confirmed"] = True
            report["summary"] = (f"WAF BYPASS LIKELY — Origin responds (status: {direct_status}) "
                                 f"but content differs from CDN (CDN hash: {cdn_hash}, direct hash: {direct_hash})")
        elif not dns_has_waf and direct_status in (200, 301, 302):
            report["bypass_confirmed"] = True
            report["summary"] = (f"DIRECT ACCESS — Origin responds (status: {direct_status}) "
                                 f"but content differs from domain (CDN hash: {cdn_hash}, direct hash: {direct_hash})")
        else:
            report["bypass_confirmed"] = False
            report["summary"] = (f"INCONCLUSIVE — Direct IP responded with status {direct_status}, "
                                 f"content differs (CDN hash: {cdn_hash}, direct hash: {direct_hash})")

    return report


def full_scan_batch(targets, timeout=10, max_workers=5, **kwargs):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(full_scan, t, timeout=timeout, **kwargs): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"target": target, "error": str(e)})
    return results
