"""Core scanner — orchestrates all detection modules into a unified scan."""

import hashlib
import concurrent.futures
import httpx
from .modules import (
    dns_resolver, asn_lookup, waf_signatures, tech_fingerprint,
    origin_finder, geoip, security_headers, dns_deep, http_utils,
    whois_lookup, waf_bypass,
)

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def fetch_response(url, timeout=10, user_agent=None, proxy=None):
    """Fetch a URL using httpx and return parsed response data."""
    try:
        client_kwargs = {
            "timeout": timeout,
            "follow_redirects": True,
            "verify": False,
            "headers": {"User-Agent": user_agent or DEFAULT_UA},
        }
        if proxy:
            client_kwargs["proxy"] = proxy

        with httpx.Client(**client_kwargs) as client:
            resp = client.get(url)

        headers = dict(resp.headers)
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        cookies = set_cookies if set_cookies else [f"{k}={v}" for k, v in resp.cookies.items()]

        return {
            "status": resp.status_code,
            "headers": headers,
            "cookies": cookies,
            "body": _smart_body_cap(resp.text),
            "url": str(resp.url),
        }
    except Exception as e:
        return {"error": str(e)}


def _smart_body_cap(body, max_size=200000):
    """Cap body size but keep head and closing tags intact for fingerprinting."""
    if len(body) <= max_size:
        return body
    return body[:150000] + "\n<!-- truncated -->\n" + body[-50000:]


def origins_scan(inputs):
    """Quick origins scan — DNS + ASN classification (like the shell function)."""
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
            "domain": domain,
            "ip": ip,
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
              on_status=None):
    """Full recon scan of a target. Returns a comprehensive report dict.

    on_status: optional callback(phase_name, detail_str) for live progress.
    """
    status = on_status or _noop_status
    domain = dns_resolver._clean_domain(target)
    url = target if target.startswith("http") else f"https://{domain}"

    report = {
        "target": target, "domain": domain,
        "dns": {}, "dns_deep": {}, "whois": {},
        "ips": [], "cnames": [],
        "redirect_chain": [], "http": {},
        "waf": [], "technologies": [],
        "security_headers": {},
        "robots": {},
        "open_ports": [],
        "origin_candidates": [], "cert_info": None,
        "historical_ips": [],
        "response_hash": "",
        "cdn_detected": False, "waf_detected": False,
        "summary": "",
    }

    # 1. DNS resolution
    status("dns", f"Resolving {domain}")
    dns_info = dns_resolver.resolve_domain(domain)
    report["dns"] = dns_info
    report["cnames"] = dns_info.get("cnames", [])
    a_records = dns_info.get("a_records", [])
    status("dns", f"{len(a_records)} IP(s) found")

    # 2. ASN lookup + Geolocation
    if a_records:
        status("asn", f"ASN + Geolocation for {len(a_records)} IP(s)")
        asn_records = asn_lookup.lookup_asn_bulk(a_records)
        geo_records = geoip.geolocate_bulk(a_records)
        for asn_rec, geo_rec in zip(asn_records, geo_records):
            asn_rec["geo"] = geo_rec
        report["ips"] = asn_records
        cdn_ips = {r["ip"] for r in asn_records if r["classification"] == "CDN"}
        report["cdn_detected"] = len(cdn_ips) > 0
    else:
        asn_records = []
        cdn_ips = set()

    # 3. Deep DNS + WHOIS + redirects + robots (parallel)
    status("recon", "DNS intel, WHOIS, redirects, robots.txt")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        dns_deep_fut = pool.submit(dns_deep.deep_dns_analysis, domain)
        whois_fut = pool.submit(whois_lookup.lookup_whois, domain, timeout)
        redirect_fut = pool.submit(http_utils.trace_redirects, url, timeout, 10, None, proxy)
        robots_fut = pool.submit(http_utils.parse_robots_txt, url, timeout, proxy)

        report["dns_deep"] = dns_deep_fut.result()
        report["whois"] = whois_fut.result()
        report["redirect_chain"] = redirect_fut.result()
        report["robots"] = robots_fut.result()

    # 4. HTTP fetch + WAF + tech + security headers
    status("http", f"Fetching {url}")
    resp = fetch_response(url, timeout=timeout, user_agent=user_agent, proxy=proxy)
    if "error" not in resp:
        report["http"] = {
            "status": resp["status"],
            "server": resp["headers"].get("server", resp["headers"].get("Server", "")),
            "content_type": resp["headers"].get("content-type", resp["headers"].get("Content-Type", "")),
            "url": resp.get("url", url),
        }
        report["response_hash"] = hashlib.sha256(
            resp["body"].encode("utf-8", errors="replace")
        ).hexdigest()

        status("waf", "WAF/CDN signature matching")
        report["waf"] = waf_signatures.detect_waf(
            resp["headers"], resp["cookies"], resp["body"], resp["status"]
        )
        report["waf_detected"] = any(
            d["category"] in ("WAF", "CDN/WAF") for d in report["waf"]
        )

        status("tech", "Technology fingerprinting")
        report["technologies"] = tech_fingerprint.fingerprint_tech(
            resp["headers"], resp["cookies"], resp["body"]
        )
        report["security_headers"] = security_headers.audit_security_headers(resp["headers"])
    else:
        report["http"] = {"error": resp.get("error", "unknown")}

    # 5. Port probe
    if a_records:
        status("ports", f"Port scanning {a_records[0]}")
        report["open_ports"] = http_utils.probe_ports(a_records[0])

    # 6. SSL certificate
    if check_cert and a_records:
        status("cert", f"SSL certificate for {domain}")
        report["cert_info"] = origin_finder.check_ssl_cert(a_records[0], domain, timeout=timeout)

    # 7. Subdomain origin leakage
    if scan_subs and report["cdn_detected"]:
        status("origins", "Subdomain origin leakage scan")
        candidates = origin_finder.find_origins(domain, cdn_ips=cdn_ips)
        report["origin_candidates"] = [c for c in candidates if not c.get("is_cdn")]

    # 8. Historical DNS
    if check_history:
        status("history", "Historical DNS lookup")
        report["historical_ips"] = origin_finder.fetch_historical_ips(domain)

    # 9. WAF bypass testing
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
            domain, bypass_ips, timeout=timeout,
            user_agent=user_agent, proxy=proxy,
        )
    else:
        report["waf_bypass"] = {}

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
    if not parts:
        parts.append("No CDN/WAF detected - likely direct to origin")
    report["summary"] = " | ".join(parts)

    if delay:
        import time
        time.sleep(delay)

    return report


def full_scan_batch(targets, timeout=10, max_workers=5, **kwargs):
    """Scan multiple targets concurrently."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(full_scan, t, timeout=timeout, **kwargs): t
            for t in targets
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                report = future.result()
                results.append(report)
            except Exception as e:
                results.append({"target": target, "error": str(e)})
    return results
