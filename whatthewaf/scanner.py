"""Core scanner — orchestrates WAF detection, bypass, and evasion analysis."""

import hashlib
import concurrent.futures
import httpx
from .modules import (
    dns_resolver, asn_lookup, waf_signatures, origin_finder,
    waf_bypass, error_pages, tls_fingerprint, waf_evasion, proxy_manager,
)

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


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
              proxy_chain=None, use_proton=False):
    """Full WAF-focused scan."""
    status = on_status or _noop_status
    domain = dns_resolver._clean_domain(target)
    url = target if target.startswith("http") else f"https://{domain}"

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

    # 1. DNS
    status("dns", f"Resolving {domain}")
    dns_info = dns_resolver.resolve_domain(domain)
    report["dns"] = dns_info
    report["cnames"] = dns_info.get("cnames", [])
    a_records = dns_info.get("a_records", [])

    # 2. ASN
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
    if check_tls:
        status("tls", f"TLS fingerprint analysis for {domain}")
        report["tls_fingerprint"] = tls_fingerprint.analyze_tls_fingerprint(domain, timeout=timeout)

    # 6. WAF evasion analysis
    if check_evasion:
        status("evasion", "WAF evasion analysis (UA, encoding, methods)")
        report["waf_evasion"] = waf_evasion.analyze_waf_detection(
            domain, timeout=timeout, user_agent=user_agent, proxy=proxy
        )

    # 7. Proxy effectiveness
    proxies = proxy_manager.get_proxy_chain(proxy_chain, use_proton)
    if proxies:
        status("proxy", f"Testing {len(proxies)} proxy(ies) against WAF")
        report["proxy_effectiveness"] = proxy_manager.test_proxy_effectiveness(
            domain, proxies, timeout=timeout
        )

    # 8. SSL certificate (for CDN detection)
    if check_cert and a_records:
        status("cert", f"SSL certificate for {domain}")
        report["cert_info"] = origin_finder.check_ssl_cert(a_records[0], domain, timeout=timeout)

    # 9. Origin discovery
    if scan_subs and report["cdn_detected"]:
        status("origins", "Subdomain origin leakage scan")
        candidates = origin_finder.find_origins(domain, cdn_ips=cdn_ips)
        report["origin_candidates"] = [c for c in candidates if not c.get("is_cdn")]

    # 10. Historical DNS
    if check_history:
        status("history", "Historical DNS lookup")
        report["historical_ips"] = origin_finder.fetch_historical_ips(domain)

    # 11. WAF bypass testing
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
