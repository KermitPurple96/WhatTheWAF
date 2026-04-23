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


def direct_ip_scan(domain, ip, timeout=10, user_agent=None, on_status=None):
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
        "target": domain, "ip": ip, "mode": "direct-ip",
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
    cdn_resp = fetch_response(f"https://{domain}", timeout=timeout, user_agent=ua)
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
    status("bypass", f"Direct HTTPS connection to {ip} with Host: {domain}")
    try:
        client_kwargs = {
            "timeout": timeout, "follow_redirects": True, "verify": False,
            "headers": {
                "User-Agent": ua,
                "Host": domain,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "close",
            },
        }
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(f"https://{ip}/", extensions={"sni": domain})
        headers = dict(resp.headers)
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        cookies = set_cookies if set_cookies else [f"{k}={v}" for k, v in resp.cookies.items()]
        body = _smart_body_cap(resp.text)

        report["direct_https"] = {
            "status": resp.status_code,
            "server": headers.get("server", headers.get("Server", "")),
            "headers": headers,
            "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16],
            "body_length": len(body),
            "body_preview": body[:500],
        }
        report["waf_direct"] = waf_signatures.detect_waf(headers, cookies, body, resp.status_code)
    except Exception as e:
        report["direct_https"] = {"error": str(e)}

    # 4. Direct HTTP connection (port 80)
    status("bypass", f"Direct HTTP connection to {ip}:80 with Host: {domain}")
    try:
        client_kwargs = {
            "timeout": timeout, "follow_redirects": True, "verify": False,
            "headers": {
                "User-Agent": ua,
                "Host": domain,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Connection": "close",
            },
        }
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(f"http://{ip}/")
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

    if direct_err:
        report["bypass_confirmed"] = False
        report["summary"] = f"Direct connection failed: {direct_err}"
    elif direct_status and direct_status != 0:
        # Check if WAF signatures are absent in direct response
        waf_gone = cdn_waf_names - direct_waf_names
        same_content = (report.get("cdn_response", {}).get("body_hash") ==
                       report.get("direct_https", {}).get("body_hash"))

        if cdn_provider and direct_server and cdn_provider.lower() not in direct_server.lower():
            report["bypass_confirmed"] = True
            report["summary"] = f"BYPASS CONFIRMED — Direct IP responds without CDN/WAF (server: {direct_server})"
        elif waf_gone:
            report["bypass_confirmed"] = True
            report["summary"] = f"BYPASS CONFIRMED — WAF signatures missing in direct response (missing: {', '.join(waf_gone)})"
        elif direct_status in (200, 301, 302, 403):
            report["bypass_confirmed"] = True
            report["summary"] = f"Origin responds on direct IP (status: {direct_status}, server: {direct_server})"
        else:
            report["bypass_confirmed"] = False
            report["summary"] = f"Direct IP responded with status {direct_status} — inconclusive"
    else:
        report["bypass_confirmed"] = False
        report["summary"] = "Could not determine bypass status"

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
