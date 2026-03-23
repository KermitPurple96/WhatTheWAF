"""Core scanner — orchestrates all detection modules into a unified scan."""

import httpx
from .modules import dns_resolver, asn_lookup, waf_signatures, tech_fingerprint, origin_finder, geoip


def fetch_response(url, timeout=10):
    """Fetch a URL using httpx and return parsed response data."""
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
        ) as client:
            resp = client.get(url)

        headers = dict(resp.headers)
        cookies = [
            f"{k}={v}" for k, v in resp.cookies.items()
        ]
        # Also grab raw set-cookie headers
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if set_cookies:
            cookies = set_cookies

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
    """Cap body size but keep <head> and closing tags intact for fingerprinting."""
    if len(body) <= max_size:
        return body
    # Keep first 150K + last 50K to catch meta generators at the end
    return body[:150000] + "\n<!-- truncated -->\n" + body[-50000:]


def origins_scan(inputs):
    """Quick origins scan — DNS + ASN classification (like the shell function).

    Args:
        inputs: list of domains/IPs

    Returns:
        list of dicts: domain, ip, provider, classification, country
    """
    all_pairs = []  # (domain, ip)

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

    # Bulk ASN lookup
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


def full_scan(target, timeout=10, scan_subs=True, check_cert=True, check_history=False):
    """Full recon scan of a target.

    Returns a comprehensive report dict.
    """
    domain = dns_resolver._clean_domain(target)
    url = target if target.startswith("http") else f"https://{domain}"

    report = {
        "target": target,
        "domain": domain,
        "dns": {},
        "ips": [],
        "cnames": [],
        "waf": [],
        "technologies": [],
        "origin_candidates": [],
        "cert_info": None,
        "historical_ips": [],
        "cdn_detected": False,
        "waf_detected": False,
        "summary": "",
    }

    # 1. DNS resolution
    dns_info = dns_resolver.resolve_domain(domain)
    report["dns"] = dns_info
    report["cnames"] = dns_info.get("cnames", [])

    # 2. ASN lookup + Geolocation
    a_records = dns_info.get("a_records", [])
    if a_records:
        asn_records = asn_lookup.lookup_asn_bulk(a_records)
        geo_records = geoip.geolocate_bulk(a_records)
        # Merge geo into ASN records
        for asn_rec, geo_rec in zip(asn_records, geo_records):
            asn_rec["geo"] = geo_rec
        report["ips"] = asn_records
        cdn_ips = {r["ip"] for r in asn_records if r["classification"] == "CDN"}
        report["cdn_detected"] = len(cdn_ips) > 0
    else:
        asn_records = []
        cdn_ips = set()

    # 3. HTTP fetch + WAF detection + tech fingerprinting
    resp = fetch_response(url, timeout=timeout)
    if "error" not in resp:
        report["http"] = {
            "status": resp["status"],
            "server": resp["headers"].get("server", resp["headers"].get("Server", "")),
            "content_type": resp["headers"].get("content-type", resp["headers"].get("Content-Type", "")),
            "url": resp.get("url", url),
        }

        waf_results = waf_signatures.detect_waf(
            resp["headers"], resp["cookies"], resp["body"], resp["status"]
        )
        report["waf"] = waf_results
        report["waf_detected"] = any(
            d["category"] in ("WAF", "CDN/WAF") for d in waf_results
        )

        tech_results = tech_fingerprint.fingerprint_tech(
            resp["headers"], resp["cookies"], resp["body"]
        )
        report["technologies"] = tech_results
    else:
        report["http"] = {"error": resp.get("error", "unknown")}

    # 4. SSL certificate check
    if check_cert and a_records:
        cert = origin_finder.check_ssl_cert(a_records[0], domain, timeout=timeout)
        report["cert_info"] = cert

    # 5. Subdomain origin leakage scan
    if scan_subs and report["cdn_detected"]:
        candidates = origin_finder.find_origins(domain, cdn_ips=cdn_ips)
        # Filter to non-CDN only
        report["origin_candidates"] = [c for c in candidates if not c.get("is_cdn")]

    # 6. Historical DNS
    if check_history:
        report["historical_ips"] = origin_finder.fetch_historical_ips(domain)

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
    if not parts:
        parts.append("No CDN/WAF detected - likely direct to origin")
    report["summary"] = " | ".join(parts)

    return report
