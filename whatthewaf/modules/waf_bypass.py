"""WAF bypass testing — probe origin IPs directly to check if WAF can be circumvented.

Techniques:
1. Direct IP with Host header — hit origin IP, set Host: to the real domain
2. DNS pinning (--resolve style) — force domain resolution to a candidate IP
3. Protocol downgrade — try HTTP instead of HTTPS on origin
4. Alternative ports — try 8080, 8443 on origin
5. Path-based — common paths that may not be WAF-protected (/health, /robots.txt)
6. Header manipulation — X-Forwarded-For, X-Real-IP spoofing
"""

import hashlib
import re
import httpx

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Paths commonly unprotected by WAF
BYPASS_PATHS = [
    "/", "/robots.txt", "/favicon.ico",
    "/health", "/healthz", "/healthcheck",
    "/status", "/ping", "/ready", "/alive",
    "/.well-known/security.txt",
    "/server-status", "/server-info",
]

# Headers that might reveal origin or bypass WAF
SPOOF_HEADERS_SETS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Fastly-Client-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
]

# WAF block indicators
BLOCK_STATUS_CODES = {403, 406, 429, 503}
BLOCK_KEYWORDS = [
    "access denied", "request blocked", "forbidden", "blocked by",
    "not acceptable", "rate limit", "security check",
    "captcha", "challenge", "attention required",
    "please wait", "checking your browser",
]


def test_bypass(domain, origin_ips, timeout=10, user_agent=None, proxy=None):
    """Run WAF bypass tests against candidate origin IPs.

    Args:
        domain: the real hostname (e.g. www.factumidentity.com)
        origin_ips: list of candidate origin IPs to test
        timeout: request timeout
        user_agent: custom UA
        proxy: proxy URL

    Returns:
        dict with: baseline, ip_tests, header_tests, findings
    """
    ua = user_agent or DEFAULT_UA
    report = {
        "domain": domain,
        "baseline": None,
        "ip_tests": [],
        "header_tests": [],
        "findings": [],
    }

    # Step 1: Baseline — normal request through CDN/WAF
    report["baseline"] = _fetch_baseline(domain, timeout, ua, proxy)
    baseline = report["baseline"]
    if not baseline or baseline.get("error"):
        return report

    # Step 2: Direct IP access with Host header
    for ip in origin_ips:
        ip_result = _test_direct_ip(ip, domain, timeout, ua, proxy)
        report["ip_tests"].append(ip_result)

        if ip_result.get("accessible") and not ip_result.get("blocked"):
            finding = {
                "type": "direct_ip",
                "ip": ip,
                "detail": f"Origin responds directly at {ip} with Host: {domain}",
                "severity": "high",
            }
            # Check if WAF is actually bypassed
            if ip_result.get("waf_absent"):
                finding["detail"] += " — WAF signatures absent from direct response"
                finding["severity"] = "critical"
            report["findings"].append(finding)

        # Test alternative ports on origin
        for port in [8080, 8443]:
            alt_result = _test_direct_ip(ip, domain, timeout, ua, proxy, port=port)
            if alt_result.get("accessible"):
                alt_result["port"] = port
                report["ip_tests"].append(alt_result)
                report["findings"].append({
                    "type": "alt_port",
                    "ip": ip,
                    "port": port,
                    "detail": f"Origin accessible on port {port} at {ip}",
                    "severity": "high",
                })

        # Test HTTP (no TLS) on origin
        http_result = _test_direct_ip(ip, domain, timeout, ua, proxy, scheme="http")
        if http_result.get("accessible"):
            http_result["scheme"] = "http"
            report["ip_tests"].append(http_result)
            report["findings"].append({
                "type": "http_downgrade",
                "ip": ip,
                "detail": f"Origin accessible via plain HTTP at {ip}",
                "severity": "medium",
            })

    # Step 3: Header manipulation on the WAF-fronted domain
    for hdr_set in SPOOF_HEADERS_SETS:
        hdr_result = _test_header_spoof(domain, hdr_set, baseline, timeout, ua, proxy)
        if hdr_result.get("different"):
            report["header_tests"].append(hdr_result)
            hdr_name = list(hdr_set.keys())[0]
            report["findings"].append({
                "type": "header_spoof",
                "header": hdr_name,
                "detail": f"Response changed with {hdr_name}: {hdr_set[hdr_name]}",
                "severity": "low",
            })

    return report


def _fetch_baseline(domain, timeout, ua, proxy):
    """Fetch normal response through CDN/WAF as baseline."""
    url = f"https://{domain}/"
    try:
        kw = _client_kwargs(timeout, ua, proxy)
        with httpx.Client(**kw) as client:
            resp = client.get(url)
        return _parse_response(resp, url, "baseline")
    except Exception as e:
        return {"url": url, "error": str(e)}


def _test_direct_ip(ip, domain, timeout, ua, proxy, port=443, scheme="https"):
    """Test direct access to an IP with Host header set to the domain."""
    url = f"{scheme}://{ip}:{port}/" if port not in (80, 443) else f"{scheme}://{ip}/"
    result = {
        "url": url,
        "ip": ip,
        "host_header": domain,
        "port": port,
        "scheme": scheme,
        "accessible": False,
        "blocked": False,
        "waf_absent": False,
        "error": None,
    }

    try:
        headers = {
            "Host": domain,
            "User-Agent": ua,
            "Connection": "close",
        }
        kw = {
            "timeout": timeout,
            "follow_redirects": False,
            "verify": False,
            "headers": headers,
        }
        if proxy:
            kw["proxy"] = proxy

        with httpx.Client(**kw) as client:
            resp = client.get(url)

        parsed = _parse_response(resp, url, f"direct_ip:{ip}")
        result.update(parsed)
        result["accessible"] = True

        # Check if blocked
        if resp.status_code in BLOCK_STATUS_CODES:
            body_lower = resp.text[:5000].lower()
            if any(kw in body_lower for kw in BLOCK_KEYWORDS):
                result["blocked"] = True

        # Check if WAF signatures are absent (compare with typical WAF headers)
        waf_headers = ["cf-ray", "x-sucuri-id", "x-iinfo", "x-akamai-transformed",
                       "x-amzn-waf-action", "x-cdn"]
        has_waf = any(h in [k.lower() for k in resp.headers.keys()] for h in waf_headers)
        result["waf_absent"] = not has_waf

    except httpx.ConnectError:
        result["error"] = "connection refused"
    except httpx.ConnectTimeout:
        result["error"] = "connection timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def _test_header_spoof(domain, extra_headers, baseline, timeout, ua, proxy):
    """Test if spoofing headers changes the response."""
    url = f"https://{domain}/"
    result = {
        "url": url,
        "headers": extra_headers,
        "different": False,
        "status_changed": False,
        "body_changed": False,
    }

    try:
        headers = {"User-Agent": ua}
        headers.update(extra_headers)
        kw = _client_kwargs(timeout, ua, proxy)
        kw["headers"] = headers

        with httpx.Client(**kw) as client:
            resp = client.get(url)

        parsed = _parse_response(resp, url, "header_spoof")
        result.update(parsed)

        # Compare with baseline
        if baseline and not baseline.get("error"):
            if parsed.get("status_code") != baseline.get("status_code"):
                result["status_changed"] = True
                result["different"] = True
            if parsed.get("body_hash") != baseline.get("body_hash"):
                result["body_changed"] = True
                # Only flag as truly different if status also changed or body significantly differs
                if result["status_changed"]:
                    result["different"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def _parse_response(resp, url, label):
    """Parse httpx response into a summary dict."""
    body = resp.text[:10000]
    return {
        "url": url,
        "label": label,
        "status_code": resp.status_code,
        "content_length": len(resp.content),
        "server": resp.headers.get("server", ""),
        "body_hash": hashlib.sha256(resp.content).hexdigest()[:16],
        "title": _extract_title(body),
        "has_waf_headers": _has_waf_indicators(resp.headers),
    }


def _extract_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


def _has_waf_indicators(headers):
    """Check if response has WAF-specific headers."""
    waf_hdrs = ["cf-ray", "x-sucuri-id", "x-iinfo", "x-akamai-transformed",
                "x-amzn-waf-action", "x-cdn", "x-sucuri-cache",
                "x-ddos-protection", "x-fastly-request-id"]
    header_keys = [k.lower() for k in headers.keys()]
    return any(h in header_keys for h in waf_hdrs)


def _client_kwargs(timeout, ua, proxy):
    kw = {
        "timeout": timeout,
        "follow_redirects": True,
        "verify": False,
        "headers": {"User-Agent": ua},
    }
    if proxy:
        kw["proxy"] = proxy
    return kw
