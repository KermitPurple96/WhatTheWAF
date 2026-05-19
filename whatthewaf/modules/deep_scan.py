"""Deep scan modules — alternative ports, cloud metadata, cache poisoning, WAF tier detection.

These are additional probes that go beyond basic WAF detection to find
infrastructure-level vulnerabilities between the client and the origin.
"""

import concurrent.futures
import hashlib
import re
import socket
import ssl
import httpx

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ──────────────────────────────────────────────────────────────
#  1. Alternative port scanning
# ──────────────────────────────────────────────────────────────

ALT_PORTS = {
    # HTTPS
    443: "https", 8443: "https", 4443: "https", 9443: "https",
    # HTTP
    80: "http", 8080: "http", 8000: "http", 3000: "http",
    5000: "http", 9090: "http",
    # Admin panels
    2083: "https", 2087: "https",  # cPanel
    10000: "https",  # Webmin
    8888: "https",   # Plesk
}


def scan_alt_ports(ip, domain, timeout=3, max_workers=10):
    """Scan alternative ports on an IP and check if they serve the target domain.

    Returns list of {port, scheme, status, server, body_hash, title}.
    """
    results = []

    def _probe(port, scheme):
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.close()
        except Exception:
            return None

        url = f"{scheme}://{ip}:{port}/"
        try:
            resp = httpx.get(url, timeout=timeout, verify=False,
                             headers={"Host": domain, "User-Agent": DEFAULT_UA},
                             follow_redirects=False)
            body = resp.text[:50000]
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", body[:5000], re.I | re.DOTALL)
            if m:
                title = m.group(1).strip()[:80]
            body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]
            server = resp.headers.get("server", "")

            return {
                "port": port,
                "scheme": scheme,
                "status": resp.status_code,
                "server": server,
                "body_hash": body_hash,
                "title": title,
                "content_length": len(body),
            }
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe, port, scheme): (port, scheme)
                   for port, scheme in ALT_PORTS.items()}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                results.append(result)

    results.sort(key=lambda x: x["port"])
    return results


# ──────────────────────────────────────────────────────────────
#  2. Cloud metadata probe
# ──────────────────────────────────────────────────────────────

METADATA_ENDPOINTS = [
    # AWS IMDSv1
    {
        "name": "AWS IMDSv1",
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {},
        "match": r"ami-id|instance-id|hostname|iam",
        "severity": "critical",
    },
    # AWS via IP variations (WAF bypass)
    {
        "name": "AWS IMDSv1 (hex)",
        "url": "http://0xA9FEA9FE/latest/meta-data/",
        "headers": {},
        "match": r"ami-id|instance-id|hostname",
        "severity": "critical",
    },
    # GCP
    {
        "name": "GCP Metadata",
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "match": r"instance/|project/",
        "severity": "critical",
    },
    # Azure
    {
        "name": "Azure IMDS",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "match": r"compute|vmId|subscriptionId",
        "severity": "critical",
    },
    # DigitalOcean
    {
        "name": "DigitalOcean Metadata",
        "url": "http://169.254.169.254/metadata/v1/",
        "headers": {},
        "match": r"droplet_id|hostname|region",
        "severity": "critical",
    },
]


def probe_cloud_metadata(ip, timeout=3):
    """Probe cloud metadata endpoints via an origin IP.

    This tests if the origin server can be used for SSRF to cloud metadata.
    We connect to the origin IP but request the metadata URL.

    Returns list of findings.
    """
    findings = []

    for endpoint in METADATA_ENDPOINTS:
        try:
            # We're testing if the origin IP has metadata service accessible
            # directly (not via SSRF — but exposed metadata = misconfiguration)
            resp = httpx.get(
                endpoint["url"].replace("169.254.169.254", ip).replace("metadata.google.internal", ip),
                timeout=timeout,
                verify=False,
                headers={**endpoint["headers"], "User-Agent": DEFAULT_UA},
                follow_redirects=False,
            )
            if resp.status_code == 200 and re.search(endpoint["match"], resp.text, re.IGNORECASE):
                findings.append({
                    "endpoint": endpoint["name"],
                    "url": endpoint["url"],
                    "severity": endpoint["severity"],
                    "status": resp.status_code,
                    "evidence": resp.text[:200],
                })
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────────────────────
#  3. Cache poisoning tests
# ──────────────────────────────────────────────────────────────

# Headers that might be reflected/used but not part of cache key
POISON_HEADERS = [
    ("X-Forwarded-Host", "wtw-poison-test.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Original-URL", "/wtw-poison-test"),
    ("X-Rewrite-URL", "/wtw-poison-test"),
    ("X-Forwarded-Proto", "http"),
    ("X-Host", "wtw-poison-test.com"),
    ("X-Forwarded-Server", "wtw-poison-test.com"),
    ("X-Forwarded-Port", "1337"),
    ("X-Forwarded-Prefix", "/wtw-poison-test"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("Fastly-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
]

# Extensions for cache deception testing
CACHE_DECEPTION_PATHS = [
    # Standard static extensions
    "/nonexistent.css",
    "/nonexistent.js",
    "/nonexistent.png",
    "/nonexistent.avif",
    "/nonexistent.webp",
    # Path confusion variants
    ";/style.css",
    "%00.css",
    "/.css",
    "/..%2f..%2fstyle.css",
    "%2f.css",
]


def _get_cache_indicators(resp):
    """Extract cache-related info from response headers."""
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    return {
        "cache_control": hdrs.get("cache-control", ""),
        "age": hdrs.get("age", ""),
        "x_cache": hdrs.get("x-cache", ""),
        "cf_cache_status": hdrs.get("cf-cache-status", ""),
        "x_cache_status": hdrs.get("x-cache-status", ""),
        "via": hdrs.get("via", ""),
        "is_cacheable": (
            "no-store" not in hdrs.get("cache-control", "").lower()
            and "private" not in hdrs.get("cache-control", "").lower()
        ),
        "is_cached": (
            hdrs.get("x-cache", "").upper().startswith("HIT")
            or hdrs.get("cf-cache-status", "").upper() == "HIT"
            or hdrs.get("x-cache-status", "").upper() == "HIT"
            or bool(hdrs.get("age", ""))
        ),
    }


def test_cache_poisoning(url, timeout=5):
    """Test for cache poisoning and cache deception vulnerabilities.

    Methodology:
    1. Baseline: fetch with cache buster to get clean response
    2. Header poisoning: inject each header, check if reflected or response changes
    3. Verify cacheability: check Cache-Control, X-Cache, Age headers
    4. Confirm cached: re-request WITHOUT the header, check if poison persists
    5. Cache deception: path confusion with static extensions + variants

    Returns list of findings.
    """
    import random
    import string

    findings = []
    cache_buster = "".join(random.choices(string.ascii_lowercase, k=8))

    # 1. Baseline with cache buster (guaranteed MISS)
    try:
        baseline_url = f"{url}{'&' if '?' in url else '?'}wtw_cb={cache_buster}"
        baseline = httpx.get(baseline_url, timeout=timeout, verify=False,
                             headers={"User-Agent": DEFAULT_UA})
        baseline_body = baseline.text[:10000]
        baseline_hash = hashlib.sha256(baseline_body.encode()).hexdigest()[:16]
        baseline_cache = _get_cache_indicators(baseline)
    except Exception:
        return findings

    # 2. Test unkeyed header injection
    for header_name, header_value in POISON_HEADERS:
        try:
            # Request with poison header + new cache buster
            cb = "".join(random.choices(string.ascii_lowercase, k=8))
            poison_url = f"{url}{'&' if '?' in url else '?'}wtw_cb={cb}"
            resp = httpx.get(poison_url, timeout=timeout, verify=False,
                             headers={"User-Agent": DEFAULT_UA, header_name: header_value})
            body = resp.text[:10000]
            resp_cache = _get_cache_indicators(resp)

            # Check if our injected value is reflected in the response body
            if header_value in body and header_value not in baseline_body:
                # HIGH: value reflected — if cached, attacker controls page content
                desc = f"{header_name}: {header_value} reflected in response body"
                if resp_cache["is_cacheable"]:
                    desc += f" (cacheable: {resp_cache['cache_control'] or 'no cache-control'})"

                    # Confirm: re-request WITHOUT the header, same cache buster
                    # If the response still contains our value → it was cached
                    try:
                        verify = httpx.get(poison_url, timeout=timeout, verify=False,
                                           headers={"User-Agent": DEFAULT_UA})
                        if header_value in verify.text[:10000]:
                            desc += " — CONFIRMED CACHED (poison persists without header)"
                            severity = "critical"
                        else:
                            severity = "high"
                    except Exception:
                        severity = "high"
                else:
                    severity = "medium"  # Reflected but not cacheable

                findings.append({
                    "type": "cache_poisoning",
                    "title": f"Header reflected: {header_name}",
                    "severity": severity,
                    "description": desc,
                    "header": header_name,
                    "value": header_value,
                })
                continue  # Don't double-report

            # Check if response differs (header influences server behavior)
            resp_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
            if resp_hash != baseline_hash and resp.status_code == baseline.status_code:
                if resp_cache["is_cacheable"]:
                    findings.append({
                        "type": "cache_poisoning",
                        "title": f"Response varies on unkeyed header: {header_name}",
                        "severity": "medium",
                        "description": f"{header_name} changes response (cacheable: {resp_cache['cache_control'] or 'no cache-control'})",
                        "header": header_name,
                    })
        except Exception:
            pass

    # 3. Test cache deception (path confusion)
    parsed = httpx.URL(url)
    base_path = str(parsed.path).rstrip("/") or ""

    for suffix in CACHE_DECEPTION_PATHS:
        deception_url = f"{parsed.scheme}://{parsed.host}{base_path}{suffix}"
        try:
            resp = httpx.get(deception_url, timeout=timeout, verify=False,
                             headers={"User-Agent": DEFAULT_UA}, follow_redirects=True)
            if resp.status_code == 200:
                resp_hash = hashlib.sha256(resp.text[:10000].encode()).hexdigest()[:16]
                resp_cache = _get_cache_indicators(resp)

                # Same content as original page served under a static-looking path
                if resp_hash == baseline_hash:
                    severity = "high" if resp_cache["is_cached"] else "medium"
                    cache_info = resp_cache["cf_cache_status"] or resp_cache["x_cache"] or resp_cache["cache_control"] or "unknown"
                    findings.append({
                        "type": "cache_deception",
                        "title": f"Path confusion: {suffix}",
                        "severity": severity,
                        "description": f"{base_path}{suffix} returns same content as {base_path}/ (cache: {cache_info})",
                        "path": suffix,
                        "cached": resp_cache["is_cached"],
                    })
        except Exception:
            pass

    # Deduplicate (same header shouldn't appear twice)
    seen = set()
    deduped = []
    for f in findings:
        key = f.get("header", f.get("path", f["title"]))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    deduped.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 9))
    return deduped


# ──────────────────────────────────────────────────────────────
#  4. WAF tier/plan detection
# ──────────────────────────────────────────────────────────────

def detect_waf_tier(url, waf_name, headers, cookies, body, timeout=5):
    """Detect the WAF tier/plan level based on behavioral signals.

    Returns dict with: tier, confidence, evidence.
    """
    result = {"waf": waf_name, "tier": "unknown", "confidence": 0, "evidence": []}

    if not waf_name:
        return result

    waf_lower = waf_name.lower()
    cookie_str = "\n".join(cookies).lower() if cookies else ""
    headers_lower = {k.lower(): v for k, v in headers.items()} if headers else {}

    if "cloudflare" in waf_lower:
        result = _detect_cloudflare_tier(headers_lower, cookie_str, body, url, timeout)
    elif "akamai" in waf_lower:
        result = _detect_akamai_tier(headers_lower, cookie_str, body)
    elif "imperva" in waf_lower or "incapsula" in waf_lower:
        result = _detect_imperva_tier(headers_lower, cookie_str, body)
    elif "aws" in waf_lower or "cloudfront" in waf_lower:
        result = _detect_aws_tier(headers_lower, cookie_str, body)

    result["waf"] = waf_name
    return result


def _detect_cloudflare_tier(headers, cookies, body, url, timeout):
    """Detect Cloudflare plan: Free, Pro, Business, Enterprise."""
    tier = "Free"
    confidence = 0.3
    evidence = []

    # __cf_bm cookie = Bot Management (Enterprise)
    if "__cf_bm" in cookies:
        tier = "Enterprise"
        confidence = 0.9
        evidence.append("__cf_bm cookie (Bot Management)")

    # cf-mitigated header = active WAF rules
    if "cf-mitigated" in headers:
        if tier != "Enterprise":
            tier = "Pro+"
            confidence = max(confidence, 0.6)
        evidence.append("cf-mitigated header")

    # Managed challenge complexity
    if "cf-chl-bypass" in cookies:
        evidence.append("cf-chl-bypass cookie (challenge active)")
        if tier == "Free":
            tier = "Pro+"
            confidence = max(confidence, 0.5)

    # Check for custom WAF rules by sending a benign-but-unusual request
    try:
        resp = httpx.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": DEFAULT_UA, "X-Custom-Test": "whatthewaf"})
        # Enterprise with custom rules might block custom headers
        if resp.status_code in (403, 503) and "cloudflare" in resp.text.lower():
            tier = "Business/Enterprise"
            confidence = max(confidence, 0.7)
            evidence.append("Custom header triggered block (custom WAF rules)")
    except Exception:
        pass

    # nel header (Network Error Logging) = Enterprise feature
    if "nel" in headers or "report-to" in headers:
        evidence.append("NEL/Report-To headers (Enterprise feature)")
        if tier in ("Free", "Pro+"):
            tier = "Business/Enterprise"
            confidence = max(confidence, 0.6)

    return {"tier": tier, "confidence": round(confidence, 2), "evidence": evidence}


def _detect_akamai_tier(headers, cookies, body):
    """Detect Akamai tier: Standard, Kona Site Defender, App & API Protector."""
    tier = "Standard"
    confidence = 0.4
    evidence = []

    if "x-akamai-transformed" in headers:
        evidence.append("x-akamai-transformed header")

    # Kona Site Defender headers
    if "x-kona-error" in headers or "akamai-origin-hop" in headers:
        tier = "Kona Site Defender"
        confidence = 0.8
        evidence.append("Kona-specific headers")

    # Bot Manager
    if "ak_bmsc" in cookies:
        tier = "Bot Manager"
        confidence = 0.9
        evidence.append("ak_bmsc cookie (Bot Manager)")

    # Sensor data collection (advanced bot detection)
    if "_abck" in cookies:
        tier = "Bot Manager Premier"
        confidence = 0.9
        evidence.append("_abck cookie (advanced bot detection)")

    return {"tier": tier, "confidence": round(confidence, 2), "evidence": evidence}


def _detect_imperva_tier(headers, cookies, body):
    """Detect Imperva/Incapsula tier."""
    tier = "Standard"
    confidence = 0.4
    evidence = []

    if "incap_ses_" in cookies:
        evidence.append("incap_ses_ cookie")
    if "visid_incap_" in cookies:
        evidence.append("visid_incap_ cookie")
    if "nlbi_" in cookies:
        tier = "Advanced"
        confidence = 0.7
        evidence.append("nlbi_ cookie (load balancer)")

    # Advanced bot protection
    if "reese84" in cookies:
        tier = "Advanced Bot Protection"
        confidence = 0.9
        evidence.append("reese84 cookie (advanced bot detection)")

    return {"tier": tier, "confidence": round(confidence, 2), "evidence": evidence}


def _detect_aws_tier(headers, cookies, body):
    """Detect AWS WAF/Shield tier."""
    tier = "CloudFront"
    confidence = 0.4
    evidence = []

    if "x-amzn-waf-action" in headers:
        tier = "AWS WAF"
        confidence = 0.8
        evidence.append("x-amzn-waf-action header")

    if "aws-waf-token" in cookies:
        tier = "AWS WAF with Bot Control"
        confidence = 0.9
        evidence.append("aws-waf-token cookie (Bot Control)")

    if "x-amzn-requestid" in headers:
        evidence.append("x-amzn-requestid header")

    return {"tier": tier, "confidence": round(confidence, 2), "evidence": evidence}
