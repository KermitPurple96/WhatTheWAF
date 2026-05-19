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

# Headers that might be reflected but not part of cache key
POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Proto", "http"),
    ("X-Host", "evil.com"),
    ("X-Forwarded-Server", "evil.com"),
]

# Extensions for cache deception
CACHE_DECEPTION_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".gif", ".svg",
    ".woff", ".woff2", ".ico", ".avif", ".webp",
]


def test_cache_poisoning(url, timeout=5):
    """Test for cache poisoning and cache deception vulnerabilities.

    Returns list of findings.
    """
    findings = []

    # 1. Get baseline response
    try:
        baseline = httpx.get(url, timeout=timeout, verify=False,
                             headers={"User-Agent": DEFAULT_UA})
        baseline_body = baseline.text[:10000]
        baseline_hash = hashlib.sha256(baseline_body.encode()).hexdigest()[:16]
    except Exception:
        return findings

    # 2. Test unkeyed header injection
    for header_name, header_value in POISON_HEADERS:
        try:
            resp = httpx.get(url, timeout=timeout, verify=False,
                             headers={"User-Agent": DEFAULT_UA, header_name: header_value})
            body = resp.text[:10000]

            # Check if our injected value is reflected in the response
            if header_value in body and header_value not in baseline_body:
                findings.append({
                    "type": "cache_poisoning",
                    "title": f"Header reflected: {header_name}",
                    "severity": "high",
                    "description": f"{header_name}: {header_value} reflected in response body",
                    "header": header_name,
                    "value": header_value,
                })

            # Check if response differs (header influences rendering)
            resp_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
            if resp_hash != baseline_hash and resp.status_code == baseline.status_code:
                # Check cache headers to see if this would be cached
                cache_control = resp.headers.get("cache-control", "").lower()
                if "no-store" not in cache_control and "private" not in cache_control:
                    findings.append({
                        "type": "cache_poisoning",
                        "title": f"Response varies on unkeyed header: {header_name}",
                        "severity": "medium",
                        "description": f"{header_name} changes response (cacheable: {cache_control or 'no cache-control'})",
                        "header": header_name,
                    })
        except Exception:
            pass

    # 3. Test cache deception (path confusion)
    parsed = httpx.URL(url)
    base_path = str(parsed.path).rstrip("/")
    for ext in CACHE_DECEPTION_EXTENSIONS[:5]:  # limit to avoid noise
        deception_url = f"{parsed.scheme}://{parsed.host}{base_path}/nonexistent{ext}"
        try:
            resp = httpx.get(deception_url, timeout=timeout, verify=False,
                             headers={"User-Agent": DEFAULT_UA}, follow_redirects=True)
            # If we get the same content as the original page with a static extension
            if resp.status_code == 200:
                resp_hash = hashlib.sha256(resp.text[:10000].encode()).hexdigest()[:16]
                if resp_hash == baseline_hash:
                    cache_status = resp.headers.get("cf-cache-status", resp.headers.get("x-cache", ""))
                    findings.append({
                        "type": "cache_deception",
                        "title": f"Path confusion: {ext} serves dynamic content",
                        "severity": "medium",
                        "description": f"{base_path}/nonexistent{ext} returns same content as {base_path}/ (cache: {cache_status})",
                        "extension": ext,
                    })
        except Exception:
            pass

    return findings


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
