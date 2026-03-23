"""Security headers audit — check for presence and quality of HTTP security headers."""

import re

# Each entry: (header_name, description, severity_if_missing, validator_func_or_None)
# severity: "high", "medium", "low", "info"
SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "description": "HSTS — forces HTTPS connections",
        "severity": "high",
        "good_values": ["max-age="],
        "best_practice": "max-age=63072000; includeSubDomains; preload",
    },
    {
        "name": "Content-Security-Policy",
        "description": "CSP — prevents XSS, injection, clickjacking",
        "severity": "high",
        "good_values": [],
        "best_practice": "default-src 'self'; script-src 'self'",
    },
    {
        "name": "X-Frame-Options",
        "description": "Prevents clickjacking via iframes",
        "severity": "medium",
        "good_values": ["deny", "sameorigin"],
        "best_practice": "DENY or SAMEORIGIN",
    },
    {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME type sniffing",
        "severity": "medium",
        "good_values": ["nosniff"],
        "best_practice": "nosniff",
    },
    {
        "name": "X-XSS-Protection",
        "description": "Legacy XSS filter (deprecated but still checked)",
        "severity": "low",
        "good_values": ["1", "1; mode=block"],
        "best_practice": "0 (disabled, rely on CSP instead)",
    },
    {
        "name": "Referrer-Policy",
        "description": "Controls referrer information sent with requests",
        "severity": "medium",
        "good_values": ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin", "no-referrer-when-downgrade"],
        "best_practice": "strict-origin-when-cross-origin",
    },
    {
        "name": "Permissions-Policy",
        "description": "Controls browser features (camera, microphone, geolocation, etc.)",
        "severity": "medium",
        "good_values": [],
        "best_practice": "camera=(), microphone=(), geolocation=()",
    },
    {
        "name": "X-Permitted-Cross-Domain-Policies",
        "description": "Controls Flash/PDF cross-domain requests",
        "severity": "low",
        "good_values": ["none", "master-only"],
        "best_practice": "none",
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "description": "COEP — controls cross-origin resource embedding",
        "severity": "low",
        "good_values": ["require-corp", "credentialless"],
        "best_practice": "require-corp",
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "description": "COOP — isolates browsing context",
        "severity": "low",
        "good_values": ["same-origin"],
        "best_practice": "same-origin",
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "description": "CORP — controls cross-origin resource sharing",
        "severity": "low",
        "good_values": ["same-origin", "same-site"],
        "best_practice": "same-origin",
    },
]

# Headers that leak information and should ideally be removed
INFO_LEAK_HEADERS = [
    # Server / platform
    ("Server", "Reveals web server software and version"),
    ("X-Powered-By", "Reveals backend framework/language"),
    ("X-AspNet-Version", "Reveals ASP.NET version"),
    ("X-AspNetMvc-Version", "Reveals ASP.NET MVC version"),
    ("X-Generator", "Reveals CMS/generator"),
    # Proxies / caches
    ("X-Varnish", "Reveals Varnish cache proxy"),
    ("X-Cache", "Reveals caching layer"),
    ("X-Cache-Hits", "Reveals cache hit count"),
    ("X-Rack-Cache", "Reveals Ruby Rack cache"),
    ("X-Served-By", "Reveals serving node/cache ID"),
    ("Via", "Reveals proxy/gateway chain"),
    # CMS / framework
    ("X-Drupal-Cache", "Reveals Drupal CMS"),
    ("X-Drupal-Dynamic-Cache", "Reveals Drupal CMS"),
    ("X-Litespeed-Cache", "Reveals LiteSpeed cache"),
    ("X-Shopify-Stage", "Reveals Shopify platform"),
    ("X-WPE-Backend", "Reveals WP Engine hosting"),
    ("X-Ah-Environment", "Reveals Acquia hosting environment"),
    ("X-Pantheon-Styx-Hostname", "Reveals Pantheon hosting"),
    ("X-Kinsta-Cache", "Reveals Kinsta hosting"),
    # Debug / internal
    ("X-Runtime", "Reveals server processing time"),
    ("X-Request-Id", "Reveals internal request ID"),
    ("X-Correlation-Id", "Reveals internal correlation ID"),
    ("X-Debug-Token", "Debug token — should not be in production"),
    ("X-Debug-Token-Link", "Debug link — should not be in production"),
    ("X-Debug-Info", "Debug info — should not be in production"),
    # CI/CD / infra
    ("X-Jenkins", "Reveals Jenkins CI"),
    ("X-GitLab-Meta", "Reveals GitLab"),
    ("X-Amz-Cf-Id", "Reveals AWS CloudFront distribution ID"),
    ("X-Amz-Request-Id", "Reveals AWS request ID"),
    ("X-Azure-Ref", "Reveals Azure infrastructure"),
    ("X-Backend-Server", "Reveals backend server hostname"),
    ("X-Upstream", "Reveals upstream server"),
    ("X-Real-IP", "Reveals real client IP — possible proxy misconfiguration"),
    ("X-Forwarded-Server", "Reveals forwarding server hostname"),
    ("X-Host", "Reveals internal hostname"),
    ("X-Envoy-Upstream-Service-Time", "Reveals Envoy service mesh"),
]


def audit_security_headers(headers):
    """Audit HTTP response headers for security best practices.

    Args:
        headers: dict of response headers

    Returns:
        dict with: present, missing, warnings, info_leaks, score
    """
    result = {
        "present": [],
        "missing": [],
        "warnings": [],
        "info_leaks": [],
        "score": 0,
        "max_score": 0,
        "grade": "",
    }

    header_lower = {k.lower(): v for k, v in headers.items()}
    points = 0
    max_points = 0

    for spec in SECURITY_HEADERS:
        name_lower = spec["name"].lower()
        severity = spec["severity"]

        # Weight by severity
        weight = {"high": 20, "medium": 10, "low": 5, "info": 1}.get(severity, 5)
        max_points += weight

        value = header_lower.get(name_lower)

        if value is not None:
            # Header is present
            entry = {
                "name": spec["name"],
                "value": value,
                "severity": severity,
                "description": spec["description"],
            }

            # Check quality
            warnings = _check_header_quality(spec, value)
            if warnings:
                entry["warnings"] = warnings
                result["warnings"].extend(warnings)
                points += weight // 2  # Half points for weak config
            else:
                points += weight

            result["present"].append(entry)
        else:
            result["missing"].append({
                "name": spec["name"],
                "severity": severity,
                "description": spec["description"],
                "best_practice": spec["best_practice"],
            })

    # Check for info leak headers
    for hdr_name, description in INFO_LEAK_HEADERS:
        value = header_lower.get(hdr_name.lower())
        if value:
            result["info_leaks"].append({
                "name": hdr_name,
                "value": value,
                "description": description,
            })

    # HSTS-specific checks
    hsts = header_lower.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m:
            max_age = int(m.group(1))
            if max_age < 31536000:  # less than 1 year
                result["warnings"].append(f"HSTS max-age is {max_age}s (< 1 year recommended)")
        if "includesubdomains" not in hsts.lower():
            result["warnings"].append("HSTS missing includeSubDomains")
        if "preload" not in hsts.lower():
            result["warnings"].append("HSTS missing preload directive")

    # CSP-specific checks
    csp = header_lower.get("content-security-policy", "")
    if csp:
        if "'unsafe-inline'" in csp:
            result["warnings"].append("CSP allows 'unsafe-inline' — weakens XSS protection")
        if "'unsafe-eval'" in csp:
            result["warnings"].append("CSP allows 'unsafe-eval' — weakens XSS protection")
        if "*" in csp.split():
            result["warnings"].append("CSP contains wildcard (*) — overly permissive")

    result["score"] = points
    result["max_score"] = max_points
    pct = (points / max_points * 100) if max_points > 0 else 0
    if pct >= 90:
        result["grade"] = "A"
    elif pct >= 75:
        result["grade"] = "B"
    elif pct >= 50:
        result["grade"] = "C"
    elif pct >= 25:
        result["grade"] = "D"
    else:
        result["grade"] = "F"

    return result


def _check_header_quality(spec, value):
    """Check if header value meets good practices."""
    warnings = []
    good = spec.get("good_values", [])
    if good:
        value_lower = value.lower()
        if not any(g.lower() in value_lower for g in good):
            warnings.append(f"{spec['name']}: unexpected value '{value}' (expected: {', '.join(good)})")
    return warnings


# --- CORS Misconfiguration Testing ---

# Origins to test for CORS reflection
_CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


def test_cors(url, timeout=5, proxy=None):
    """Test for CORS misconfigurations by sending Origin headers.

    Checks:
    1. Origin reflection — does Access-Control-Allow-Origin reflect arbitrary origins?
    2. Null origin — does it accept Origin: null?
    3. Wildcard — is ACAO set to * ?
    4. Credentials — does it allow credentials with a reflected/wildcard origin?

    Returns dict with: vulnerable, findings, details
    """
    import httpx

    result = {
        "vulnerable": False,
        "findings": [],
        "details": [],
    }

    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "verify": False,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    # First: check baseline response without Origin header
    try:
        with httpx.Client(**client_kwargs) as client:
            baseline = client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            })
        baseline_acao = baseline.headers.get("access-control-allow-origin", "")
        baseline_acac = baseline.headers.get("access-control-allow-credentials", "")

        if baseline_acao == "*":
            result["findings"].append("ACAO wildcard (*) — allows any origin to read responses")
            if baseline_acac.lower() == "true":
                result["findings"].append("CRITICAL: Wildcard + credentials — but browsers block this combo")
            result["vulnerable"] = True
            result["details"].append({
                "test": "baseline",
                "acao": baseline_acao,
                "acac": baseline_acac,
            })
    except Exception:
        return result

    # Test each evil origin
    for test_origin in _CORS_TEST_ORIGINS:
        try:
            with httpx.Client(**client_kwargs) as client:
                resp = client.get(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Origin": test_origin,
                })

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            acam = resp.headers.get("access-control-allow-methods", "")
            acah = resp.headers.get("access-control-allow-headers", "")

            detail = {
                "test_origin": test_origin,
                "acao": acao,
                "acac": acac,
                "acam": acam,
                "acah": acah,
                "reflected": False,
            }

            if test_origin == "null" and acao == "null":
                detail["reflected"] = True
                result["vulnerable"] = True
                result["findings"].append(
                    f"Origin 'null' reflected in ACAO — exploitable via sandboxed iframe"
                )
            elif acao == test_origin:
                detail["reflected"] = True
                result["vulnerable"] = True
                sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
                result["findings"].append(
                    f"{sev}: Origin '{test_origin}' reflected in ACAO"
                    + (" with credentials" if acac.lower() == "true" else "")
                )

            result["details"].append(detail)

        except Exception:
            pass

    # Also test with a subdomain-like origin to check prefix matching
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]
        # Test: evil-domain.com (prefix of real domain)
        trick_origin = f"https://evil-{domain}"
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(url, headers={
                "User-Agent": "Mozilla/5.0",
                "Origin": trick_origin,
            })
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        if acao == trick_origin:
            result["vulnerable"] = True
            result["findings"].append(
                f"Prefix bypass: '{trick_origin}' reflected in ACAO — regex/substring matching flaw"
            )
            result["details"].append({
                "test_origin": trick_origin,
                "acao": acao,
                "acac": acac,
                "reflected": True,
            })
    except Exception:
        pass

    return result
