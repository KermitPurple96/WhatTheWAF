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
    ("Server", "Reveals web server software and version"),
    ("X-Powered-By", "Reveals backend framework/language"),
    ("X-AspNet-Version", "Reveals ASP.NET version"),
    ("X-AspNetMvc-Version", "Reveals ASP.NET MVC version"),
    ("X-Generator", "Reveals CMS/generator"),
    ("X-Drupal-Cache", "Reveals Drupal CMS"),
    ("X-Drupal-Dynamic-Cache", "Reveals Drupal CMS"),
    ("X-Varnish", "Reveals Varnish cache proxy"),
    ("X-Rack-Cache", "Reveals Ruby Rack cache"),
    ("X-Runtime", "Reveals server processing time"),
    ("X-Debug-Token", "Debug token — should not be in production"),
    ("X-Debug-Token-Link", "Debug link — should not be in production"),
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
