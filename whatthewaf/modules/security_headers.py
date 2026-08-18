"""HTTP Security Headers audit."""

EXPECTED_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "severity": "high",
        "description": "Forces HTTPS — prevents SSL stripping (HSTS)",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    {
        "name": "X-Frame-Options",
        "severity": "high",
        "description": "Prevents clickjacking via iframe embedding",
        "recommended": "DENY or SAMEORIGIN",
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff",
    },
    {
        "name": "Content-Security-Policy",
        "severity": "high",
        "description": "Controls resource loading — mitigates XSS and data injection",
        "recommended": "default-src 'self'; script-src 'self'",
    },
    {
        "name": "Referrer-Policy",
        "severity": "medium",
        "description": "Controls URL leakage in Referer header",
        "recommended": "strict-origin-when-cross-origin",
    },
    {
        "name": "Permissions-Policy",
        "severity": "medium",
        "description": "Restricts browser API access (camera, mic, geolocation)",
        "recommended": "camera=(), microphone=(), geolocation=()",
    },
]

# X-XSS-Protection is DEPRECATED and dangerous when present.
# - Removed from Chrome v78 (2019), never properly supported in Firefox
# - "X-XSS-Protection: 1" (without mode=block) enables selective content
#   extraction attacks — the XSS auditor can be weaponized to remove
#   specific HTML elements, leaking data cross-origin
# - "X-XSS-Protection: 1; mode=block" was the safe value but is now a no-op
# - OWASP and MDN recommend "X-XSS-Protection: 0" or omitting it entirely
# - The proper replacement is Content-Security-Policy
# References:
#   https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
#   https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
#   https://blog.innerht.ml/the-misunderstood-x-xss-protection/
DANGEROUS_HEADERS = {
    "X-XSS-Protection": {
        "severity": "low",
        "safe_values": ["0"],
        "description": "Deprecated XSS filter — can be exploited for content extraction attacks",
        "recommendation": "Remove header or set to '0'. Use Content-Security-Policy instead.",
    },
}

# Headers that leak server info (should be removed)
INFO_LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
]

# Cookie flags to check
COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]


def audit_headers(response_headers, cookies=None, url=None):
    """Audit HTTP response headers for security issues.

    Args:
        response_headers: dict of response headers
        cookies: list of Set-Cookie header values
        url: the request URL (for context)

    Returns:
        dict with: missing, present, info_leak, cookie_issues, dangerous, score
    """
    # Normalize header keys to lowercase for lookup
    h_lower = {k.lower(): v for k, v in response_headers.items()}

    missing = []
    present = []
    warnings = []

    for spec in EXPECTED_HEADERS:
        name_lower = spec["name"].lower()
        if name_lower in h_lower:
            value = h_lower[name_lower]
            entry = {
                "name": spec["name"],
                "value": value,
                "severity": spec["severity"],
                "description": spec["description"],
            }

            # Check for weak values
            warn = _check_weak_value(spec["name"], value)
            if warn:
                entry["warning"] = warn
                warnings.append(entry)
            else:
                present.append(entry)
        else:
            missing.append({
                "name": spec["name"],
                "severity": spec["severity"],
                "description": spec["description"],
                "recommended": spec["recommended"],
            })

    # Dangerous/deprecated headers that should NOT be present
    dangerous = []
    for header_name, spec in DANGEROUS_HEADERS.items():
        if header_name.lower() in h_lower:
            value = h_lower[header_name.lower()].strip()
            is_safe = value in spec["safe_values"]
            if not is_safe:
                dangerous.append({
                    "name": header_name,
                    "value": value,
                    "severity": spec["severity"],
                    "description": spec["description"],
                    "recommendation": spec["recommendation"],
                })

    # Info leak headers
    info_leak = []
    for header in INFO_LEAK_HEADERS:
        if header.lower() in h_lower:
            info_leak.append({
                "name": header,
                "value": h_lower[header.lower()],
            })

    # Cookie security
    cookie_issues = []
    for raw_cookie in (cookies or []):
        cookie_lower = raw_cookie.lower()
        name = raw_cookie.split("=")[0].strip() if "=" in raw_cookie else raw_cookie[:30]
        issues = []
        if "secure" not in cookie_lower:
            issues.append("missing Secure flag")
        if "httponly" not in cookie_lower:
            issues.append("missing HttpOnly flag")
        if "samesite" not in cookie_lower:
            issues.append("missing SameSite attribute")
        if issues:
            cookie_issues.append({"name": name, "issues": issues, "raw": raw_cookie[:120]})

    # Score: percentage of expected headers present (without warnings)
    total = len(EXPECTED_HEADERS)
    ok = len(present)
    score = round((ok / total) * 100) if total else 0

    return {
        "missing": missing,
        "present": present,
        "warnings": warnings,
        "dangerous": dangerous,
        "info_leak": info_leak,
        "cookie_issues": cookie_issues,
        "score": score,
        "total": total,
        "url": url,
    }


def _check_weak_value(header_name, value):
    """Check for known weak configurations."""
    name = header_name.lower()
    val = value.lower().strip()

    if name == "strict-transport-security":
        if "max-age=0" in val:
            return "max-age=0 effectively disables HSTS"
        try:
            import re
            m = re.search(r"max-age=(\d+)", val)
            if m and int(m.group(1)) < 15768000:  # < 6 months
                return f"max-age too short ({m.group(1)}s) — recommend >= 31536000 (1 year)"
        except Exception:
            pass

    if name == "x-frame-options":
        if val == "allowall" or "allow-from" in val:
            return f"Weak value: {value} — use DENY or SAMEORIGIN"

    if name == "x-content-type-options":
        if val != "nosniff":
            return f"Unexpected value: {value} — should be 'nosniff'"

    if name == "content-security-policy":
        if "unsafe-inline" in val and "unsafe-eval" in val:
            return "Contains both 'unsafe-inline' and 'unsafe-eval' — weakens CSP significantly"
        if "unsafe-inline" in val:
            return "Contains 'unsafe-inline' — weakens XSS protection"
        if "unsafe-eval" in val:
            return "Contains 'unsafe-eval' — allows eval() execution"
        if "*" in val.split():
            return "Contains wildcard '*' — allows loading from any source"

    if name == "referrer-policy":
        if val in ("unsafe-url", "no-referrer-when-downgrade"):
            return f"Weak policy: {value} — leaks full URL"

    return None
