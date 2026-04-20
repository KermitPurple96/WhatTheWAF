"""WAF evasion analysis — detect what the WAF is checking about us."""

import hashlib
import concurrent.futures
import httpx

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# User-Agent strings to test
TEST_USER_AGENTS = [
    ("Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    ("Firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"),
    ("curl", "curl/8.18.0"),
    ("Python-requests", "python-requests/2.31.0"),
    ("Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("Empty", ""),
    ("Burp-like", "Java/17.0.1"),
    ("wget", "Wget/1.21.3"),
    ("sqlmap", "sqlmap/1.7"),
    ("Nikto", "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"),
]

# Encoding tricks to test
ENCODING_TESTS = [
    ("Normal path", "/"),
    ("URL encoded dot", "/%2e/"),
    ("Double URL encoded", "/%252e/"),
    ("Unicode dot", "/..%c0%af/"),
    ("Overlong UTF-8", "/%c0%ae/"),
    ("Mixed case", "/INDEX.HTML"),
    ("Path with semicolon", "/;/"),
    ("Null byte", "/%00/"),
    ("Double slash", "//"),
    ("Backslash", "/\\/"),
]


def analyze_waf_detection(domain, timeout=10, user_agent=None, proxy=None):
    """Determine what the WAF detects about us.

    Returns dict with findings about UA sensitivity, rate limiting,
    encoding bypass, method restrictions, and evasion recommendations.
    """
    result = {
        "ua_tests": [],
        "ua_sensitive": False,
        "method_tests": [],
        "encoding_tests": [],
        "rate_test": {},
        "findings": [],
        "evasion_recommendations": [],
    }

    url = f"https://{domain}/"
    base_kw = {"timeout": timeout, "follow_redirects": True, "verify": False}
    if proxy:
        base_kw["proxy"] = proxy

    # 1. Baseline request
    baseline = _quick_fetch(url, DEFAULT_UA, base_kw)
    if not baseline or baseline.get("error"):
        result["error"] = baseline.get("error", "Could not reach target")
        return result

    baseline_hash = baseline.get("body_hash", "")
    baseline_status = baseline.get("status_code", 0)

    # 2. User-Agent sensitivity
    for ua_name, ua_string in TEST_USER_AGENTS:
        test = _quick_fetch(url, ua_string, base_kw)
        test["ua_name"] = ua_name
        test["ua_string"] = ua_string[:60]

        if test.get("status_code") != baseline_status:
            test["different"] = True
            result["ua_sensitive"] = True
        elif test.get("body_hash") != baseline_hash:
            test["different"] = True
        else:
            test["different"] = False

        result["ua_tests"].append(test)

    if result["ua_sensitive"]:
        blocked_uas = [t["ua_name"] for t in result["ua_tests"]
                       if t.get("status_code") in (403, 406, 429, 503)]
        if blocked_uas:
            result["findings"].append(
                f"WAF blocks User-Agents: {', '.join(blocked_uas)}"
            )
            result["evasion_recommendations"].append(
                "Use a browser-like User-Agent (Chrome/Firefox)"
            )

    # 3. HTTP method testing
    for method in ["GET", "HEAD", "OPTIONS", "POST", "TRACE", "PUT"]:
        try:
            with httpx.Client(**base_kw) as client:
                resp = client.request(method, url, headers={"User-Agent": DEFAULT_UA})
            result["method_tests"].append({
                "method": method,
                "status_code": resp.status_code,
                "allowed": resp.status_code not in (405, 403, 501),
            })
        except Exception as e:
            result["method_tests"].append({"method": method, "error": str(e)})

    allowed = [t["method"] for t in result["method_tests"] if t.get("allowed")]
    blocked = [t["method"] for t in result["method_tests"] if not t.get("allowed") and not t.get("error")]
    if "TRACE" in allowed:
        result["findings"].append("TRACE method allowed — potential XST (Cross-Site Tracing)")
    if blocked:
        result["findings"].append(f"Blocked HTTP methods: {', '.join(blocked)}")

    # 4. Encoding bypass tests
    for enc_name, enc_path in ENCODING_TESTS:
        test_url = f"https://{domain}{enc_path}"
        test = _quick_fetch(test_url, DEFAULT_UA, base_kw)
        test["name"] = enc_name
        test["path"] = enc_path

        if test.get("status_code") and test["status_code"] != baseline_status:
            test["different"] = True
            if test["status_code"] in (200, 301, 302) and baseline_status in (403, 503):
                result["findings"].append(
                    f"Encoding bypass: '{enc_name}' ({enc_path}) returns {test['status_code']} "
                    f"instead of {baseline_status}"
                )
                result["evasion_recommendations"].append(
                    f"Use encoding '{enc_name}' to bypass WAF: curl -sk 'https://{domain}{enc_path}'"
                )
        else:
            test["different"] = False

        result["encoding_tests"].append(test)

    # 5. Rate limiting test (5 rapid requests)
    statuses = []
    for i in range(5):
        try:
            with httpx.Client(**base_kw) as client:
                resp = client.get(url, headers={"User-Agent": DEFAULT_UA})
            statuses.append(resp.status_code)
        except Exception:
            statuses.append(0)

    result["rate_test"] = {
        "requests": 5,
        "statuses": statuses,
        "rate_limited": any(s == 429 for s in statuses),
    }
    if result["rate_test"]["rate_limited"]:
        result["findings"].append("Rate limiting detected after rapid requests")
        result["evasion_recommendations"].append(
            "Add delay between requests (--delay 1) or use proxy rotation"
        )

    # 6. Protocol version test (HTTP/1.0 vs 1.1)
    try:
        import socket
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for proto_ver in ["1.0", "1.1"]:
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    req = f"GET / HTTP/{proto_ver}\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                    ssock.send(req.encode())
                    data = ssock.recv(2048).decode("utf-8", errors="replace")
                    status = 0
                    if "HTTP/" in data:
                        parts = data.split(" ", 2)
                        if len(parts) >= 2:
                            try: status = int(parts[1])
                            except: pass
                    result[f"http_{proto_ver.replace('.', '')}_status"] = status
    except Exception:
        pass

    if not result["evasion_recommendations"]:
        result["evasion_recommendations"].append("WAF does not appear to be doing advanced detection")

    return result


def _quick_fetch(url, ua, base_kw):
    """Quick fetch returning status + body hash."""
    try:
        kw = dict(base_kw)
        kw["headers"] = {"User-Agent": ua} if ua else {}
        with httpx.Client(**kw) as client:
            resp = client.get(url)
        body = resp.text[:5000]
        return {
            "status_code": resp.status_code,
            "body_hash": hashlib.sha256(body.encode()).hexdigest()[:12],
            "server": resp.headers.get("server", ""),
        }
    except Exception as e:
        return {"error": str(e)}
