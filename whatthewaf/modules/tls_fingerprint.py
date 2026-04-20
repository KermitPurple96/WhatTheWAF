"""TLS fingerprint analysis — detect what WAFs see about our TLS handshake."""

import ssl
import socket
import hashlib
import httpx

# Known JA3-like client profiles (reference, not actual hashes - for comparison)
KNOWN_CLIENTS = {
    "Chrome": {"tls": "TLSv1.3", "alpn": "h2", "ciphers_count": "~15"},
    "Firefox": {"tls": "TLSv1.3", "alpn": "h2", "ciphers_count": "~17"},
    "curl/OpenSSL": {"tls": "TLSv1.3", "alpn": "h2,http/1.1", "ciphers_count": "~90"},
    "Python/urllib": {"tls": "TLSv1.3", "alpn": None, "ciphers_count": "~90"},
    "Java/Burp": {"tls": "TLSv1.2", "alpn": None, "ciphers_count": "~40"},
    "Go net/http": {"tls": "TLSv1.3", "alpn": "h2", "ciphers_count": "~5"},
}


def analyze_tls_fingerprint(domain, port=443, timeout=10):
    """Analyze our TLS fingerprint and compare with browser fingerprints.

    Returns dict with: our_tls_version, our_cipher, our_alpn, our_sni,
                       browser_differences, recommendations
    """
    result = {
        "our_tls_version": "",
        "our_cipher": "",
        "our_alpn": "",
        "our_sni": domain,
        "our_ciphers_count": 0,
        "browser_differences": [],
        "recommendations": [],
        "config_tests": [],
    }

    # 1. Analyze our default TLS fingerprint
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["our_tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["our_cipher"] = cipher[0]
                result["our_alpn"] = ssock.selected_alpn_protocol() or ""

        # Count available ciphers
        result["our_ciphers_count"] = len(ctx.get_ciphers())

    except Exception as e:
        result["error"] = str(e)
        return result

    # 2. Compare with known browser profiles
    if not result["our_alpn"]:
        result["browser_differences"].append(
            "No ALPN negotiated — browsers always negotiate h2. WAFs may flag this."
        )
        result["recommendations"].append(
            "Use a client that supports HTTP/2 ALPN (e.g., curl with --http2)"
        )

    if result["our_ciphers_count"] > 50:
        result["browser_differences"].append(
            f"Offering {result['our_ciphers_count']} cipher suites — browsers offer ~15-17. "
            f"Large cipher list is a strong indicator of non-browser client."
        )
        result["recommendations"].append(
            "Restrict cipher suites to match a browser profile"
        )

    if result["our_tls_version"] == "TLSv1.2":
        result["browser_differences"].append(
            "Using TLS 1.2 — modern browsers prefer TLS 1.3"
        )

    # 3. Test different TLS configurations to see what WAF accepts
    configs = [
        ("Default Python", {}),
        ("TLS 1.3 only", {"min_version": ssl.TLSVersion.TLSv1_3, "max_version": ssl.TLSVersion.TLSv1_3}),
        ("TLS 1.2 only", {"min_version": ssl.TLSVersion.TLSv1_2, "max_version": ssl.TLSVersion.TLSv1_2}),
        ("Chrome-like ciphers", {"ciphers": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"}),
    ]

    for config_name, config_opts in configs:
        test_result = _test_tls_config(domain, port, timeout, config_name, config_opts)
        result["config_tests"].append(test_result)

    # Analyze which configs were accepted vs rejected
    accepted = [t for t in result["config_tests"] if t.get("accepted")]
    rejected = [t for t in result["config_tests"] if not t.get("accepted") and not t.get("error")]

    if rejected:
        result["recommendations"].append(
            f"WAF rejected {len(rejected)} TLS configuration(s): "
            + ", ".join(t["config"] for t in rejected)
        )

    return result


def _test_tls_config(domain, port, timeout, config_name, config_opts):
    """Test a specific TLS configuration."""
    test = {"config": config_name, "accepted": False, "status_code": None, "error": None}

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if "min_version" in config_opts:
            ctx.minimum_version = config_opts["min_version"]
        if "max_version" in config_opts:
            ctx.maximum_version = config_opts["max_version"]
        if "ciphers" in config_opts:
            ctx.set_ciphers(config_opts["ciphers"])

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                test["tls_version"] = ssock.version()
                test["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""

                # Send a minimal HTTP request to check if WAF accepts
                request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                ssock.send(request.encode())
                response = ssock.recv(1024).decode("utf-8", errors="replace")

                if "HTTP/" in response:
                    status_line = response.split("\r\n")[0]
                    parts = status_line.split(" ", 2)
                    if len(parts) >= 2:
                        try:
                            test["status_code"] = int(parts[1])
                        except ValueError:
                            pass

                test["accepted"] = test.get("status_code") not in (None, 403, 503)

    except ssl.SSLError as e:
        test["error"] = f"SSL: {e}"
    except socket.timeout:
        test["error"] = "timeout"
    except Exception as e:
        test["error"] = str(e)

    return test


def test_tls_configurations(domain, port=443, timeout=10):
    """Test multiple TLS configurations to find what WAF accepts/blocks.

    Returns list of config test results.
    """
    result = analyze_tls_fingerprint(domain, port, timeout)
    return result.get("config_tests", [])
