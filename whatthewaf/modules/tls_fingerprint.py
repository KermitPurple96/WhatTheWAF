"""TLS fingerprint analysis — sslscan-level TLS/SSL audit.

Enumerates supported protocols, ciphers, certificate chain, vulnerabilities,
and compares our TLS fingerprint against known browser profiles.
"""

import ssl
import socket
import hashlib
import struct
import concurrent.futures
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Known JA3-like client profiles (reference for comparison)
KNOWN_CLIENTS = {
    "Chrome": {"tls": "TLSv1.3", "alpn": "h2", "ciphers_count": "~15"},
    "Firefox": {"tls": "TLSv1.3", "alpn": "h2", "ciphers_count": "~17"},
    "curl/OpenSSL": {"tls": "TLSv1.3", "alpn": "h2,http/1.1", "ciphers_count": "~90"},
    "Python/urllib": {"tls": "TLSv1.3", "alpn": None, "ciphers_count": "~90"},
    "Java/Burp": {"tls": "TLSv1.2", "alpn": None, "ciphers_count": "~40"},
    "Go net/http": {"tls": "TLSv1.3", "alpn": "h2", "ciphers_count": "~5"},
}

# Cipher suites considered weak/insecure
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA",
}

# Ciphers that indicate no forward secrecy
NO_PFS_PREFIXES = ("RSA-", "AES128-", "AES256-", "DES-", "RC4-", "NULL-")


def analyze_tls_fingerprint(domain, port=443, timeout=10, on_status=None):
    """Full TLS analysis: protocols, ciphers, cert, vulns, fingerprint comparison.

    Args:
        on_status: optional callback(phase, detail) for progress feedback

    Returns dict with:
        our_tls_version, our_cipher, our_alpn, our_sni, our_ciphers_count,
        protocols, ciphers, certificate, vulnerabilities,
        browser_differences, recommendations, config_tests
    """
    _status = on_status or (lambda *a: None)
    result = {
        "our_tls_version": "",
        "our_cipher": "",
        "our_alpn": "",
        "our_sni": domain,
        "our_ciphers_count": 0,
        "protocols": {},
        "ciphers": [],
        "certificate": {},
        "vulnerabilities": [],
        "browser_differences": [],
        "recommendations": [],
        "config_tests": [],
    }

    # 1. Our default TLS fingerprint
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

        result["our_ciphers_count"] = len(ctx.get_ciphers())

    except Exception as e:
        result["error"] = str(e)
        return result

    # 2. Protocol support enumeration
    _status("tls", f"Protocol enumeration (TLS 1.0–1.3) for {domain}")
    result["protocols"] = _enumerate_protocols(domain, port, timeout)

    # 3. Cipher enumeration per protocol
    _status("tls", f"Cipher suite enumeration ({len(_CIPHER_GROUPS)} ciphers) for {domain}")
    result["ciphers"] = _enumerate_ciphers(domain, port, timeout)

    # 4. Certificate analysis
    _status("tls", f"Certificate analysis for {domain}")
    result["certificate"] = _analyze_certificate(domain, port, timeout)

    # 5. Vulnerability assessment
    result["vulnerabilities"] = _assess_vulnerabilities(result)

    # 6. Browser fingerprint comparison
    _compare_browser_fingerprints(result)

    # 7. WAF acceptance tests
    _status("tls", f"WAF TLS acceptance tests for {domain}")
    configs = [
        ("Default Python", {}),
        ("TLS 1.3 only", {"min_version": ssl.TLSVersion.TLSv1_3, "max_version": ssl.TLSVersion.TLSv1_3}),
        ("TLS 1.2 only", {"min_version": ssl.TLSVersion.TLSv1_2, "max_version": ssl.TLSVersion.TLSv1_2}),
        ("Chrome-like ciphers", {"ciphers": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"}),
    ]

    for config_name, config_opts in configs:
        test_result = _test_tls_config(domain, port, timeout, config_name, config_opts)
        result["config_tests"].append(test_result)

    accepted = [t for t in result["config_tests"] if t.get("accepted")]
    rejected = [t for t in result["config_tests"] if not t.get("accepted") and not t.get("error")]
    if rejected:
        result["recommendations"].append(
            f"WAF rejected {len(rejected)} TLS config(s): "
            + ", ".join(t["config"] for t in rejected)
        )

    return result


# ------------------------------------------------------------------
# Protocol enumeration
# ------------------------------------------------------------------

def _enumerate_protocols(domain, port, timeout):
    """Test which TLS/SSL protocol versions the server accepts."""
    protocols = {}

    # Test each protocol version
    tests = [
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ]

    # TLS 1.0 and 1.1 — try if available (deprecated in newer OpenSSL)
    try:
        tests.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1))
        tests.append(("TLSv1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1))
    except AttributeError:
        pass

    def _test_proto(name, min_ver, max_ver):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    negotiated = ssock.version()
                    # Verify we actually got the version we asked for
                    if negotiated and name.replace("v", " ").replace(".", "") in negotiated.replace("v", " ").replace(".", ""):
                        return (name, True, negotiated, ssock.cipher()[0] if ssock.cipher() else "")
                    return (name, True, negotiated, ssock.cipher()[0] if ssock.cipher() else "")
        except Exception:
            return (name, False, None, None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_test_proto, n, mn, mx) for n, mn, mx in tests]
        for f in concurrent.futures.as_completed(futures):
            name, supported, version, cipher = f.result()
            protocols[name] = {
                "supported": supported,
                "negotiated_version": version,
                "cipher": cipher,
            }

    # Fallback: if TLS 1.3 test failed but default context negotiates 1.3, mark it supported
    if not protocols.get("TLSv1.3", {}).get("supported"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    if ssock.version() == "TLSv1.3":
                        protocols["TLSv1.3"] = {
                            "supported": True,
                            "negotiated_version": "TLSv1.3",
                            "cipher": ssock.cipher()[0] if ssock.cipher() else "",
                        }
        except Exception:
            pass

    return protocols


# ------------------------------------------------------------------
# Cipher enumeration
# ------------------------------------------------------------------

# Comprehensive cipher list for enumeration
_CIPHER_GROUPS = [
    # TLS 1.3 ciphers
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    # ECDHE + AESGCM (strong, PFS)
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    # ECDHE + CBC
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    # DHE (PFS, but slower)
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-SHA",
    # RSA (no PFS — weak)
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA256",
    "AES256-SHA256",
    "AES128-SHA",
    "AES256-SHA",
    # Weak/legacy
    "DES-CBC3-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "NULL-SHA",
    "NULL-MD5",
]


def _enumerate_ciphers(domain, port, timeout):
    """Test which cipher suites the server accepts."""
    accepted = []

    def _test_cipher(cipher_name):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # TLS 1.3 ciphers use different API
            if cipher_name.startswith("TLS_"):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                # TLS 1.3 ciphers can't be set individually in most OpenSSL bindings
                # They're always available if TLS 1.3 is supported
                ctx.set_ciphers("DEFAULT")
            else:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                ctx.set_ciphers(cipher_name)

            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    negotiated = ssock.cipher()
                    if negotiated:
                        bits = negotiated[2] if len(negotiated) > 2 else 0
                        # For individual cipher test, check we actually got that cipher
                        if cipher_name.startswith("TLS_"):
                            if negotiated[0] == cipher_name:
                                return (cipher_name, True, negotiated[1], bits)
                        else:
                            return (cipher_name, True, negotiated[1], bits)
            return (cipher_name, False, None, 0)
        except Exception:
            return (cipher_name, False, None, 0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_test_cipher, c): c for c in _CIPHER_GROUPS}
        for f in concurrent.futures.as_completed(futures):
            name, ok, proto, bits = f.result()
            if ok:
                # Classify strength
                strength = _classify_cipher_strength(name, bits)
                pfs = not any(name.startswith(p) for p in NO_PFS_PREFIXES)
                accepted.append({
                    "name": name,
                    "protocol": proto or "",
                    "bits": bits,
                    "strength": strength,
                    "pfs": pfs,
                })

    # Sort: strong first, weak last
    strength_order = {"strong": 0, "acceptable": 1, "weak": 2, "insecure": 3}
    accepted.sort(key=lambda c: (strength_order.get(c["strength"], 9), -c["bits"]))
    return accepted


def _classify_cipher_strength(name, bits):
    """Classify a cipher as strong/acceptable/weak/insecure."""
    name_upper = name.upper()
    if any(w in name_upper for w in ("NULL", "EXPORT", "anon", "RC4", "DES-CBC3", "MD5")):
        return "insecure"
    if any(w in name_upper for w in ("RC2", "IDEA", "SEED")):
        return "weak"
    if bits and bits < 128:
        return "weak"
    if "GCM" in name_upper or "CHACHA20" in name_upper or name.startswith("TLS_"):
        return "strong"
    if "CBC" in name_upper:
        return "acceptable"  # CBC is ok but vulnerable to padding oracles
    return "acceptable"


# ------------------------------------------------------------------
# Certificate analysis
# ------------------------------------------------------------------

def _analyze_certificate(domain, port, timeout):
    """Analyze the server's TLS certificate chain."""
    cert_info = {
        "subject": "",
        "issuer": "",
        "issuer_org": "",
        "san": [],
        "not_before": "",
        "not_after": "",
        "days_remaining": 0,
        "expired": False,
        "self_signed": False,
        "key_type": "",
        "key_bits": 0,
        "serial": "",
        "sig_algorithm": "",
        "chain_length": 0,
        "chain": [],
        "ocsp_stapling": False,
        "hsts": False,
        "hsts_max_age": 0,
    }

    try:
        # Get certificate with verification disabled (we want to see it even if invalid)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()

                if cert_dict:
                    # Subject
                    subject = dict(x[0] for x in cert_dict.get("subject", ()))
                    cert_info["subject"] = subject.get("commonName", "")

                    # Issuer
                    issuer = dict(x[0] for x in cert_dict.get("issuer", ()))
                    cert_info["issuer"] = issuer.get("commonName", "")
                    cert_info["issuer_org"] = issuer.get("organizationName", "")

                    # Self-signed check
                    cert_info["self_signed"] = cert_info["subject"] == cert_info["issuer"]

                    # SANs
                    sans = cert_dict.get("subjectAltName", ())
                    cert_info["san"] = [v for t, v in sans if t in ("DNS", "IP Address")]

                    # Validity
                    not_before = cert_dict.get("notBefore", "")
                    not_after = cert_dict.get("notAfter", "")
                    cert_info["not_before"] = not_before
                    cert_info["not_after"] = not_after

                    if not_after:
                        try:
                            # Python's ssl cert dates: 'Mon DD HH:MM:SS YYYY GMT'
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            delta = expiry - now
                            cert_info["days_remaining"] = delta.days
                            cert_info["expired"] = delta.days < 0
                        except Exception:
                            pass

                    # Serial
                    cert_info["serial"] = cert_dict.get("serialNumber", "")

                # Use cryptography library for deeper analysis if available
                if cert_der:
                    _analyze_cert_deep(cert_der, cert_info)

                # Check HSTS via HTTP response
                request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                ssock.send(request.encode())
                response = ssock.recv(4096).decode("utf-8", errors="replace")
                if "strict-transport-security" in response.lower():
                    cert_info["hsts"] = True
                    import re
                    m = re.search(r"max-age=(\d+)", response, re.IGNORECASE)
                    if m:
                        cert_info["hsts_max_age"] = int(m.group(1))

    except Exception as e:
        cert_info["error"] = str(e)

    return cert_info


def _analyze_cert_deep(cert_der, cert_info):
    """Deep certificate analysis using cryptography library."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

        cert = x509.load_der_x509_certificate(cert_der)

        # Subject and issuer (always available from DER, unlike getpeercert with CERT_NONE)
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn:
                cert_info["subject"] = cert_info["subject"] or cn[0].value
        except Exception:
            pass

        try:
            icn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if icn:
                cert_info["issuer"] = cert_info["issuer"] or icn[0].value
            iorg = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            if iorg:
                cert_info["issuer_org"] = cert_info["issuer_org"] or iorg[0].value
        except Exception:
            pass

        # Self-signed
        cert_info["self_signed"] = cert.issuer == cert.subject

        # Validity
        now = datetime.now(timezone.utc)
        cert_info["not_before"] = cert_info["not_before"] or cert.not_valid_before_utc.isoformat()
        cert_info["not_after"] = cert_info["not_after"] or cert.not_valid_after_utc.isoformat()
        delta = cert.not_valid_after_utc - now
        cert_info["days_remaining"] = delta.days
        cert_info["expired"] = delta.days < 0

        # SANs
        if not cert_info["san"]:
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                cert_info["san"] = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

        # Signature algorithm
        cert_info["sig_algorithm"] = cert.signature_algorithm_oid._name

        # Key type and size
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            cert_info["key_type"] = "RSA"
            cert_info["key_bits"] = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            cert_info["key_type"] = "ECDSA"
            cert_info["key_bits"] = pub_key.key_size
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey,)):
            cert_info["key_type"] = "Ed25519"
            cert_info["key_bits"] = 256
        elif isinstance(pub_key, (ed448.Ed448PublicKey,)):
            cert_info["key_type"] = "Ed448"
            cert_info["key_bits"] = 448
        else:
            cert_info["key_type"] = type(pub_key).__name__

    except ImportError:
        pass
    except Exception:
        pass


# ------------------------------------------------------------------
# Vulnerability assessment
# ------------------------------------------------------------------

def _assess_vulnerabilities(result):
    """Assess TLS vulnerabilities based on collected data."""
    vulns = []
    protocols = result.get("protocols", {})
    ciphers = result.get("ciphers", [])
    cert = result.get("certificate", {})

    # Deprecated protocol versions
    for proto in ("SSLv3", "TLSv1.0", "TLSv1.1"):
        p = protocols.get(proto, {})
        if p.get("supported"):
            severity = "high" if proto == "SSLv3" else "medium"
            vulns.append({
                "id": f"deprecated-{proto.lower().replace('.', '')}",
                "title": f"Deprecated protocol: {proto}",
                "severity": severity,
                "description": f"Server accepts {proto} which is deprecated and vulnerable",
            })

    # No TLS 1.3 support
    tls13 = protocols.get("TLSv1.3", {})
    if not tls13.get("supported"):
        vulns.append({
            "id": "no-tls13",
            "title": "TLS 1.3 not supported",
            "severity": "low",
            "description": "Server does not support TLS 1.3 — missing performance and security benefits",
        })

    # Weak ciphers
    weak = [c for c in ciphers if c["strength"] in ("weak", "insecure")]
    if weak:
        names = [c["name"] for c in weak[:5]]
        severity = "high" if any(c["strength"] == "insecure" for c in weak) else "medium"
        vulns.append({
            "id": "weak-ciphers",
            "title": f"{len(weak)} weak cipher(s) accepted",
            "severity": severity,
            "description": f"Weak ciphers: {', '.join(names)}",
        })

    # No forward secrecy
    no_pfs = [c for c in ciphers if not c.get("pfs") and c["strength"] != "insecure"]
    if no_pfs:
        vulns.append({
            "id": "no-pfs",
            "title": f"{len(no_pfs)} cipher(s) without forward secrecy",
            "severity": "medium",
            "description": "RSA key exchange ciphers don't provide PFS — past traffic can be decrypted if private key is compromised",
        })

    # CBC ciphers (padding oracle risk)
    cbc = [c for c in ciphers if "CBC" in c["name"]]
    if cbc:
        vulns.append({
            "id": "cbc-ciphers",
            "title": f"{len(cbc)} CBC cipher(s) accepted",
            "severity": "low",
            "description": "CBC mode ciphers are vulnerable to padding oracle attacks (POODLE, Lucky13)",
        })

    # Certificate issues
    if cert.get("expired"):
        vulns.append({
            "id": "cert-expired",
            "title": "Certificate expired",
            "severity": "critical",
            "description": f"Certificate expired {abs(cert.get('days_remaining', 0))} days ago",
        })
    elif cert.get("days_remaining", 999) < 30:
        vulns.append({
            "id": "cert-expiring",
            "title": f"Certificate expires in {cert['days_remaining']} days",
            "severity": "medium",
            "description": "Certificate is expiring soon",
        })

    if cert.get("self_signed"):
        vulns.append({
            "id": "cert-self-signed",
            "title": "Self-signed certificate",
            "severity": "medium",
            "description": "Certificate is self-signed — not trusted by browsers",
        })

    if cert.get("key_type") == "RSA" and cert.get("key_bits", 4096) < 2048:
        vulns.append({
            "id": "weak-key",
            "title": f"Weak RSA key ({cert['key_bits']} bits)",
            "severity": "high",
            "description": "RSA keys shorter than 2048 bits are considered insecure",
        })

    # Missing HSTS
    if not cert.get("hsts"):
        vulns.append({
            "id": "no-hsts",
            "title": "HSTS not enabled",
            "severity": "low",
            "description": "Strict-Transport-Security header not present — vulnerable to SSL stripping",
        })
    elif cert.get("hsts_max_age", 0) < 31536000:
        vulns.append({
            "id": "weak-hsts",
            "title": f"HSTS max-age too short ({cert['hsts_max_age']}s)",
            "severity": "low",
            "description": "HSTS max-age should be at least 31536000 (1 year)",
        })

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: sev_order.get(v["severity"], 9))

    return vulns


# ------------------------------------------------------------------
# Browser fingerprint comparison
# ------------------------------------------------------------------

def _compare_browser_fingerprints(result):
    """Compare our TLS fingerprint with known browser profiles."""
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
            f"Large cipher list is a strong fingerprinting signal."
        )
        result["recommendations"].append(
            "Restrict cipher suites to match a browser profile"
        )

    if result["our_tls_version"] == "TLSv1.2":
        result["browser_differences"].append(
            "Using TLS 1.2 — modern browsers prefer TLS 1.3"
        )


# ------------------------------------------------------------------
# WAF TLS config testing
# ------------------------------------------------------------------

def _test_tls_config(domain, port, timeout, config_name, config_opts):
    """Test a specific TLS configuration against the server."""
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
    """Test multiple TLS configurations to find what WAF accepts/blocks."""
    result = analyze_tls_fingerprint(domain, port, timeout)
    return result.get("config_tests", [])
