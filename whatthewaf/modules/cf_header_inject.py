"""
Cloudflare internal header injection module for WAF bypass testing.

Tests whether a target trusts Cloudflare-internal and common CDN/proxy
headers, which can be abused to spoof source IPs and bypass WAF rules.
"""

import json
import random
import string
from typing import Optional

import httpx

# ---------------------------------------------------------------------------
# Cloudflare IPv4 prefixes (public, used by CF edge nodes)
# ---------------------------------------------------------------------------
CF_IP_RANGES: list[str] = [
    "173.245.48.",
    "103.21.244.",
    "103.22.200.",
    "103.31.4.",
    "141.101.64.",
    "108.162.192.",
    "190.93.240.",
    "188.114.96.",
    "197.234.240.",
    "198.41.128.",
    "162.158.0.",
    "104.16.0.",
    "104.24.0.",
    "172.64.0.",
    "131.0.72.",
]

# IATA airport codes seen in real CF-RAY values
_AIRPORT_CODES: list[str] = [
    "NBO", "LHR", "JFK", "LAX", "SIN",
    "DXB", "FRA", "CDG", "AMS", "SYD",
]

# Countries Cloudflare reports via CF-IPCountry
_CF_COUNTRIES: list[str] = ["US", "GB", "DE", "FR", "SG", "AU", "JP"]

# Additional IP-spoof headers used by other CDNs / reverse proxies
EXTRA_SPOOF_HEADERS: dict[str, str] = {
    "Fastly-Client-IP": "",
    "X-Azure-ClientIP": "",
    "Akamai-Origin-Hop": "",
    "X-Cluster-Client-IP": "",
}


def _random_ip_from_cf_range() -> str:
    """Generate a random IP that falls within a Cloudflare prefix."""
    prefix = random.choice(CF_IP_RANGES)
    return prefix + str(random.randint(1, 254))


def _generate_ray_id() -> str:
    """Return a realistic CF-RAY value (16 hex chars + dash + airport code)."""
    hex_part = "".join(random.choices(string.hexdigits[:16], k=16))
    airport = random.choice(_AIRPORT_CODES)
    return f"{hex_part}-{airport}"


def generate_cf_headers(visitor_ip: Optional[str] = None) -> dict[str, str]:
    """Build a full set of Cloudflare-internal headers.

    Parameters
    ----------
    visitor_ip : str, optional
        IP address to embed in the headers.  When *None* a random IP
        from :data:`CF_IP_RANGES` is used.

    Returns
    -------
    dict[str, str]
        Header name -> value mapping ready to be merged into a request.
    """
    ip = visitor_ip or _random_ip_from_cf_range()
    return {
        "CF-Connecting-IP": ip,
        "X-Forwarded-For": ip,
        "X-Forwarded-Proto": "https",
        "CF-RAY": _generate_ray_id(),
        "CF-Visitor": json.dumps({"scheme": "https"}),
        "CF-IPCountry": random.choice(_CF_COUNTRIES),
        "X-Real-IP": ip,
        "True-Client-IP": ip,
    }


def _make_request(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
    proxy: str | None = None,
) -> dict:
    """Fire a GET request and return a simplified result dict."""
    transport_kwargs: dict = {}
    client_kwargs: dict = {
        "timeout": timeout,
        "follow_redirects": True,
        "verify": False,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    merged_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if headers:
        merged_headers.update(headers)

    try:
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(url, headers=merged_headers)
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_length": len(resp.content),
            "body_hash": hash(resp.content),
            "error": None,
        }
    except httpx.HTTPError as exc:
        return {
            "status_code": None,
            "headers": {},
            "body_length": 0,
            "body_hash": None,
            "error": str(exc),
        }


def _responses_differ(baseline: dict, test: dict) -> bool:
    """Heuristic check: did the response meaningfully change?"""
    if baseline.get("error") or test.get("error"):
        return baseline.get("error") != test.get("error")
    if baseline["status_code"] != test["status_code"]:
        return True
    # Allow small body-length variance (ads, tokens, etc.)
    length_delta = abs(baseline["body_length"] - test["body_length"])
    if length_delta > 256:
        return True
    if baseline["body_hash"] != test["body_hash"]:
        # Bodies differ but length is close -- flag only if status also shifted
        return baseline["status_code"] != test["status_code"]
    return False


def test_cf_header_trust(
    domain: str,
    timeout: int = 10,
    proxy: Optional[str] = None,
) -> dict:
    """Probe whether *domain* trusts injected CF / CDN headers.

    Parameters
    ----------
    domain : str
        Target domain or full URL.  If no scheme is present ``https://``
        is prepended automatically.
    timeout : int
        Per-request timeout in seconds.
    proxy : str, optional
        HTTP(S) proxy URL (e.g. ``http://127.0.0.1:8080``).

    Returns
    -------
    dict
        Keys:

        * **baseline** -- response without any spoofed headers.
        * **individual_results** -- ``{header_name: {response, differs}}``
          for each CF header tested in isolation.
        * **combined_result** -- response with all CF headers sent at once.
        * **findings** -- list of human-readable observations.
    """
    url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"

    findings: list[str] = []

    # 1. Baseline --------------------------------------------------------
    baseline = _make_request(url, timeout=timeout, proxy=proxy)
    if baseline["error"]:
        findings.append(f"Baseline request failed: {baseline['error']}")

    # 2. Individual CF header tests --------------------------------------
    cf_headers = generate_cf_headers()
    individual_results: dict[str, dict] = {}

    for header_name, header_value in cf_headers.items():
        resp = _make_request(
            url,
            headers={header_name: header_value},
            timeout=timeout,
            proxy=proxy,
        )
        differs = _responses_differ(baseline, resp)
        individual_results[header_name] = {
            "response": resp,
            "differs": differs,
        }
        if differs:
            findings.append(
                f"Response changed when injecting {header_name}: "
                f"status {baseline.get('status_code')} -> {resp.get('status_code')}, "
                f"body length {baseline.get('body_length')} -> {resp.get('body_length')}"
            )

    # 3. All CF headers combined -----------------------------------------
    combined_resp = _make_request(
        url,
        headers=cf_headers,
        timeout=timeout,
        proxy=proxy,
    )
    combined_differs = _responses_differ(baseline, combined_resp)
    combined_result = {"response": combined_resp, "differs": combined_differs}
    if combined_differs:
        findings.append(
            "Response changed with ALL CF headers combined -- "
            "target may trust Cloudflare internal headers."
        )

    # 4. Internal / localhost IPs ----------------------------------------
    internal_ips = ["127.0.0.1", "10.0.0.1"]
    for ip in internal_ips:
        internal_headers = generate_cf_headers(visitor_ip=ip)
        resp = _make_request(
            url,
            headers=internal_headers,
            timeout=timeout,
            proxy=proxy,
        )
        differs = _responses_differ(baseline, resp)
        label = f"internal_ip_{ip}"
        individual_results[label] = {
            "response": resp,
            "differs": differs,
        }
        if differs:
            findings.append(
                f"Response changed with internal IP {ip} in CF headers -- "
                "potential WAF bypass or SSRF vector."
            )

    # 5. Extra CDN spoof headers -----------------------------------------
    random_ip = _random_ip_from_cf_range()
    for header_name in EXTRA_SPOOF_HEADERS:
        resp = _make_request(
            url,
            headers={header_name: random_ip},
            timeout=timeout,
            proxy=proxy,
        )
        differs = _responses_differ(baseline, resp)
        individual_results[header_name] = {
            "response": resp,
            "differs": differs,
        }
        if differs:
            findings.append(
                f"Response changed when injecting {header_name} (non-CF CDN header)."
            )

    if not findings:
        findings.append("No observable response changes from header injection.")

    return {
        "baseline": baseline,
        "individual_results": individual_results,
        "combined_result": combined_result,
        "findings": findings,
    }
