"""WAF Vulnerability Scanner -- treats the WAF itself as the attack surface.

Scans across 10 layers to discover weaknesses, misconfigurations, and bypass
opportunities in Web Application Firewalls.

Layers:
 1. Network        - virtual-host bypass, sensitive path probing, Host header manipulation
 2. RuleEngine     - WAF rule gap detection with SQLi/XSS/RCE/LFI payloads
 3. RateLimit      - rate-limiting threshold detection and tracking mechanism analysis
 4. Evasion        - encoding-based rule bypass (10 variants per payload)
 5. Behavioural    - timing analysis, tarpit detection, JS challenge detection
 6. Header         - header injection via forwarded-for / client-IP headers
 7. TLS            - TLS version probing, SNI bypass, certificate info extraction
 8. MethodVerb     - HTTP method/verb acceptance testing
 9. Session        - cookie manipulation, session tracking detection
10. Misconfig      - WAF info leakage, version exposure, rule enumeration
"""

from __future__ import annotations

import base64
import hashlib
import html
import logging
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Severity ordering (for sorting)
# ---------------------------------------------------------------------------
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# ---------------------------------------------------------------------------
# VulnFinding dataclass
# ---------------------------------------------------------------------------

@dataclass
class VulnFinding:
    """A single vulnerability finding produced by a scan layer."""

    category: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    evidence: str = ""
    confidence: float = 0.5
    verified: bool = False
    layer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Embedded payloads
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "UNION SELECT",
    "' AND '1'='1",
    '" OR ""="',
    "1; DROP TABLE--",
    "WAITFOR DELAY '0:0:5'",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]

RCE_PAYLOADS = [
    "; ls",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "${7*7}",
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "....//....//etc/passwd",
    "..%252f..%252f",
    "/proc/self/environ",
]

ALL_PAYLOADS: List[Tuple[str, str]] = (
    [("sqli", p) for p in SQLI_PAYLOADS]
    + [("xss", p) for p in XSS_PAYLOADS]
    + [("rce", p) for p in RCE_PAYLOADS]
    + [("lfi", p) for p in LFI_PAYLOADS]
)

SENSITIVE_PATHS = [
    "/admin",
    "/console",
    "/debug",
    "/server-status",
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/actuator",
]

HTTP_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
    "HEAD", "TRACE", "PROPFIND", "MKCOL", "COPY", "MOVE",
    "LOCK", "UNLOCK",
]

HEADER_INJECTION_SETS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Real-IP": "10.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Originating-IP": "192.168.1.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "10.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "10.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "10.0.0.1"},
]

WAF_HEADER_FINGERPRINTS = [
    "x-cdn",
    "x-cache",
    "x-waf",
    "x-sucuri",
    "x-cloudflare",
    "cf-ray",
    "cf-cache-status",
    "x-akamai",
    "x-edgeconnect",
    "x-amz-cf",
    "x-firewall",
    "x-protected-by",
    "x-powered-by",
    "server",
    "x-request-id",
    "x-trace-id",
    "x-mod-security",
    "x-denied-reason",
    "x-block-reason",
]

WAF_ERROR_SIGNATURES = [
    "access denied",
    "forbidden",
    "blocked",
    "request rejected",
    "not acceptable",
    "web application firewall",
    "waf",
    "mod_security",
    "modsecurity",
    "cloudflare",
    "sucuri",
    "imperva",
    "incapsula",
    "akamai",
    "f5 big-ip",
    "barracuda",
    "fortiweb",
    "citrix",
    "radware",
    "aws waf",
    "azure front door",
]


# ---------------------------------------------------------------------------
# Encoding helpers for the Evasion layer
# ---------------------------------------------------------------------------

def _url_encode(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def _double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def _unicode_encode(payload: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in payload)


def _hex_encode(payload: str) -> str:
    return "".join(f"\\x{ord(c):02x}" if not c.isalnum() else c for c in payload)


def _html_entity_encode(payload: str) -> str:
    return "".join(f"&#{ord(c)};" if not c.isalnum() else c for c in payload)


def _base64_encode(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()


def _mixed_case(payload: str) -> str:
    result = []
    for i, c in enumerate(payload):
        result.append(c.upper() if i % 2 == 0 else c.lower())
    return "".join(result)


def _null_byte_insert(payload: str) -> str:
    return "%00".join(payload)


def _sql_comment_inject(payload: str) -> str:
    """Insert SQL inline comments between words."""
    return re.sub(r"\s+", "/**/", payload)


def _whitespace_variant(payload: str) -> str:
    """Replace spaces with tabs and other whitespace."""
    return payload.replace(" ", "\t").replace("\t", "%09")


EVASION_ENCODERS = [
    ("url_encode", _url_encode),
    ("double_url_encode", _double_url_encode),
    ("unicode", _unicode_encode),
    ("hex", _hex_encode),
    ("html_entity", _html_entity_encode),
    ("base64", _base64_encode),
    ("mixed_case", _mixed_case),
    ("null_byte", _null_byte_insert),
    ("comment_inject", _sql_comment_inject),
    ("whitespace_variant", _whitespace_variant),
]


# ---------------------------------------------------------------------------
# Response classification
# ---------------------------------------------------------------------------

def _classify_response(response: httpx.Response) -> str:
    """Classify a WAF response into PASSED / BLOCKED / CHALLENGE / ERROR."""
    status = response.status_code

    if status in (403, 406, 503):
        return "BLOCKED"

    body_lower = response.text.lower() if response.text else ""

    # Detect JS / CAPTCHA challenge pages
    challenge_indicators = [
        "captcha",
        "challenge",
        "cf-browser-verification",
        "jschl-answer",
        "just a moment",
        "checking your browser",
        "recaptcha",
        "hcaptcha",
        "ddos protection",
    ]
    for indicator in challenge_indicators:
        if indicator in body_lower:
            return "CHALLENGE"

    if 200 <= status < 400:
        return "PASSED"

    return "ERROR"


# ---------------------------------------------------------------------------
# WAFVulnScanner
# ---------------------------------------------------------------------------

class WAFVulnScanner:
    """Comprehensive WAF vulnerability scanner -- 10-layer analysis."""

    LAYER_NAMES = [
        "network",
        "ruleengine",
        "ratelimit",
        "evasion",
        "behavioural",
        "header",
        "tls",
        "methodverb",
        "session",
        "misconfig",
    ]

    def __init__(
        self,
        domain: str,
        timeout: int = 10,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        self.domain = domain.rstrip("/")
        if not self.domain.startswith(("http://", "https://")):
            self.domain = f"https://{self.domain}"
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent or DEFAULT_UA
        self._findings: List[VulnFinding] = []
        self._baseline_hash: Optional[str] = None
        self._baseline_status: Optional[int] = None
        self._baseline_headers: Optional[httpx.Headers] = None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _client(self, **kwargs: Any) -> httpx.Client:
        """Build a configured httpx.Client."""
        transport_kwargs: Dict[str, Any] = {}
        client_kwargs: Dict[str, Any] = {
            "timeout": self.timeout,
            "follow_redirects": True,
            "verify": False,
            "headers": {"User-Agent": self.user_agent},
            **kwargs,
        }
        if self.proxy:
            client_kwargs["proxy"] = self.proxy
        return httpx.Client(**client_kwargs)

    def _get(
        self,
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Optional[httpx.Response]:
        url = f"{self.domain}{path}"
        try:
            with self._client() as client:
                return client.get(url, headers=headers or {}, params=params or {})
        except Exception as exc:
            logger.debug("GET %s failed: %s", url, exc)
            return None

    def _post(
        self,
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
    ) -> Optional[httpx.Response]:
        url = f"{self.domain}{path}"
        try:
            with self._client() as client:
                return client.post(url, headers=headers or {}, data=data or {})
        except Exception as exc:
            logger.debug("POST %s failed: %s", url, exc)
            return None

    def _request(
        self,
        method: str,
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[httpx.Response]:
        url = f"{self.domain}{path}"
        try:
            with self._client() as client:
                return client.request(method, url, headers=headers or {})
        except Exception as exc:
            logger.debug("%s %s failed: %s", method, url, exc)
            return None

    def _rapid_get(
        self,
        count: int,
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
    ) -> List[httpx.Response]:
        """Send *count* GET requests as fast as possible, return all responses."""
        url = f"{self.domain}{path}"
        results: List[httpx.Response] = []
        try:
            with self._client() as client:
                for _ in range(count):
                    try:
                        r = client.get(url, headers=headers or {})
                        results.append(r)
                    except Exception:
                        pass
        except Exception:
            pass
        return results

    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------

    def _capture_baseline(self) -> None:
        """Fetch baseline response for false-positive verification."""
        resp = self._get("/")
        if resp is not None:
            self._baseline_status = resp.status_code
            self._baseline_hash = hashlib.md5(resp.content).hexdigest()
            self._baseline_headers = resp.headers
        else:
            self._baseline_status = None
            self._baseline_hash = None
            self._baseline_headers = None

    def _verify_finding(self, make_request: Any) -> bool:
        """Re-send the same request to verify the finding is consistent (not a fluke).

        *make_request* is a callable that returns an httpx.Response or None.
        Returns True if the second response matches the first (verified).
        """
        try:
            r1 = make_request()
            r2 = make_request()
            if r1 is None or r2 is None:
                return False
            return _classify_response(r1) == _classify_response(r2)
        except Exception:
            return False

    def _add_finding(self, finding: VulnFinding) -> None:
        self._findings.append(finding)

    # ------------------------------------------------------------------
    # Layer 1: Network
    # ------------------------------------------------------------------

    def _scan_network(self) -> List[VulnFinding]:
        """Layer 1 -- network-level probing."""
        findings: List[VulnFinding] = []
        layer = "network"

        # --- Sensitive path probing ---
        for path in SENSITIVE_PATHS:
            resp = self._get(path)
            if resp is None:
                continue
            classification = _classify_response(resp)
            if classification == "PASSED":
                sev = "high" if path in ("/.env", "/.git/config") else "medium"
                f = VulnFinding(
                    category="sensitive_path",
                    severity=sev,
                    title=f"Sensitive path accessible: {path}",
                    description=(
                        f"The path {path} returned HTTP {resp.status_code} and was "
                        f"not blocked by the WAF. This may expose sensitive data."
                    ),
                    evidence=f"HTTP {resp.status_code} - {resp.text[:200]}",
                    confidence=0.8,
                    verified=self._verify_finding(lambda p=path: self._get(p)),
                    layer=layer,
                )
                findings.append(f)

        # --- Virtual host bypass ---
        parsed = urllib.parse.urlparse(self.domain)
        hostname = parsed.hostname or ""
        vhost_targets = [
            "127.0.0.1",
            "localhost",
            "internal",
            "backend",
            f"admin.{hostname}",
            f"dev.{hostname}",
            f"staging.{hostname}",
        ]
        for vhost in vhost_targets:
            resp = self._get("/", headers={"Host": vhost})
            if resp is None:
                continue
            classification = _classify_response(resp)
            if classification == "PASSED":
                # Compare against baseline
                if (
                    self._baseline_hash
                    and hashlib.md5(resp.content).hexdigest() != self._baseline_hash
                ):
                    f = VulnFinding(
                        category="vhost_bypass",
                        severity="high",
                        title=f"Virtual host bypass with Host: {vhost}",
                        description=(
                            f"Setting Host header to '{vhost}' produced a different "
                            f"response than the baseline, suggesting the WAF can be "
                            f"bypassed via virtual host manipulation."
                        ),
                        evidence=f"HTTP {resp.status_code} - different body hash",
                        confidence=0.7,
                        verified=self._verify_finding(
                            lambda v=vhost: self._get("/", headers={"Host": v})
                        ),
                        layer=layer,
                    )
                    findings.append(f)

        # --- Host header manipulation with IP ---
        try:
            ip = socket.gethostbyname(hostname)
            resp = self._get("/", headers={"Host": ip})
            if resp is not None and _classify_response(resp) == "PASSED":
                f = VulnFinding(
                    category="host_header_ip",
                    severity="medium",
                    title="WAF accepts IP address as Host header",
                    description=(
                        f"The WAF accepted a request with Host: {ip} (resolved IP). "
                        f"This may allow bypassing domain-based WAF rules."
                    ),
                    evidence=f"Host: {ip} -> HTTP {resp.status_code}",
                    confidence=0.6,
                    verified=self._verify_finding(
                        lambda: self._get("/", headers={"Host": ip})
                    ),
                    layer=layer,
                )
                findings.append(f)
        except socket.gaierror:
            logger.debug("Could not resolve %s", hostname)

        return findings

    # ------------------------------------------------------------------
    # Layer 2: RuleEngine
    # ------------------------------------------------------------------

    def _scan_ruleengine(self) -> List[VulnFinding]:
        """Layer 2 -- test WAF rule gaps with attack payloads."""
        findings: List[VulnFinding] = []
        layer = "ruleengine"

        for category, payload in ALL_PAYLOADS:
            results: Dict[str, str] = {}

            # -- URL parameter --
            resp_param = self._get("/", params={"q": payload})
            if resp_param is not None:
                results["url_param"] = _classify_response(resp_param)

            # -- Header injection --
            resp_header = self._get("/", headers={"X-Custom": payload})
            if resp_header is not None:
                results["header"] = _classify_response(resp_header)

            # -- POST body --
            resp_post = self._post("/", data={"q": payload})
            if resp_post is not None:
                results["post_body"] = _classify_response(resp_post)

            for vector, classification in results.items():
                if classification == "PASSED":
                    sev_map = {
                        "sqli": "critical",
                        "xss": "high",
                        "rce": "critical",
                        "lfi": "high",
                    }
                    sev = sev_map.get(category, "medium")
                    f = VulnFinding(
                        category=f"rule_gap_{category}",
                        severity=sev,
                        title=f"WAF did not block {category.upper()} payload via {vector}",
                        description=(
                            f"The {category.upper()} payload '{payload}' was sent "
                            f"via {vector} and received a PASSED classification. "
                            f"The WAF failed to detect or block this attack vector."
                        ),
                        evidence=f"Payload: {payload} | Vector: {vector} | Result: {classification}",
                        confidence=0.85,
                        verified=False,
                        layer=layer,
                    )
                    # Verify by replaying
                    if vector == "url_param":
                        f.verified = self._verify_finding(
                            lambda p=payload: self._get("/", params={"q": p})
                        )
                    elif vector == "header":
                        f.verified = self._verify_finding(
                            lambda p=payload: self._get("/", headers={"X-Custom": p})
                        )
                    elif vector == "post_body":
                        f.verified = self._verify_finding(
                            lambda p=payload: self._post("/", data={"q": p})
                        )
                    findings.append(f)
                elif classification == "CHALLENGE":
                    f = VulnFinding(
                        category=f"challenge_{category}",
                        severity="info",
                        title=f"WAF issued challenge for {category.upper()} via {vector}",
                        description=(
                            f"The WAF responded with a challenge page (CAPTCHA/JS) "
                            f"for payload '{payload}' via {vector}."
                        ),
                        evidence=f"Payload: {payload} | Vector: {vector}",
                        confidence=0.9,
                        verified=True,
                        layer=layer,
                    )
                    findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Layer 3: RateLimit
    # ------------------------------------------------------------------

    def _scan_ratelimit(self) -> List[VulnFinding]:
        """Layer 3 -- rate-limiting threshold detection."""
        findings: List[VulnFinding] = []
        layer = "ratelimit"

        thresholds = [10, 20, 50]
        rate_limit_triggered = False
        trigger_point: Optional[int] = None

        for count in thresholds:
            responses = self._rapid_get(count)
            blocked = sum(
                1
                for r in responses
                if r.status_code in (429, 403, 503) or _classify_response(r) == "BLOCKED"
            )
            if blocked > 0 and not rate_limit_triggered:
                rate_limit_triggered = True
                trigger_point = count
                f = VulnFinding(
                    category="rate_limit",
                    severity="info",
                    title=f"Rate limiting detected at ~{count} requests",
                    description=(
                        f"After sending {count} rapid requests, {blocked} were "
                        f"blocked/rate-limited. The WAF enforces rate limiting."
                    ),
                    evidence=f"Requests: {count}, Blocked: {blocked}",
                    confidence=0.9,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)
                break

        if not rate_limit_triggered:
            f = VulnFinding(
                category="no_rate_limit",
                severity="medium",
                title="No rate limiting detected up to 50 rapid requests",
                description=(
                    "The WAF did not enforce rate limiting even after 50 rapid "
                    "requests. This may allow brute-force or DoS attacks."
                ),
                evidence=f"50 rapid requests sent, none blocked",
                confidence=0.7,
                verified=self._verify_finding(
                    lambda: self._rapid_get(50) and self._get("/")
                ),
                layer=layer,
            )
            findings.append(f)

        # --- Tracking mechanism analysis ---
        # Test with different User-Agent
        alt_ua = "RateLimitTestBot/1.0"
        responses_alt_ua = self._rapid_get(
            20, headers={"User-Agent": alt_ua}
        )
        blocked_alt_ua = sum(
            1
            for r in responses_alt_ua
            if r.status_code in (429, 403, 503)
        )

        # If original was rate-limited but different UA is not, tracking is UA-based
        if rate_limit_triggered and trigger_point and trigger_point <= 20:
            if blocked_alt_ua == 0:
                f = VulnFinding(
                    category="rate_limit_ua_tracking",
                    severity="medium",
                    title="Rate limiting may use User-Agent for tracking",
                    description=(
                        "Changing the User-Agent string bypassed rate limiting, "
                        "suggesting the WAF tracks rate limits by User-Agent "
                        "rather than IP alone."
                    ),
                    evidence=f"Original UA blocked, alt UA ({alt_ua}) not blocked",
                    confidence=0.6,
                    verified=False,
                    layer=layer,
                )
                findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Layer 4: Evasion
    # ------------------------------------------------------------------

    def _scan_evasion(self) -> List[VulnFinding]:
        """Layer 4 -- encoding-based evasion of WAF rules."""
        findings: List[VulnFinding] = []
        layer = "evasion"

        for category, payload in ALL_PAYLOADS:
            # First check if the raw payload IS blocked
            raw_resp = self._get("/", params={"q": payload})
            if raw_resp is None:
                continue
            raw_class = _classify_response(raw_resp)
            if raw_class != "BLOCKED":
                # If the raw payload is not blocked, evasion testing is moot
                continue

            # Raw payload is blocked -- try each encoding
            for enc_name, encoder in EVASION_ENCODERS:
                try:
                    encoded = encoder(payload)
                except Exception:
                    continue

                # Try in URL param
                resp = self._get("/", params={"q": encoded})
                if resp is None:
                    continue
                classification = _classify_response(resp)

                if classification == "PASSED":
                    f = VulnFinding(
                        category=f"evasion_{enc_name}",
                        severity="high",
                        title=(
                            f"WAF bypass via {enc_name} encoding "
                            f"({category.upper()} payload)"
                        ),
                        description=(
                            f"The {category.upper()} payload was blocked in raw form "
                            f"but passed when encoded with {enc_name}. "
                            f"Original: '{payload}' | Encoded: '{encoded[:100]}'"
                        ),
                        evidence=(
                            f"Raw: BLOCKED | {enc_name}: PASSED | "
                            f"Encoded payload: {encoded[:100]}"
                        ),
                        confidence=0.8,
                        verified=self._verify_finding(
                            lambda e=encoded: self._get("/", params={"q": e})
                        ),
                        layer=layer,
                    )
                    findings.append(f)

                # Also try in POST body
                resp_post = self._post("/", data={"q": encoded})
                if resp_post is None:
                    continue
                post_class = _classify_response(resp_post)
                if post_class == "PASSED":
                    f = VulnFinding(
                        category=f"evasion_{enc_name}_post",
                        severity="high",
                        title=(
                            f"WAF bypass via {enc_name} encoding in POST body "
                            f"({category.upper()})"
                        ),
                        description=(
                            f"The {category.upper()} payload bypassed the WAF when "
                            f"sent as {enc_name}-encoded POST body data."
                        ),
                        evidence=(
                            f"Raw: BLOCKED | POST {enc_name}: PASSED | "
                            f"Encoded: {encoded[:100]}"
                        ),
                        confidence=0.8,
                        verified=self._verify_finding(
                            lambda e=encoded: self._post("/", data={"q": e})
                        ),
                        layer=layer,
                    )
                    findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Layer 5: Behavioural
    # ------------------------------------------------------------------

    def _scan_behavioural(self) -> List[VulnFinding]:
        """Layer 5 -- timing analysis, tarpit detection, progressive back-off."""
        findings: List[VulnFinding] = []
        layer = "behavioural"

        # --- Baseline timing ---
        timings: List[float] = []
        for _ in range(5):
            start = time.monotonic()
            resp = self._get("/")
            elapsed = time.monotonic() - start
            if resp is not None:
                timings.append(elapsed)

        if not timings:
            return findings

        avg_time = sum(timings) / len(timings)
        max_time = max(timings)

        # --- Tarpit detection: send a malicious payload and check for delays ---
        tarpit_timings: List[float] = []
        for payload in SQLI_PAYLOADS[:3]:
            start = time.monotonic()
            resp = self._get("/", params={"q": payload})
            elapsed = time.monotonic() - start
            if resp is not None:
                tarpit_timings.append(elapsed)

        if tarpit_timings:
            avg_tarpit = sum(tarpit_timings) / len(tarpit_timings)
            if avg_tarpit > avg_time * 3 and avg_tarpit > 2.0:
                f = VulnFinding(
                    category="tarpit",
                    severity="info",
                    title="Tarpit behaviour detected",
                    description=(
                        f"Malicious payloads caused significantly slower responses "
                        f"(avg {avg_tarpit:.2f}s vs baseline {avg_time:.2f}s). "
                        f"The WAF may be using tarpit/slowdown as a defence."
                    ),
                    evidence=(
                        f"Baseline avg: {avg_time:.2f}s | "
                        f"Payload avg: {avg_tarpit:.2f}s"
                    ),
                    confidence=0.7,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

        # --- JS challenge detection ---
        resp = self._get("/")
        if resp is not None:
            body_lower = resp.text.lower()
            if any(
                ind in body_lower
                for ind in [
                    "challenge",
                    "jschl-answer",
                    "cf-browser-verification",
                    "just a moment",
                ]
            ):
                f = VulnFinding(
                    category="js_challenge",
                    severity="info",
                    title="JavaScript challenge page detected",
                    description=(
                        "The WAF serves a JavaScript challenge page that "
                        "requires browser execution before allowing access."
                    ),
                    evidence=f"Indicators found in response body",
                    confidence=0.9,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

        # --- Progressive back-off detection ---
        progressive_timings: List[float] = []
        for i in range(10):
            start = time.monotonic()
            resp = self._get("/")
            elapsed = time.monotonic() - start
            if resp is not None:
                progressive_timings.append(elapsed)

        if len(progressive_timings) >= 5:
            first_half = progressive_timings[: len(progressive_timings) // 2]
            second_half = progressive_timings[len(progressive_timings) // 2 :]
            avg_first = sum(first_half) / len(first_half)
            avg_second = sum(second_half) / len(second_half)
            if avg_second > avg_first * 2 and avg_second > 1.0:
                f = VulnFinding(
                    category="progressive_backoff",
                    severity="info",
                    title="Progressive back-off detected",
                    description=(
                        f"Response times increased progressively during rapid "
                        f"requests (first half avg: {avg_first:.2f}s, second half "
                        f"avg: {avg_second:.2f}s). The WAF may implement "
                        f"progressive rate limiting."
                    ),
                    evidence=(
                        f"First half avg: {avg_first:.2f}s | "
                        f"Second half avg: {avg_second:.2f}s"
                    ),
                    confidence=0.65,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Layer 6: Header
    # ------------------------------------------------------------------

    def _scan_header(self) -> List[VulnFinding]:
        """Layer 6 -- header injection with forwarded-for / client-IP headers."""
        findings: List[VulnFinding] = []
        layer = "header"

        for header_set in HEADER_INJECTION_SETS:
            resp = self._get("/", headers=header_set)
            if resp is None:
                continue

            header_name = list(header_set.keys())[0]
            header_val = list(header_set.values())[0]

            # Check if we got a different response from baseline
            if self._baseline_hash:
                resp_hash = hashlib.md5(resp.content).hexdigest()
                if resp_hash != self._baseline_hash:
                    f = VulnFinding(
                        category="header_injection",
                        severity="medium",
                        title=f"Different response with {header_name}: {header_val}",
                        description=(
                            f"Setting {header_name}: {header_val} produced a "
                            f"different response than the baseline. This may "
                            f"indicate the WAF trusts this header for IP-based "
                            f"decisions."
                        ),
                        evidence=(
                            f"Header: {header_name}: {header_val} | "
                            f"Status: {resp.status_code}"
                        ),
                        confidence=0.6,
                        verified=self._verify_finding(
                            lambda h=header_set: self._get("/", headers=h)
                        ),
                        layer=layer,
                    )
                    findings.append(f)

            # Check if a previously blocked payload now passes with spoofed IP
            test_payload = "' OR 1=1--"
            resp_blocked = self._get("/", params={"q": test_payload})
            if resp_blocked is not None and _classify_response(resp_blocked) == "BLOCKED":
                resp_with_header = self._get(
                    "/",
                    params={"q": test_payload},
                    headers=header_set,
                )
                if (
                    resp_with_header is not None
                    and _classify_response(resp_with_header) == "PASSED"
                ):
                    f = VulnFinding(
                        category="header_bypass",
                        severity="critical",
                        title=(
                            f"WAF bypass via {header_name} header spoofing"
                        ),
                        description=(
                            f"A blocked SQLi payload passed through when "
                            f"{header_name} was set to {header_val}. The WAF "
                            f"may whitelist requests based on trusted headers."
                        ),
                        evidence=(
                            f"Without header: BLOCKED | "
                            f"With {header_name}: {header_val}: PASSED"
                        ),
                        confidence=0.9,
                        verified=self._verify_finding(
                            lambda h=header_set: self._get(
                                "/", params={"q": test_payload}, headers=h
                            )
                        ),
                        layer=layer,
                    )
                    findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Layer 7: TLS
    # ------------------------------------------------------------------

    def _scan_tls(self) -> List[VulnFinding]:
        """Layer 7 -- TLS version probing, SNI bypass, certificate info."""
        findings: List[VulnFinding] = []
        layer = "tls"

        parsed = urllib.parse.urlparse(self.domain)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if parsed.scheme != "https":
            f = VulnFinding(
                category="no_tls",
                severity="info",
                title="Target is not using HTTPS",
                description="The target URL uses HTTP, skipping TLS analysis.",
                evidence=f"Scheme: {parsed.scheme}",
                confidence=1.0,
                verified=True,
                layer=layer,
            )
            findings.append(f)
            return findings

        # --- TLS version testing ---
        tls_versions = {
            "TLSv1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
        }
        accepted_versions: List[str] = []
        for version_name, version_enum in tls_versions.items():
            if version_enum is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version_enum
                ctx.maximum_version = version_enum
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        accepted_versions.append(version_name)
            except Exception:
                pass

        for ver in accepted_versions:
            if ver in ("TLSv1.0", "TLSv1.1"):
                f = VulnFinding(
                    category="weak_tls",
                    severity="medium",
                    title=f"WAF accepts deprecated {ver}",
                    description=(
                        f"The WAF/server accepts {ver} connections, which are "
                        f"considered insecure and deprecated."
                    ),
                    evidence=f"Accepted TLS versions: {', '.join(accepted_versions)}",
                    confidence=0.95,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

        if not accepted_versions:
            f = VulnFinding(
                category="tls_error",
                severity="info",
                title="Could not establish any TLS connection",
                description="Failed to connect using any TLS version.",
                evidence="All TLS version attempts failed",
                confidence=0.5,
                verified=True,
                layer=layer,
            )
            findings.append(f)

        # --- SNI bypass testing ---
        sni_tests = [
            ("wrong_sni", f"wrong.{hostname}"),
            ("empty_sni", ""),
            ("ip_sni", None),  # will use IP
        ]

        try:
            target_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            target_ip = None

        for sni_label, sni_value in sni_tests:
            if sni_label == "ip_sni":
                sni_value = target_ip or "0.0.0.0"
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection(
                    (hostname, port), timeout=self.timeout
                ) as sock:
                    sni_kwarg = (
                        {"server_hostname": sni_value}
                        if sni_value
                        else {"server_hostname": None}
                    )
                    with ctx.wrap_socket(sock, **sni_kwarg) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        f = VulnFinding(
                            category="sni_bypass",
                            severity="low",
                            title=f"TLS connection accepted with {sni_label} SNI",
                            description=(
                                f"The server accepted a TLS connection with "
                                f"SNI={sni_value!r}. This may allow bypassing "
                                f"SNI-based WAF routing."
                            ),
                            evidence=f"SNI: {sni_value!r} -> connection established",
                            confidence=0.5,
                            verified=True,
                            layer=layer,
                        )
                        findings.append(f)
            except Exception:
                pass

        # --- Certificate info extraction ---
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert(binary_form=False)
                    if cert_dict:
                        issuer = dict(
                            x[0]
                            for x in cert_dict.get("issuer", ())
                            if x
                        )
                        subject = dict(
                            x[0]
                            for x in cert_dict.get("subject", ())
                            if x
                        )
                        san = cert_dict.get("subjectAltName", ())
                        san_values = [v for _, v in san]
                        f = VulnFinding(
                            category="cert_info",
                            severity="info",
                            title="TLS certificate information",
                            description=(
                                f"Issuer: {issuer.get('organizationName', 'N/A')}\n"
                                f"Subject CN: {subject.get('commonName', 'N/A')}\n"
                                f"SANs: {', '.join(san_values[:10])}"
                            ),
                            evidence=f"Issuer: {issuer}, Subject: {subject}",
                            confidence=1.0,
                            verified=True,
                            layer=layer,
                        )
                        findings.append(f)
        except Exception as exc:
            logger.debug("Certificate extraction failed: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Layer 8: MethodVerb
    # ------------------------------------------------------------------

    def _scan_methodverb(self) -> List[VulnFinding]:
        """Layer 8 -- HTTP method/verb acceptance testing."""
        findings: List[VulnFinding] = []
        layer = "methodverb"

        accepted_methods: List[str] = []
        blocked_methods: List[str] = []
        errored_methods: List[str] = []

        for method in HTTP_METHODS:
            resp = self._request(method)
            if resp is None:
                errored_methods.append(method)
                continue

            if resp.status_code in (405, 501):
                blocked_methods.append(method)
            elif resp.status_code < 400:
                accepted_methods.append(method)
            elif _classify_response(resp) == "BLOCKED":
                blocked_methods.append(method)
            else:
                errored_methods.append(method)

        # Dangerous methods that should be blocked
        dangerous = {"TRACE", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
        dangerous_accepted = [m for m in accepted_methods if m in dangerous]

        if dangerous_accepted:
            f = VulnFinding(
                category="dangerous_methods",
                severity="medium",
                title=f"WAF allows dangerous HTTP methods: {', '.join(dangerous_accepted)}",
                description=(
                    f"The following HTTP methods are accepted but are typically "
                    f"dangerous and should be blocked by the WAF: "
                    f"{', '.join(dangerous_accepted)}"
                ),
                evidence=f"Accepted: {accepted_methods} | Blocked: {blocked_methods}",
                confidence=0.8,
                verified=True,
                layer=layer,
            )
            findings.append(f)

        # TRACE specifically is an XST vector
        if "TRACE" in accepted_methods:
            resp = self._request("TRACE")
            if resp is not None and "trace" in resp.text.lower():
                f = VulnFinding(
                    category="trace_enabled",
                    severity="high",
                    title="TRACE method enabled -- Cross-Site Tracing (XST) possible",
                    description=(
                        "The TRACE HTTP method is enabled and reflects request "
                        "data in the response. This enables Cross-Site Tracing "
                        "attacks and the WAF did not block it."
                    ),
                    evidence=f"TRACE response: {resp.text[:200]}",
                    confidence=0.9,
                    verified=self._verify_finding(
                        lambda: self._request("TRACE")
                    ),
                    layer=layer,
                )
                findings.append(f)

        # Summary finding
        f = VulnFinding(
            category="method_summary",
            severity="info",
            title="HTTP method acceptance summary",
            description=(
                f"Accepted: {', '.join(accepted_methods) or 'none'}\n"
                f"Blocked: {', '.join(blocked_methods) or 'none'}\n"
                f"Errored: {', '.join(errored_methods) or 'none'}"
            ),
            evidence=f"Total tested: {len(HTTP_METHODS)}",
            confidence=1.0,
            verified=True,
            layer=layer,
        )
        findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Layer 9: Session
    # ------------------------------------------------------------------

    def _scan_session(self) -> List[VulnFinding]:
        """Layer 9 -- cookie manipulation, session tracking detection."""
        findings: List[VulnFinding] = []
        layer = "session"

        # --- Capture cookies from initial request ---
        resp = self._get("/")
        if resp is None:
            return findings

        cookies = dict(resp.cookies)
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []

        if cookies:
            f = VulnFinding(
                category="session_cookies",
                severity="info",
                title=f"WAF sets {len(cookies)} cookie(s)",
                description=(
                    f"Cookies set by WAF/server: {', '.join(cookies.keys())}. "
                    f"These may be used for session tracking, challenge tokens, "
                    f"or bot detection."
                ),
                evidence=f"Cookies: {list(cookies.keys())}",
                confidence=1.0,
                verified=True,
                layer=layer,
            )
            findings.append(f)

        # --- Test without cookies (remove all cookies) ---
        resp_no_cookies = self._get("/")
        if resp_no_cookies is not None:
            class_with = _classify_response(resp)
            class_without = _classify_response(resp_no_cookies)
            if class_with != class_without:
                f = VulnFinding(
                    category="cookie_dependent",
                    severity="low",
                    title="WAF behaviour changes without cookies",
                    description=(
                        "Removing cookies changed the WAF response classification "
                        f"from {class_with} to {class_without}. The WAF may rely "
                        "on cookies for session state."
                    ),
                    evidence=f"With cookies: {class_with} | Without: {class_without}",
                    confidence=0.6,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

        # --- Test with modified session cookie ---
        if cookies:
            for cookie_name in cookies:
                modified_cookies = cookies.copy()
                modified_cookies[cookie_name] = "AAAA" + "B" * 32
                try:
                    with self._client(cookies=modified_cookies) as client:
                        url = f"{self.domain}/"
                        resp_mod = client.get(url)
                        mod_class = _classify_response(resp_mod)
                        if mod_class == "BLOCKED":
                            f = VulnFinding(
                                category="session_validation",
                                severity="info",
                                title=f"WAF validates cookie: {cookie_name}",
                                description=(
                                    f"Modifying the '{cookie_name}' cookie caused "
                                    f"the WAF to block the request, indicating "
                                    f"server-side session validation."
                                ),
                                evidence=(
                                    f"Modified '{cookie_name}' -> BLOCKED"
                                ),
                                confidence=0.7,
                                verified=True,
                                layer=layer,
                            )
                            findings.append(f)
                except Exception:
                    pass

            # --- Test with duplicate cookies ---
            for cookie_name, cookie_val in cookies.items():
                # Send request with the cookie duplicated via header
                dup_cookie = f"{cookie_name}={cookie_val}; {cookie_name}=tampered"
                resp_dup = self._get("/", headers={"Cookie": dup_cookie})
                if resp_dup is not None:
                    dup_class = _classify_response(resp_dup)
                    if dup_class == "PASSED":
                        f = VulnFinding(
                            category="duplicate_cookie",
                            severity="low",
                            title=f"WAF accepts duplicate cookie: {cookie_name}",
                            description=(
                                f"Sending duplicate values for '{cookie_name}' was "
                                f"not flagged by the WAF. Cookie parsing "
                                f"inconsistencies can lead to bypasses."
                            ),
                            evidence=f"Duplicate cookie header accepted",
                            confidence=0.5,
                            verified=True,
                            layer=layer,
                        )
                        findings.append(f)

        # --- Session tracking test ---
        # Send a payload, then the same payload without cookies
        test_payload = "<script>alert(1)</script>"
        resp1 = self._get("/", params={"q": test_payload})
        if resp1 is not None and _classify_response(resp1) == "BLOCKED":
            # Second request without cookies -- does WAF remember?
            resp2 = self._get("/")
            if resp2 is not None and _classify_response(resp2) == "BLOCKED":
                f = VulnFinding(
                    category="session_memory",
                    severity="info",
                    title="WAF may track sessions across requests",
                    description=(
                        "After sending a malicious payload, subsequent clean "
                        "requests were also blocked. The WAF may be tracking "
                        "sessions and scoring cumulative threat."
                    ),
                    evidence="Clean request blocked after malicious request",
                    confidence=0.5,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Layer 10: Misconfig
    # ------------------------------------------------------------------

    def _scan_misconfig(self) -> List[VulnFinding]:
        """Layer 10 -- WAF info leakage, version exposure, rule enumeration."""
        findings: List[VulnFinding] = []
        layer = "misconfig"

        # --- WAF info leakage in headers ---
        resp = self._get("/")
        if resp is None:
            return findings

        waf_headers_found: Dict[str, str] = {}
        for hdr_name in WAF_HEADER_FINGERPRINTS:
            val = resp.headers.get(hdr_name)
            if val:
                waf_headers_found[hdr_name] = val

        if waf_headers_found:
            # Check for version information
            version_pattern = re.compile(r"[\d]+\.[\d]+(?:\.[\d]+)?")
            versions_leaked: Dict[str, str] = {}
            for hdr, val in waf_headers_found.items():
                match = version_pattern.search(val)
                if match:
                    versions_leaked[hdr] = match.group()

            if versions_leaked:
                f = VulnFinding(
                    category="version_exposure",
                    severity="medium",
                    title="WAF version information leaked in headers",
                    description=(
                        f"The following headers expose version information: "
                        f"{versions_leaked}. This helps attackers target "
                        f"version-specific vulnerabilities."
                    ),
                    evidence=f"Version headers: {versions_leaked}",
                    confidence=0.85,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

            f = VulnFinding(
                category="waf_headers",
                severity="low",
                title=f"WAF fingerprint headers detected ({len(waf_headers_found)})",
                description=(
                    f"The following WAF-related headers were found: "
                    f"{', '.join(f'{k}: {v}' for k, v in waf_headers_found.items())}"
                ),
                evidence=f"Headers: {waf_headers_found}",
                confidence=0.9,
                verified=True,
                layer=layer,
            )
            findings.append(f)

        # --- WAF info leakage in error pages ---
        error_paths = [
            "/nonexistent-path-" + hashlib.md5(b"waftest").hexdigest()[:8],
            "/%00",
            "/index.php?id=<invalid>",
        ]
        for path in error_paths:
            resp_err = self._get(path)
            if resp_err is None:
                continue
            body_lower = resp_err.text.lower()
            for sig in WAF_ERROR_SIGNATURES:
                if sig in body_lower:
                    # Extract surrounding context
                    idx = body_lower.index(sig)
                    start = max(0, idx - 50)
                    end = min(len(body_lower), idx + len(sig) + 50)
                    context = resp_err.text[start:end].strip()
                    f = VulnFinding(
                        category="error_page_leak",
                        severity="low",
                        title=f"WAF signature in error page: '{sig}'",
                        description=(
                            f"The error page for {path} contains the WAF "
                            f"signature '{sig}'. This reveals WAF identity."
                        ),
                        evidence=f"Context: ...{context}...",
                        confidence=0.8,
                        verified=True,
                        layer=layer,
                    )
                    findings.append(f)
                    break  # One signature per path is enough

        # --- Server header analysis ---
        server_header = resp.headers.get("server", "")
        if server_header:
            f = VulnFinding(
                category="server_header",
                severity="info",
                title=f"Server header: {server_header}",
                description=(
                    f"The Server header is set to '{server_header}'. "
                    f"This may reveal the WAF or origin server identity."
                ),
                evidence=f"Server: {server_header}",
                confidence=1.0,
                verified=True,
                layer=layer,
            )
            findings.append(f)

        # --- Rule enumeration: send payloads and map which rules trigger ---
        rule_map: Dict[str, Dict[str, str]] = {}
        for category, payload in ALL_PAYLOADS[:8]:  # Test a subset
            resp_rule = self._get("/", params={"q": payload})
            if resp_rule is None:
                continue
            classification = _classify_response(resp_rule)
            if classification == "BLOCKED":
                # Look for rule ID or block reason in response
                block_headers = {}
                for hdr in [
                    "x-denied-reason",
                    "x-block-reason",
                    "x-waf-rule",
                    "x-mod-security",
                    "x-request-id",
                ]:
                    val = resp_rule.headers.get(hdr)
                    if val:
                        block_headers[hdr] = val

                body = resp_rule.text
                rule_id_match = re.search(
                    r"(?:rule[_\- ]?id|id)[:\s=]+([A-Z0-9\-]+)",
                    body,
                    re.IGNORECASE,
                )
                rule_id = rule_id_match.group(1) if rule_id_match else None

                rule_map[payload] = {
                    "classification": classification,
                    "status": str(resp_rule.status_code),
                    "rule_id": rule_id or "unknown",
                    "block_headers": str(block_headers),
                }

        if rule_map:
            # Check if different payloads give different rule IDs (enumerable rules)
            rule_ids = [
                info["rule_id"]
                for info in rule_map.values()
                if info["rule_id"] != "unknown"
            ]
            unique_ids = set(rule_ids)

            if unique_ids:
                f = VulnFinding(
                    category="rule_enumeration",
                    severity="medium",
                    title=f"WAF rules can be enumerated ({len(unique_ids)} unique rule IDs)",
                    description=(
                        f"The WAF exposes rule IDs in block responses, allowing "
                        f"attackers to enumerate and map specific rules. "
                        f"Rule IDs found: {', '.join(sorted(unique_ids))}"
                    ),
                    evidence=f"Rule mapping: {rule_map}",
                    confidence=0.8,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

            # Check if block page content varies (reveals rule categories)
            statuses = set(info["status"] for info in rule_map.values())
            if len(statuses) > 1:
                f = VulnFinding(
                    category="inconsistent_blocking",
                    severity="low",
                    title="WAF uses different status codes for different blocks",
                    description=(
                        f"Blocked requests received different HTTP status codes: "
                        f"{', '.join(sorted(statuses))}. This inconsistency "
                        f"reveals how the WAF categorizes different attack types."
                    ),
                    evidence=f"Status codes: {statuses}",
                    confidence=0.7,
                    verified=True,
                    layer=layer,
                )
                findings.append(f)

        # --- Check if WAF rules differ for different content types ---
        content_types = [
            "application/json",
            "application/xml",
            "text/plain",
            "multipart/form-data",
        ]
        test_payload = "' OR 1=1--"
        ct_results: Dict[str, str] = {}
        for ct in content_types:
            resp_ct = self._post(
                "/",
                headers={"Content-Type": ct},
                data={"q": test_payload},
            )
            if resp_ct is not None:
                ct_results[ct] = _classify_response(resp_ct)

        passed_cts = [ct for ct, cls in ct_results.items() if cls == "PASSED"]
        blocked_cts = [ct for ct, cls in ct_results.items() if cls == "BLOCKED"]

        if passed_cts and blocked_cts:
            f = VulnFinding(
                category="content_type_bypass",
                severity="high",
                title=(
                    f"WAF bypass via Content-Type: "
                    f"{', '.join(passed_cts)}"
                ),
                description=(
                    f"The WAF blocks payloads with Content-Type "
                    f"{', '.join(blocked_cts)} but allows them with "
                    f"{', '.join(passed_cts)}. This is a misconfiguration "
                    f"that allows bypassing WAF rules by changing the "
                    f"Content-Type header."
                ),
                evidence=f"Blocked CTs: {blocked_cts} | Passed CTs: {passed_cts}",
                confidence=0.85,
                verified=self._verify_finding(
                    lambda: self._post(
                        "/",
                        headers={"Content-Type": passed_cts[0]},
                        data={"q": test_payload},
                    )
                ),
                layer=layer,
            )
            findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Layer dispatcher
    # ------------------------------------------------------------------

    _LAYER_DISPATCH = {
        "network": "_scan_network",
        "ruleengine": "_scan_ruleengine",
        "ratelimit": "_scan_ratelimit",
        "evasion": "_scan_evasion",
        "behavioural": "_scan_behavioural",
        "header": "_scan_header",
        "tls": "_scan_tls",
        "methodverb": "_scan_methodverb",
        "session": "_scan_session",
        "misconfig": "_scan_misconfig",
    }

    def scan_layer(self, layer_name: str) -> List[VulnFinding]:
        """Run a specific scan layer by name.

        Valid layer names: network, ruleengine, ratelimit, evasion,
        behavioural, header, tls, methodverb, session, misconfig.
        """
        layer_name = layer_name.lower().strip()
        method_name = self._LAYER_DISPATCH.get(layer_name)
        if method_name is None:
            raise ValueError(
                f"Unknown layer: {layer_name!r}. "
                f"Valid layers: {', '.join(self.LAYER_NAMES)}"
            )

        # Ensure baseline is captured
        if self._baseline_hash is None:
            self._capture_baseline()

        logger.info("Scanning layer: %s", layer_name)
        method = getattr(self, method_name)
        layer_findings = method()
        self._findings.extend(layer_findings)
        return layer_findings

    # ------------------------------------------------------------------
    # Full scan
    # ------------------------------------------------------------------

    def scan_all(self) -> Dict[str, Any]:
        """Run all 10 scan layers and return a comprehensive report.

        Returns a dict with:
            - domain: target domain
            - timestamp: scan start time (ISO format)
            - layers: dict mapping layer name -> list of finding dicts
            - findings: all findings sorted by severity
            - summary: stats (total, by severity, by layer, verified count)
        """
        import datetime

        start_time = datetime.datetime.now(datetime.timezone.utc)
        self._findings = []

        # Capture baseline
        self._capture_baseline()

        layer_results: Dict[str, List[Dict[str, Any]]] = {}
        for layer_name in self.LAYER_NAMES:
            logger.info("=== Scanning layer %s ===", layer_name)
            try:
                layer_findings = self.scan_layer(layer_name)
                layer_results[layer_name] = [f.to_dict() for f in layer_findings]
            except Exception as exc:
                logger.error("Layer %s failed: %s", layer_name, exc)
                layer_results[layer_name] = []
                error_finding = VulnFinding(
                    category="scan_error",
                    severity="info",
                    title=f"Layer {layer_name} scan failed",
                    description=f"Error during scan: {exc}",
                    evidence=str(exc),
                    confidence=1.0,
                    verified=True,
                    layer=layer_name,
                )
                self._findings.append(error_finding)
                layer_results[layer_name].append(error_finding.to_dict())

        # Deduplicate findings (by title)
        seen_titles: set = set()
        unique_findings: List[VulnFinding] = []
        for f in self._findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                unique_findings.append(f)

        # Sort by severity
        sorted_findings = sorted(
            unique_findings,
            key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
        )

        # Summary stats
        severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        layer_counts: Dict[str, int] = {name: 0 for name in self.LAYER_NAMES}
        verified_count = 0

        for f in sorted_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            if f.layer in layer_counts:
                layer_counts[f.layer] += 1
            if f.verified:
                verified_count += 1

        end_time = datetime.datetime.now(datetime.timezone.utc)

        report = {
            "domain": self.domain,
            "timestamp": start_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "layers": layer_results,
            "findings": [f.to_dict() for f in sorted_findings],
            "summary": {
                "total_findings": len(sorted_findings),
                "by_severity": severity_counts,
                "by_layer": layer_counts,
                "verified_count": verified_count,
                "unverified_count": len(sorted_findings) - verified_count,
            },
        }

        return report
