"""HTTP/3 (QUIC) probing and fingerprinting.

Tests whether a target supports HTTP/3, compares WAF behavior between
QUIC and TCP connections, and generates QUIC transport fingerprints.

Some WAFs behave differently on HTTP/3 — rules may not apply, rate limits
may differ, or the origin may expose HTTP/3 directly without WAF coverage.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class H3ProbeResult:
    """Result of an HTTP/3 probe against a target."""
    domain: str
    ip: Optional[str] = None
    h3_supported: bool = False
    alt_svc_header: str = ""
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body_hash: str = ""
    body_length: int = 0
    quic_version: str = ""
    tls_version: str = ""
    server_name: str = ""
    handshake_time_ms: float = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "ip": self.ip,
            "h3_supported": self.h3_supported,
            "alt_svc_header": self.alt_svc_header,
            "status_code": self.status_code,
            "headers": self.headers,
            "body_hash": self.body_hash,
            "body_length": self.body_length,
            "quic_version": self.quic_version,
            "tls_version": self.tls_version,
            "server_name": self.server_name,
            "handshake_time_ms": self.handshake_time_ms,
            "error": self.error,
        }


@dataclass
class QUICFingerprint:
    """QUIC transport fingerprint (similar to JA4 but for QUIC)."""
    quic_version: str = ""
    initial_max_data: int = 0
    initial_max_stream_data_bidi_local: int = 0
    initial_max_stream_data_bidi_remote: int = 0
    initial_max_stream_data_uni: int = 0
    initial_max_streams_bidi: int = 0
    initial_max_streams_uni: int = 0
    max_idle_timeout: int = 0
    active_connection_id_limit: int = 0
    tls_extensions: List[int] = field(default_factory=list)
    fingerprint_hash: str = ""

    def compute_hash(self) -> str:
        """Compute a stable fingerprint hash from QUIC transport params."""
        raw = (
            f"{self.quic_version}|"
            f"{self.initial_max_data}|"
            f"{self.initial_max_stream_data_bidi_local}|"
            f"{self.initial_max_stream_data_bidi_remote}|"
            f"{self.initial_max_streams_bidi}|"
            f"{self.initial_max_streams_uni}|"
            f"{self.max_idle_timeout}|"
            f"{self.active_connection_id_limit}"
        )
        self.fingerprint_hash = hashlib.md5(raw.encode()).hexdigest()[:12]
        return self.fingerprint_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "quic_version": self.quic_version,
            "initial_max_data": self.initial_max_data,
            "initial_max_stream_data_bidi_local": self.initial_max_stream_data_bidi_local,
            "initial_max_stream_data_bidi_remote": self.initial_max_stream_data_bidi_remote,
            "initial_max_stream_data_uni": self.initial_max_stream_data_uni,
            "initial_max_streams_bidi": self.initial_max_streams_bidi,
            "initial_max_streams_uni": self.initial_max_streams_uni,
            "max_idle_timeout": self.max_idle_timeout,
            "active_connection_id_limit": self.active_connection_id_limit,
            "fingerprint_hash": self.fingerprint_hash,
        }


# QUIC transport parameter profiles matching real browsers
QUIC_PROFILES = {
    "chrome": {
        "initial_max_data": 15728640,
        "initial_max_stream_data_bidi_local": 6291456,
        "initial_max_stream_data_bidi_remote": 6291456,
        "initial_max_stream_data_uni": 6291456,
        "initial_max_streams_bidi": 100,
        "initial_max_streams_uni": 100,
        "max_idle_timeout": 30000,
        "active_connection_id_limit": 8,
    },
    "firefox": {
        "initial_max_data": 10485760,
        "initial_max_stream_data_bidi_local": 1048576,
        "initial_max_stream_data_bidi_remote": 1048576,
        "initial_max_stream_data_uni": 1048576,
        "initial_max_streams_bidi": 100,
        "initial_max_streams_uni": 100,
        "max_idle_timeout": 30000,
        "active_connection_id_limit": 8,
    },
    "safari": {
        "initial_max_data": 8388608,
        "initial_max_stream_data_bidi_local": 1048576,
        "initial_max_stream_data_bidi_remote": 1048576,
        "initial_max_stream_data_uni": 1048576,
        "initial_max_streams_bidi": 100,
        "initial_max_streams_uni": 100,
        "max_idle_timeout": 30000,
        "active_connection_id_limit": 4,
    },
}


def check_alt_svc(domain: str, timeout: int = 10) -> Optional[str]:
    """Check if a domain advertises HTTP/3 via Alt-Svc header over HTTP/2.

    Returns the Alt-Svc header value if HTTP/3 is advertised, None otherwise.
    """
    import httpx

    try:
        with httpx.Client(
            timeout=timeout, verify=False, follow_redirects=True,
            http2=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        ) as client:
            resp = client.get(f"https://{domain}/")
            alt_svc = resp.headers.get("alt-svc", "")
            if "h3" in alt_svc:
                return alt_svc
    except Exception as e:
        logger.debug("Alt-Svc check failed for %s: %s", domain, e)
    return None


async def _probe_h3_async(
    domain: str,
    port: int = 443,
    path: str = "/",
    timeout: int = 10,
    profile: str = "chrome",
    proxy_addr: Optional[Tuple[str, int]] = None,
) -> H3ProbeResult:
    """Async HTTP/3 probe using aioquic."""
    try:
        from aioquic.asyncio import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import HeadersReceived, DataReceived
        from aioquic.quic.configuration import QuicConfiguration
    except ImportError:
        return H3ProbeResult(
            domain=domain,
            error="aioquic not installed. Install with: pip install aioquic",
        )

    result = H3ProbeResult(domain=domain)

    # Configure QUIC with browser profile
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE,
    )

    # Apply transport parameters from profile
    params = QUIC_PROFILES.get(profile, QUIC_PROFILES["chrome"])
    config.max_data = params["initial_max_data"]
    config.max_stream_data = params["initial_max_stream_data_bidi_local"]
    config.idle_timeout = params["max_idle_timeout"] / 1000.0

    start_time = time.monotonic()

    try:
        async with connect(
            domain,
            port,
            configuration=config,
            create_protocol=QuicConnectionProtocol,
        ) as protocol:
            elapsed = (time.monotonic() - start_time) * 1000
            result.handshake_time_ms = round(elapsed, 2)
            result.h3_supported = True
            result.quic_version = "QUICv1"

            # Create HTTP/3 connection
            h3 = H3Connection(protocol._quic)

            # Send request
            stream_id = protocol._quic.get_next_available_stream_id()
            headers = [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", domain.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
                (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                (b"accept-encoding", b"gzip, deflate, br"),
                (b"accept-language", b"en-US,en;q=0.9"),
            ]
            h3.send_headers(stream_id=stream_id, headers=headers, end_stream=True)

            # Transmit
            protocol.transmit()

            # Receive response
            response_headers = {}
            body_parts = []
            done = False
            deadline = time.monotonic() + timeout

            while not done and time.monotonic() < deadline:
                # Wait for data
                await asyncio.sleep(0.01)
                for event in h3.handle_events():
                    if isinstance(event, HeadersReceived):
                        for name, value in event.headers:
                            name_str = name.decode() if isinstance(name, bytes) else name
                            value_str = value.decode() if isinstance(value, bytes) else value
                            if name_str == ":status":
                                result.status_code = int(value_str)
                            else:
                                response_headers[name_str] = value_str
                        if event.stream_ended:
                            done = True
                    elif isinstance(event, DataReceived):
                        body_parts.append(event.data)
                        if event.stream_ended:
                            done = True

            result.headers = response_headers
            result.server_name = response_headers.get("server", "")
            body = b"".join(body_parts)
            result.body_length = len(body)
            result.body_hash = hashlib.sha256(body).hexdigest()[:16]

    except asyncio.TimeoutError:
        result.error = "timeout"
    except ConnectionRefusedError:
        result.error = "connection_refused"
    except Exception as e:
        error_str = str(e)
        if "no_matching" in error_str.lower() or "handshake" in error_str.lower():
            result.error = "h3_not_supported"
        else:
            result.error = error_str
            result.h3_supported = False

    return result


def probe_h3(
    domain: str,
    port: int = 443,
    path: str = "/",
    timeout: int = 10,
    profile: str = "chrome",
) -> H3ProbeResult:
    """Probe a domain for HTTP/3 support (synchronous wrapper).

    Args:
        domain: Target domain.
        port: Target port (default 443).
        path: HTTP path to request.
        timeout: Connection timeout in seconds.
        profile: QUIC transport profile (chrome, firefox, safari).

    Returns:
        H3ProbeResult with connection details.
    """
    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            _probe_h3_async(domain, port, path, timeout, profile)
        )
        loop.close()
        return result
    except Exception as e:
        return H3ProbeResult(domain=domain, error=str(e))


def compare_h2_vs_h3(
    domain: str,
    path: str = "/",
    timeout: int = 10,
) -> Dict[str, Any]:
    """Compare WAF behavior between HTTP/2 and HTTP/3.

    Sends the same request over both protocols and compares:
    - Response status codes
    - Response headers (WAF signatures)
    - Body hash (content differences)
    - Timing (rate limit differences)

    Returns a comparison report.
    """
    import httpx

    report = {
        "domain": domain,
        "h2": {},
        "h3": {},
        "differences": [],
        "h3_bypass_potential": False,
    }

    # HTTP/2 request
    try:
        with httpx.Client(
            timeout=timeout, verify=False, follow_redirects=True, http2=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"},
        ) as client:
            start = time.monotonic()
            resp = client.get(f"https://{domain}{path}")
            h2_time = time.monotonic() - start
            report["h2"] = {
                "status": resp.status_code,
                "server": resp.headers.get("server", ""),
                "body_hash": hashlib.sha256(resp.content).hexdigest()[:16],
                "body_length": len(resp.content),
                "time_ms": round(h2_time * 1000, 1),
                "alt_svc": resp.headers.get("alt-svc", ""),
                "protocol": "h2" if resp.http_version == "HTTP/2" else "h1.1",
            }
    except Exception as e:
        report["h2"] = {"error": str(e)}

    # HTTP/3 request
    h3_result = probe_h3(domain, path=path, timeout=timeout)
    report["h3"] = h3_result.to_dict()

    # Compare
    if report["h2"].get("status") and h3_result.status_code:
        h2_status = report["h2"]["status"]
        h3_status = h3_result.status_code

        if h2_status != h3_status:
            report["differences"].append(
                f"Status code differs: H2={h2_status}, H3={h3_status}"
            )
            # If H2 is blocked but H3 is OK, that's a bypass
            if h2_status in (403, 406, 503) and h3_status == 200:
                report["h3_bypass_potential"] = True
                report["differences"].append(
                    "H3 BYPASS: WAF blocks on HTTP/2 but allows HTTP/3"
                )

        h2_hash = report["h2"].get("body_hash", "")
        h3_hash = h3_result.body_hash
        if h2_hash and h3_hash and h2_hash != h3_hash:
            report["differences"].append(
                f"Body hash differs: H2={h2_hash}, H3={h3_hash}"
            )

        h2_server = report["h2"].get("server", "")
        h3_server = h3_result.server_name
        if h2_server != h3_server:
            report["differences"].append(
                f"Server header differs: H2='{h2_server}', H3='{h3_server}'"
            )

    if not report["differences"]:
        report["differences"].append("No significant differences detected")

    return report


def probe_h3_with_payload(
    domain: str,
    payload: str,
    path: str = "/",
    timeout: int = 10,
) -> Dict[str, Any]:
    """Send an attack payload over HTTP/3 and compare with HTTP/2.

    Tests whether WAF rules apply equally to HTTP/3 traffic.
    """
    import httpx

    result = {
        "payload": payload,
        "h2_blocked": False,
        "h3_blocked": False,
        "h3_bypasses_waf": False,
    }

    # Test over HTTP/2
    try:
        with httpx.Client(
            timeout=timeout, verify=False, http2=True,
            headers={"User-Agent": "Mozilla/5.0"},
        ) as client:
            resp = client.get(f"https://{domain}{path}", params={"q": payload})
            result["h2_status"] = resp.status_code
            result["h2_blocked"] = resp.status_code in (403, 406, 503)
    except Exception as e:
        result["h2_error"] = str(e)

    # Test over HTTP/3
    h3_result = probe_h3(domain, path=f"{path}?q={payload}", timeout=timeout)
    result["h3_status"] = h3_result.status_code
    result["h3_blocked"] = h3_result.status_code in (403, 406, 503) if h3_result.status_code else False
    result["h3_supported"] = h3_result.h3_supported

    # If H2 blocked but H3 passed = bypass
    if result["h2_blocked"] and not result["h3_blocked"] and h3_result.h3_supported:
        result["h3_bypasses_waf"] = True

    return result
