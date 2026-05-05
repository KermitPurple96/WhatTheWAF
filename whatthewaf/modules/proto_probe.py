"""Protocol probe — detect HTTP/1.1, HTTP/2, HTTP/3 support and WAF differences.

Tests which HTTP protocols a target supports, compares WAF behavior across
protocols, and implements intelligent fallback. Useful for finding protocol-level
WAF bypasses where rules only apply to certain HTTP versions.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)


def _probe_h1(domain: str, path: str = "/", timeout: int = 10, user_agent: str = DEFAULT_UA) -> Dict[str, Any]:
    """Probe via HTTP/1.1 only."""
    try:
        with httpx.Client(
            timeout=timeout, verify=False, follow_redirects=True,
            http1=True, http2=False,
            headers={"User-Agent": user_agent},
        ) as client:
            start = time.monotonic()
            resp = client.get(f"https://{domain}{path}")
            elapsed = time.monotonic() - start
            return {
                "supported": True,
                "protocol": resp.http_version,
                "status": resp.status_code,
                "server": resp.headers.get("server", ""),
                "body_hash": hashlib.sha256(resp.content).hexdigest()[:16],
                "body_length": len(resp.content),
                "time_ms": round(elapsed * 1000, 1),
                "headers": dict(resp.headers),
                "alt_svc": resp.headers.get("alt-svc", ""),
            }
    except Exception as e:
        return {"supported": False, "error": str(e)}


def _probe_h2(domain: str, path: str = "/", timeout: int = 10, user_agent: str = DEFAULT_UA) -> Dict[str, Any]:
    """Probe via HTTP/2."""
    try:
        with httpx.Client(
            timeout=timeout, verify=False, follow_redirects=True,
            http2=True,
            headers={"User-Agent": user_agent},
        ) as client:
            start = time.monotonic()
            resp = client.get(f"https://{domain}{path}")
            elapsed = time.monotonic() - start
            return {
                "supported": resp.http_version == "HTTP/2",
                "protocol": resp.http_version,
                "status": resp.status_code,
                "server": resp.headers.get("server", ""),
                "body_hash": hashlib.sha256(resp.content).hexdigest()[:16],
                "body_length": len(resp.content),
                "time_ms": round(elapsed * 1000, 1),
                "headers": dict(resp.headers),
                "alt_svc": resp.headers.get("alt-svc", ""),
            }
    except Exception as e:
        return {"supported": False, "error": str(e)}


def _probe_h3(domain: str, path: str = "/", timeout: int = 10) -> Dict[str, Any]:
    """Probe via HTTP/3 (QUIC)."""
    try:
        from .http3_probe import probe_h3
        result = probe_h3(domain, path=path, timeout=timeout)
        return {
            "supported": result.h3_supported,
            "protocol": "HTTP/3" if result.h3_supported else None,
            "status": result.status_code,
            "server": result.server_name,
            "body_hash": result.body_hash,
            "body_length": result.body_length,
            "time_ms": result.handshake_time_ms,
            "quic_version": result.quic_version,
            "error": result.error or None,
        }
    except ImportError:
        return {"supported": False, "error": "aioquic not installed"}
    except Exception as e:
        return {"supported": False, "error": str(e)}


def probe_all_protocols(
    domain: str,
    path: str = "/",
    timeout: int = 10,
    user_agent: str = DEFAULT_UA,
) -> Dict[str, Any]:
    """Probe all HTTP protocols and compare behavior.

    Returns a comprehensive report of protocol support and differences.
    """
    report = {
        "domain": domain,
        "path": path,
        "protocols": {},
        "differences": [],
        "recommendations": [],
        "preferred_protocol": None,
    }

    # Probe each protocol
    report["protocols"]["h1"] = _probe_h1(domain, path, timeout, user_agent)
    report["protocols"]["h2"] = _probe_h2(domain, path, timeout, user_agent)
    report["protocols"]["h3"] = _probe_h3(domain, path, timeout)

    h1 = report["protocols"]["h1"]
    h2 = report["protocols"]["h2"]
    h3 = report["protocols"]["h3"]

    # Determine support
    supported = []
    if h1.get("supported"):
        supported.append("HTTP/1.1")
    if h2.get("supported"):
        supported.append("HTTP/2")
    if h3.get("supported"):
        supported.append("HTTP/3")
    report["supported_protocols"] = supported

    # Compare statuses
    statuses = {}
    if h1.get("status"):
        statuses["h1"] = h1["status"]
    if h2.get("status"):
        statuses["h2"] = h2["status"]
    if h3.get("status"):
        statuses["h3"] = h3["status"]

    unique_statuses = set(statuses.values())
    if len(unique_statuses) > 1:
        report["differences"].append(f"Status codes differ across protocols: {statuses}")
        # Check for bypass potential
        blocked_protos = [p for p, s in statuses.items() if s in (403, 406, 503)]
        passed_protos = [p for p, s in statuses.items() if s == 200]
        if blocked_protos and passed_protos:
            report["differences"].append(
                f"PROTOCOL BYPASS: {', '.join(passed_protos)} returns 200 while "
                f"{', '.join(blocked_protos)} is blocked"
            )
            report["recommendations"].append(
                f"Use {passed_protos[0]} to bypass WAF — it doesn't inspect this protocol"
            )

    # Compare body hashes
    hashes = {}
    if h1.get("body_hash"):
        hashes["h1"] = h1["body_hash"]
    if h2.get("body_hash"):
        hashes["h2"] = h2["body_hash"]
    if h3.get("body_hash"):
        hashes["h3"] = h3["body_hash"]

    unique_hashes = set(hashes.values())
    if len(unique_hashes) > 1:
        report["differences"].append(f"Content differs across protocols (body hashes: {hashes})")

    # Compare server headers
    servers = {}
    if h1.get("server"):
        servers["h1"] = h1["server"]
    if h2.get("server"):
        servers["h2"] = h2["server"]
    if h3.get("server"):
        servers["h3"] = h3["server"]

    unique_servers = set(servers.values())
    if len(unique_servers) > 1:
        report["differences"].append(f"Server header differs: {servers}")

    # Timing comparison
    times = {}
    if h1.get("time_ms"):
        times["h1"] = h1["time_ms"]
    if h2.get("time_ms"):
        times["h2"] = h2["time_ms"]
    if h3.get("time_ms"):
        times["h3"] = h3["time_ms"]
    if times:
        fastest = min(times, key=times.get)
        report["timing"] = times
        report["fastest_protocol"] = fastest

    # Check Alt-Svc for H3 advertisement
    alt_svc = h2.get("alt_svc", "") or h1.get("alt_svc", "")
    if alt_svc and "h3" in alt_svc:
        report["h3_advertised"] = True
        if not h3.get("supported"):
            report["recommendations"].append(
                "Server advertises HTTP/3 via Alt-Svc but probe failed — may need different port"
            )
    else:
        report["h3_advertised"] = False

    # Determine preferred protocol
    if h3.get("supported") and h3.get("status") == 200:
        report["preferred_protocol"] = "h3"
    elif h2.get("supported") and h2.get("status") == 200:
        report["preferred_protocol"] = "h2"
    elif h1.get("supported") and h1.get("status") == 200:
        report["preferred_protocol"] = "h1"

    # Recommendations
    if not report["differences"]:
        report["recommendations"].append(
            "No protocol-level differences detected — WAF applies uniformly"
        )
    if h3.get("supported"):
        report["recommendations"].append(
            "HTTP/3 supported — can be used for evasion if WAF inspects TCP only"
        )

    return report


def probe_protocols_with_payload(
    domain: str,
    payload: str,
    path: str = "/",
    timeout: int = 10,
) -> Dict[str, Any]:
    """Send a payload over all protocols and compare WAF response.

    Useful for finding protocol-specific WAF rule gaps.
    """
    result = {
        "payload": payload,
        "results": {},
        "bypass_found": False,
        "bypass_protocol": None,
    }

    # H1 with payload
    h1 = _probe_h1(domain, f"{path}?q={payload}", timeout)
    result["results"]["h1"] = {
        "status": h1.get("status"),
        "blocked": h1.get("status") in (403, 406, 503) if h1.get("status") else None,
    }

    # H2 with payload
    h2 = _probe_h2(domain, f"{path}?q={payload}", timeout)
    result["results"]["h2"] = {
        "status": h2.get("status"),
        "blocked": h2.get("status") in (403, 406, 503) if h2.get("status") else None,
    }

    # H3 with payload
    h3 = _probe_h3(domain, f"{path}?q={payload}", timeout)
    result["results"]["h3"] = {
        "status": h3.get("status"),
        "blocked": h3.get("status") in (403, 406, 503) if h3.get("status") else None,
        "supported": h3.get("supported", False),
    }

    # Check for bypass
    blocked = [p for p, r in result["results"].items() if r.get("blocked")]
    passed = [p for p, r in result["results"].items()
              if r.get("status") and not r.get("blocked") and r.get("status") == 200]

    if blocked and passed:
        result["bypass_found"] = True
        result["bypass_protocol"] = passed[0]

    return result
