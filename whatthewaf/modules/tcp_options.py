"""
TCP SYN option manipulation for OS fingerprint evasion.

Uses Scapy (when available) to craft SYN packets with browser/OS-specific
TCP option signatures. Falls back to standard socket options when Scapy
is not installed or raw socket permissions are unavailable.
"""

import logging
import os
import random
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Try importing Scapy; module works in degraded mode without it.
try:
    from scapy.all import IP, TCP, RandShort, send, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.debug("Scapy not available; TCP option manipulation will use socket-only mode")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MSS_VALUES: List[int] = [1460, 1440, 1360, 1380, 1452, 8960, 1412, 1500, 1492]

WINDOW_SCALES: List[int] = [8, 7, 6, 5, 4, 3, 2, 1]

WINDOW_SIZES: List[int] = [65535, 65392, 64240, 29200, 43690, 32768, 16384]

# Browser / OS profiles with exact TCP option values.
BROWSER_PROFILES: Dict[str, Dict[str, Any]] = {
    "chrome": {
        "mss": 1460,
        "sack": True,
        "wscale": 8,
        "timestamps": True,
        "nop": 1,
        "window": 65535,
    },
    "firefox": {
        "mss": 1460,
        "sack": True,
        "wscale": 8,
        "timestamps": True,
        "nop": 1,
        "window": 65535,
    },
    "safari": {
        "mss": 1460,
        "sack": True,
        "wscale": 6,
        "timestamps": True,
        "nop": 1,
        "window": 65535,
    },
    "edge": {
        "mss": 1460,
        "sack": True,
        "wscale": 8,
        "timestamps": True,
        "nop": 1,
        "window": 65535,
    },
    "windows10": {
        "mss": 1460,
        "sack": True,
        "wscale": 8,
        "timestamps": False,
        "nop": 2,
        "window": 65535,
    },
    "linux": {
        "mss": 1460,
        "sack": True,
        "wscale": 7,
        "timestamps": True,
        "nop": 1,
        "window": 29200,
    },
}


class TCPOptionsManipulator:
    """Manipulate TCP SYN options on a per-connection basis to evade
    OS-fingerprint-based WAF detection."""

    def __init__(self) -> None:
        self._profile_names: List[str] = list(BROWSER_PROFILES.keys())
        self._rotation_index: int = 0

    # ------------------------------------------------------------------
    # Profile helpers
    # ------------------------------------------------------------------

    def build_profile(self, profile_name: str) -> Dict[str, Any]:
        """Return a dict with a Scapy-compatible TCP options list and the
        window size for the requested *profile_name*.

        Returns:
            {
                "options": [(kind, value), ...],
                "window": int,
                "name": str,
            }

        Raises:
            ValueError: if *profile_name* is not a known profile.
        """
        if profile_name not in BROWSER_PROFILES:
            raise ValueError(
                f"Unknown profile '{profile_name}'. "
                f"Available: {', '.join(self._profile_names)}"
            )

        prof = BROWSER_PROFILES[profile_name]
        options: List[Tuple[str, Any]] = []

        # MSS
        options.append(("MSS", prof["mss"]))

        # NOP padding (insert the requested number of NOPs)
        for _ in range(prof["nop"]):
            options.append(("NOP", None))

        # Window Scale
        options.append(("WScale", prof["wscale"]))

        # SACK Permitted
        if prof["sack"]:
            options.append(("SAckOK", b""))

        # Timestamps
        if prof["timestamps"]:
            ts_val = int(time.time()) & 0xFFFFFFFF
            options.append(("Timestamp", (ts_val, 0)))

        return {
            "options": options,
            "window": prof["window"],
            "name": profile_name,
        }

    def get_random_profile(self) -> Dict[str, Any]:
        """Return a randomly selected browser profile."""
        name = random.choice(self._profile_names)
        return self.build_profile(name)

    def rotate_profile(self) -> Dict[str, Any]:
        """Cycle through profiles sequentially and return the next one."""
        name = self._profile_names[self._rotation_index % len(self._profile_names)]
        self._rotation_index += 1
        return self.build_profile(name)

    # ------------------------------------------------------------------
    # Socket-level manipulation (no raw sockets / no Scapy required)
    # ------------------------------------------------------------------

    def apply_to_socket(
        self, sock: socket.socket, profile_name: str = "chrome"
    ) -> bool:
        """Apply as many TCP tunables as possible to an existing *sock*
        using standard ``setsockopt`` calls.  This does **not** require
        root or Scapy, but the kernel may clamp or ignore some values.

        Returns True on success, False if a critical option could not be set.
        """
        prof = BROWSER_PROFILES.get(profile_name)
        if prof is None:
            logger.warning("Unknown profile '%s', falling back to 'chrome'", profile_name)
            prof = BROWSER_PROFILES["chrome"]

        success = True

        # SO_RCVBUF — approximate the advertised window
        try:
            # Kernel doubles the value internally on Linux, so halve it.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, prof["window"])
        except OSError as exc:
            logger.debug("Failed to set SO_RCVBUF: %s", exc)
            success = False

        # TCP_MAXSEG — MSS
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, prof["mss"])
        except (OSError, AttributeError) as exc:
            logger.debug("Failed to set TCP_MAXSEG: %s", exc)
            success = False

        # TCP_WINDOW_CLAMP
        tcp_window_clamp = getattr(socket, "TCP_WINDOW_CLAMP", 10)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, tcp_window_clamp, prof["window"])
        except OSError as exc:
            logger.debug("Failed to set TCP_WINDOW_CLAMP: %s", exc)

        # Disable Nagle (common for browser-like behaviour)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            logger.debug("Failed to set TCP_NODELAY: %s", exc)

        return success

    # ------------------------------------------------------------------
    # Raw-socket SYN with Scapy
    # ------------------------------------------------------------------

    def send_syn_with_options(
        self,
        target_ip: str,
        target_port: int,
        profile: Optional[Dict[str, Any]] = None,
        timeout: float = 3.0,
    ) -> Optional[Any]:
        """Send a TCP SYN packet with custom options via Scapy.

        *profile* should be a dict as returned by :meth:`build_profile`.
        If ``None``, a random profile is chosen.

        Returns the SYN-ACK response packet, or ``None`` on failure.
        Gracefully falls back (returns ``None``) when Scapy is unavailable
        or we lack raw-socket permissions.
        """
        if not self.is_available():
            logger.warning(
                "Scapy raw-socket mode unavailable; "
                "cannot send SYN with custom TCP options"
            )
            return None

        if profile is None:
            profile = self.get_random_profile()

        try:
            ip_layer = IP(dst=target_ip)
            tcp_layer = TCP(
                sport=int(RandShort()),
                dport=target_port,
                flags="S",
                window=profile["window"],
                options=profile["options"],
            )

            logger.debug(
                "Sending SYN to %s:%d with profile '%s'",
                target_ip,
                target_port,
                profile.get("name", "custom"),
            )

            response = sr1(ip_layer / tcp_layer, timeout=timeout, verbose=0)
            return response

        except PermissionError:
            logger.error(
                "Permission denied: raw sockets require root / CAP_NET_RAW"
            )
            return None
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to send SYN with custom options: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    @staticmethod
    def is_available() -> bool:
        """Return ``True`` if Scapy is installed **and** we likely have
        raw-socket permissions (running as root or with CAP_NET_RAW)."""
        if not SCAPY_AVAILABLE:
            return False

        # Quick privilege check — try opening a raw socket.
        if os.geteuid() == 0:
            return True

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            return True
        except (PermissionError, OSError):
            return False
