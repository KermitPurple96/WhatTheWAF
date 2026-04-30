"""HTTP/2 fingerprint rotation with browser-accurate SETTINGS frames.

Provides per-request HTTP/2 fingerprint rotation to mimic real browser
behaviour and evade WAF fingerprinting based on HTTP/2 connection parameters.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import h2.connection
    import h2.settings

    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTTP/2 Settings identifiers (RFC 7540 Section 6.5.2)
# ---------------------------------------------------------------------------
HEADER_TABLE_SIZE: int = 0x1
ENABLE_PUSH: int = 0x2
MAX_CONCURRENT_STREAMS: int = 0x3
INITIAL_WINDOW_SIZE: int = 0x4
MAX_FRAME_SIZE: int = 0x5
MAX_HEADER_LIST_SIZE: int = 0x6


# ---------------------------------------------------------------------------
# H2Profile dataclass
# ---------------------------------------------------------------------------
@dataclass
class H2Profile:
    """Represents a complete HTTP/2 connection fingerprint for a browser."""

    name: str
    user_agent: str
    settings: Dict[int, int] = field(default_factory=dict)
    window_update_increment: int = 0
    header_order: List[str] = field(default_factory=list)
    pseudo_header_order: List[str] = field(default_factory=list)
    priority_weight: int = 256
    priority_depends_on: int = 0
    priority_exclusive: bool = False
    padding: int = 0


# ---------------------------------------------------------------------------
# Built-in browser profiles
# ---------------------------------------------------------------------------

_CHROME_PSEUDO_HEADERS = [":method", ":authority", ":scheme", ":path"]
_FIREFOX_PSEUDO_HEADERS = [":method", ":path", ":authority", ":scheme"]
_SAFARI_PSEUDO_HEADERS = [":method", ":scheme", ":path", ":authority"]

_CHROME_HEADER_ORDER = [
    "host",
    "connection",
    "content-length",
    "cache-control",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
]

_FIREFOX_HEADER_ORDER = [
    "host",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "connection",
    "upgrade-insecure-requests",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
]

_SAFARI_HEADER_ORDER = [
    "host",
    "accept",
    "accept-language",
    "accept-encoding",
    "connection",
    "user-agent",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
]

BUILTIN_PROFILES: Dict[str, H2Profile] = {
    # ---- Chrome ----
    "chrome120": H2Profile(
        name="chrome120",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        settings={
            HEADER_TABLE_SIZE: 65536,
            ENABLE_PUSH: 0,
            INITIAL_WINDOW_SIZE: 6291456,
            MAX_FRAME_SIZE: 16384,
            MAX_HEADER_LIST_SIZE: 262144,
        },
        window_update_increment=15663105,
        header_order=_CHROME_HEADER_ORDER,
        pseudo_header_order=_CHROME_PSEUDO_HEADERS,
        priority_weight=256,
        priority_depends_on=0,
        priority_exclusive=True,
        padding=0,
    ),
    "chrome119": H2Profile(
        name="chrome119",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/119.0.0.0 Safari/537.36"
        ),
        settings={
            HEADER_TABLE_SIZE: 65536,
            ENABLE_PUSH: 0,
            INITIAL_WINDOW_SIZE: 6291456,
            MAX_FRAME_SIZE: 16384,
            MAX_HEADER_LIST_SIZE: 262144,
        },
        window_update_increment=15663105,
        header_order=_CHROME_HEADER_ORDER,
        pseudo_header_order=_CHROME_PSEUDO_HEADERS,
        priority_weight=256,
        priority_depends_on=0,
        priority_exclusive=True,
        padding=0,
    ),
    # ---- Firefox ----
    "firefox121": H2Profile(
        name="firefox121",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
            "Gecko/20100101 Firefox/121.0"
        ),
        settings={
            HEADER_TABLE_SIZE: 65536,
            ENABLE_PUSH: 0,
            INITIAL_WINDOW_SIZE: 131072,
            MAX_FRAME_SIZE: 16384,
        },
        window_update_increment=12517377,
        header_order=_FIREFOX_HEADER_ORDER,
        pseudo_header_order=_FIREFOX_PSEUDO_HEADERS,
        priority_weight=42,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=0,
    ),
    "firefox120": H2Profile(
        name="firefox120",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
            "Gecko/20100101 Firefox/120.0"
        ),
        settings={
            HEADER_TABLE_SIZE: 65536,
            ENABLE_PUSH: 0,
            INITIAL_WINDOW_SIZE: 131072,
            MAX_FRAME_SIZE: 16384,
        },
        window_update_increment=12517377,
        header_order=_FIREFOX_HEADER_ORDER,
        pseudo_header_order=_FIREFOX_PSEUDO_HEADERS,
        priority_weight=42,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=0,
    ),
    # ---- Safari ----
    "safari17": H2Profile(
        name="safari17",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.1 Safari/605.1.15"
        ),
        settings={
            HEADER_TABLE_SIZE: 4096,
            ENABLE_PUSH: 0,
            INITIAL_WINDOW_SIZE: 2097152,
            MAX_FRAME_SIZE: 16384,
            MAX_HEADER_LIST_SIZE: 16384,
        },
        window_update_increment=10485760,
        header_order=_SAFARI_HEADER_ORDER,
        pseudo_header_order=_SAFARI_PSEUDO_HEADERS,
        priority_weight=255,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=0,
    ),
    "safari16": H2Profile(
        name="safari16",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/16.6 Safari/605.1.15"
        ),
        settings={
            HEADER_TABLE_SIZE: 4096,
            ENABLE_PUSH: 0,
            INITIAL_WINDOW_SIZE: 2097152,
            MAX_FRAME_SIZE: 16384,
            MAX_HEADER_LIST_SIZE: 16384,
        },
        window_update_increment=10485760,
        header_order=_SAFARI_HEADER_ORDER,
        pseudo_header_order=_SAFARI_PSEUDO_HEADERS,
        priority_weight=255,
        priority_depends_on=0,
        priority_exclusive=False,
        padding=0,
    ),
    # ---- Edge ----
    "edge120": H2Profile(
        name="edge120",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ),
        settings={
            HEADER_TABLE_SIZE: 65536,
            ENABLE_PUSH: 0,
            INITIAL_WINDOW_SIZE: 6291456,
            MAX_FRAME_SIZE: 16384,
            MAX_HEADER_LIST_SIZE: 262144,
        },
        window_update_increment=15663105,
        header_order=_CHROME_HEADER_ORDER,
        pseudo_header_order=_CHROME_PSEUDO_HEADERS,
        priority_weight=256,
        priority_depends_on=0,
        priority_exclusive=True,
        padding=0,
    ),
}


# ---------------------------------------------------------------------------
# H2FingerprintRotator
# ---------------------------------------------------------------------------
class H2FingerprintRotator:
    """Rotates HTTP/2 fingerprints across a list of browser profiles.

    Parameters
    ----------
    profiles:
        Optional list of profile names to rotate through.  Defaults to all
        built-in profiles.
    randomize:
        If ``True`` the initial profile is chosen at random; otherwise
        rotation starts from the first entry.
    """

    def __init__(
        self,
        profiles: Optional[List[str]] = None,
        randomize: bool = True,
    ) -> None:
        if profiles:
            self._profile_names = [
                p for p in profiles if p in BUILTIN_PROFILES
            ]
            if not self._profile_names:
                logger.warning(
                    "None of the requested profiles found; falling back to all built-in profiles."
                )
                self._profile_names = list(BUILTIN_PROFILES.keys())
        else:
            self._profile_names = list(BUILTIN_PROFILES.keys())

        self._index: int = (
            random.randrange(len(self._profile_names)) if randomize else 0
        )

    # -- public API ---------------------------------------------------------

    def rotate(self) -> H2Profile:
        """Advance to the next profile and return it."""
        self._index = (self._index + 1) % len(self._profile_names)
        profile = self.get_profile()
        logger.debug("Rotated to HTTP/2 profile: %s", profile.name)
        return profile

    def get_profile(self) -> H2Profile:
        """Return the current ``H2Profile``."""
        return BUILTIN_PROFILES[self._profile_names[self._index]]

    def get_random_profile(self) -> H2Profile:
        """Return a randomly chosen ``H2Profile``."""
        name = random.choice(self._profile_names)
        return BUILTIN_PROFILES[name]

    def apply_to_connection(self, h2_conn: Any) -> None:
        """Apply the current profile's SETTINGS to an ``h2.connection.H2Connection``.

        If the ``h2`` library is not installed this method logs a warning and
        returns without error.
        """
        if not H2_AVAILABLE:
            logger.warning(
                "h2 library is not available; cannot apply HTTP/2 settings."
            )
            return

        profile = self.get_profile()

        # Map our setting constants to h2.settings.SettingCodes
        _SETTING_MAP: Dict[int, Any] = {
            HEADER_TABLE_SIZE: h2.settings.SettingCodes.HEADER_TABLE_SIZE,
            ENABLE_PUSH: h2.settings.SettingCodes.ENABLE_PUSH,
            MAX_CONCURRENT_STREAMS: h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS,
            INITIAL_WINDOW_SIZE: h2.settings.SettingCodes.INITIAL_WINDOW_SIZE,
            MAX_FRAME_SIZE: h2.settings.SettingCodes.MAX_FRAME_SIZE,
            MAX_HEADER_LIST_SIZE: h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE,
        }

        try:
            settings_to_apply: Dict[Any, int] = {}
            for setting_id, value in profile.settings.items():
                h2_code = _SETTING_MAP.get(setting_id)
                if h2_code is not None:
                    settings_to_apply[h2_code] = value

            # Initiate settings change on the connection
            h2_conn.update_settings(settings_to_apply)

            # Send a WINDOW_UPDATE for the connection-level flow control
            if profile.window_update_increment > 0:
                h2_conn.increment_flow_control_window(
                    profile.window_update_increment, stream_id=0
                )

            logger.debug(
                "Applied HTTP/2 profile '%s' to connection.", profile.name
            )
        except Exception:
            logger.exception(
                "Failed to apply HTTP/2 profile '%s' to connection.",
                profile.name,
            )

    def get_settings_for_httpx(self) -> Dict[int, int]:
        """Return the current profile's settings dict for httpx HTTP/2 transport.

        httpx (via h2) expects a dict mapping integer setting IDs to integer
        values.  This method returns exactly that.

        Returns
        -------
        dict
            A dict like ``{0x1: 65536, 0x2: 0, ...}`` suitable for passing
            to httpx's ``HTTP2Transport`` or similar configuration points.
        """
        profile = self.get_profile()
        return dict(profile.settings)
