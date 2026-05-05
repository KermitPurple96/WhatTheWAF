"""Browser-accurate header ordering profiles.

WAFs like Cloudflare and DataDome use header order as a fingerprinting signal.
Real browsers send headers in specific, consistent orders that differ between
Chrome, Firefox, Safari, and Edge. This module provides exact header order
profiles and constructs request headers in the correct sequence.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple


# Header order profiles captured from real browser traffic.
# Each profile defines the exact order headers appear in typical GET requests.

CHROME_HEADER_ORDER = [
    "host",
    "connection",
    "cache-control",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "dnt",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
    "cookie",
]

FIREFOX_HEADER_ORDER = [
    "host",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "dnt",
    "connection",
    "cookie",
    "upgrade-insecure-requests",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
]

SAFARI_HEADER_ORDER = [
    "host",
    "accept",
    "sec-fetch-site",
    "cookie",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "user-agent",
    "accept-language",
    "accept-encoding",
    "connection",
]

EDGE_HEADER_ORDER = [
    "host",
    "connection",
    "cache-control",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "dnt",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
    "cookie",
]

# Default header values per browser profile
CHROME_HEADERS = {
    "sec-ch-ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "en-US,en;q=0.9",
}

FIREFOX_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.5",
    "accept-encoding": "gzip, deflate, br, zstd",
    "upgrade-insecure-requests": "1",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "te": "trailers",
}

SAFARI_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "sec-fetch-site": "none",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
}

EDGE_HEADERS = {
    "sec-ch-ua": '"Microsoft Edge";v="136", "Chromium";v="136", "Not.A/Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "en-US,en;q=0.9",
}

PROFILES = {
    "chrome": (CHROME_HEADER_ORDER, CHROME_HEADERS),
    "firefox": (FIREFOX_HEADER_ORDER, FIREFOX_HEADERS),
    "safari": (SAFARI_HEADER_ORDER, SAFARI_HEADERS),
    "edge": (EDGE_HEADER_ORDER, EDGE_HEADERS),
}

# Module-level active profile
_active_profile: Optional[str] = None


def set_profile(profile: str) -> None:
    """Set the active header order profile.

    Args:
        profile: One of 'chrome', 'firefox', 'safari', 'edge', or 'none' to disable.
    """
    global _active_profile
    if profile.lower() == "none":
        _active_profile = None
    elif profile.lower() in PROFILES:
        _active_profile = profile.lower()
    else:
        raise ValueError(f"Unknown profile: {profile}. Available: {list(PROFILES.keys())}")


def get_active_profile() -> Optional[str]:
    """Get the currently active header order profile name."""
    return _active_profile


def build_headers(
    extra: Optional[Dict[str, str]] = None,
    profile: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, str]:
    """Build a header dict with correct browser order.

    Args:
        extra: Additional headers to merge in (placed in correct order position).
        profile: Profile to use (overrides module-level active profile).
        user_agent: Override the User-Agent (keeps correct position in order).

    Returns:
        OrderedDict-like dict with headers in browser-correct order.
    """
    prof = profile or _active_profile
    if prof is None:
        # No profile active — return minimal headers with extra
        headers = {}
        if user_agent:
            headers["user-agent"] = user_agent
        if extra:
            headers.update(extra)
        return headers

    order, defaults = PROFILES[prof]

    # Start with profile defaults
    merged = dict(defaults)

    # Override user-agent if specified
    if user_agent:
        merged["user-agent"] = user_agent

    # Merge extra headers
    if extra:
        for k, v in extra.items():
            merged[k.lower()] = v

    # Build output in correct order
    result = {}
    for key in order:
        if key in merged:
            result[key] = merged[key]

    # Append any extra headers not in the order list (at the end)
    for key, val in merged.items():
        if key not in result:
            result[key] = val

    return result


def get_ordered_headers_for_httpx(
    profile: Optional[str] = None,
    user_agent: Optional[str] = None,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Get headers ready for httpx Client(headers=...).

    httpx preserves insertion order, so this ensures the correct
    browser header ordering is maintained in requests.
    """
    return build_headers(extra=extra, profile=profile, user_agent=user_agent)
