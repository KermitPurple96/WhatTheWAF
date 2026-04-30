"""
External proxy pool rotation for IP diversification.

Supports SOCKS5, SOCKS4, HTTP, and HTTPS proxies with round-robin
and random selection. Thread-safe with built-in liveness probing.
"""

import logging
import random
import threading
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


class ProxyPool:
    """Manages a rotating pool of external proxies for IP diversification."""

    PROBE_URLS = [
        "https://api.ipify.org",
        "https://httpbin.org/ip",
    ]

    def __init__(
        self,
        proxy_urls: Optional[List[str]] = None,
        proxy_file: Optional[str] = None,
        probe_on_init: bool = True,
        timeout: int = 10,
    ) -> None:
        self._lock = threading.Lock()
        self._timeout = timeout
        self._all_proxies: List[str] = []
        self._alive_proxies: List[str] = []
        self._dead_proxies: List[str] = []
        self._rotation_counter: int = 0

        if proxy_urls:
            self._all_proxies.extend(proxy_urls)

        if proxy_file:
            self.load_from_file(proxy_file)

        if probe_on_init and self._all_proxies:
            self.probe_proxies()
        elif self._all_proxies:
            # If probing is skipped, assume all proxies are alive
            self._alive_proxies = list(self._all_proxies)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_from_file(self, filepath: str) -> None:
        """Load proxy URLs from a file, one per line.

        Blank lines and lines starting with '#' are ignored.
        """
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Proxy file not found: {filepath}")

        with open(path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                self._validate_proxy_url(line)
                with self._lock:
                    if line not in self._all_proxies:
                        self._all_proxies.append(line)

    # ------------------------------------------------------------------
    # Probing
    # ------------------------------------------------------------------

    def probe_proxies(self) -> None:
        """Test every proxy for liveness and sort into alive / dead lists."""
        alive: List[str] = []
        dead: List[str] = []

        with self._lock:
            candidates = list(self._all_proxies)

        for proxy_url in candidates:
            if self._check_proxy(proxy_url):
                alive.append(proxy_url)
                logger.info("Proxy alive: %s", proxy_url)
            else:
                dead.append(proxy_url)
                logger.warning("Proxy dead: %s", proxy_url)

        with self._lock:
            self._alive_proxies = alive
            self._dead_proxies = dead
            self._rotation_counter = 0

    def _check_proxy(self, proxy_url: str) -> bool:
        """Return True if *proxy_url* can reach the internet."""
        proxy_mapping = self._format_proxy_for_httpx(proxy_url)
        for probe_url in self.PROBE_URLS:
            try:
                with httpx.Client(
                    proxy=proxy_mapping,
                    timeout=self._timeout,
                ) as client:
                    resp = client.get(probe_url)
                    if resp.status_code == 200:
                        return True
            except Exception:  # noqa: BLE001
                continue
        return False

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def get_proxy(self) -> str:
        """Return the next alive proxy URL using round-robin rotation.

        Raises ``RuntimeError`` when no alive proxies are available.
        """
        with self._lock:
            if not self._alive_proxies:
                raise RuntimeError("No alive proxies in the pool")
            idx = self._rotation_counter % len(self._alive_proxies)
            proxy = self._alive_proxies[idx]
            self._rotation_counter += 1
            return proxy

    def get_proxy_for_httpx(self) -> str:
        """Return the next alive proxy URL formatted for httpx's ``proxy`` parameter."""
        proxy_url = self.get_proxy()
        return self._format_proxy_for_httpx(proxy_url)

    def get_random_proxy(self) -> str:
        """Return a random alive proxy URL.

        Raises ``RuntimeError`` when no alive proxies are available.
        """
        with self._lock:
            if not self._alive_proxies:
                raise RuntimeError("No alive proxies in the pool")
            return random.choice(self._alive_proxies)

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------

    def remove_dead(self, proxy_url: str) -> None:
        """Move *proxy_url* from the alive list to the dead list."""
        with self._lock:
            if proxy_url in self._alive_proxies:
                self._alive_proxies.remove(proxy_url)
                if proxy_url not in self._dead_proxies:
                    self._dead_proxies.append(proxy_url)
                logger.info("Removed dead proxy: %s", proxy_url)

    def stats(self) -> Dict[str, int]:
        """Return counts of total, alive, and dead proxies."""
        with self._lock:
            return {
                "total": len(self._all_proxies),
                "alive": len(self._alive_proxies),
                "dead": len(self._dead_proxies),
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_proxy_url(url: str) -> None:
        """Raise ``ValueError`` if *url* is not a recognised proxy URL."""
        parsed = urlparse(url)
        supported_schemes = {"socks5", "socks4", "http", "https"}
        if parsed.scheme not in supported_schemes:
            raise ValueError(
                f"Unsupported proxy scheme '{parsed.scheme}' in URL: {url}. "
                f"Supported schemes: {', '.join(sorted(supported_schemes))}"
            )
        if not parsed.hostname:
            raise ValueError(f"Missing hostname in proxy URL: {url}")
        if not parsed.port:
            raise ValueError(f"Missing port in proxy URL: {url}")

    @staticmethod
    def _format_proxy_for_httpx(proxy_url: str) -> str:
        """Return *proxy_url* in the format expected by httpx's ``proxy`` kwarg.

        httpx accepts proxy URLs directly as strings (e.g.
        ``socks5://host:port``, ``http://host:port``).  This method
        normalises the URL and returns it unchanged – kept as a
        dedicated helper so callers have a single formatting point.
        """
        return proxy_url
