"""
TCP source port manipulation for WAF evasion.

Binds to specific source ports before connections to break WAF session
tracking and rate-limit counters.
"""

import random
import socket
import threading
from contextlib import contextmanager


PROFILES = {
    "trusted": [80, 443, 53, 8080, 8443],
    "browser_linux": range(32768, 60999 + 1),
    "browser_windows": range(49152, 65535 + 1),
    "scanner_evasion": [1024, 1025, 2048, 4096, 8192],
    "rotating": [80, 443, 53, 8080, 8443] + list(range(49152, 49200)),
}

MAX_BIND_ATTEMPTS = 5


class SourcePortManipulator:
    """Cycle through source ports from a named profile."""

    def __init__(self, profile="trusted"):
        if profile not in PROFILES:
            raise ValueError(
                f"Unknown profile {profile!r}. "
                f"Choose from: {', '.join(PROFILES)}"
            )
        self._profile = profile
        self._ports = list(PROFILES[profile])
        self._index = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Port selection
    # ------------------------------------------------------------------

    def get_port(self):
        """Return the next port for the current profile."""
        with self._lock:
            port = self._ports[self._index % len(self._ports)]
            self._index += 1
            return port

    # ------------------------------------------------------------------
    # Socket binding
    # ------------------------------------------------------------------

    def bind_socket(self, sock):
        """Bind *sock* to the next source port, retrying up to 5 times.

        On each failed attempt a new port is selected from the profile.
        Returns the port that was successfully bound.
        Raises OSError if all attempts fail.
        """
        last_err = None
        for _ in range(MAX_BIND_ATTEMPTS):
            port = self.get_port()
            try:
                sock.bind(("", port))
                return port
            except OSError as exc:
                last_err = exc
        raise OSError(
            f"Failed to bind after {MAX_BIND_ATTEMPTS} attempts"
        ) from last_err

    # ------------------------------------------------------------------
    # Connection monkey-patching
    # ------------------------------------------------------------------

    @contextmanager
    def patch_connection(self, domain, port):
        """Context manager that monkey-patches ``socket.create_connection``.

        Inside the block every call to ``socket.create_connection`` whose
        destination matches (*domain*, *port*) will use a manipulated
        source port.  The original function is restored on exit.
        """
        original = socket.create_connection
        manipulator = self

        def _patched(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                     source_address=None, **kwargs):
            host, dst_port = address
            if host == domain and dst_port == port:
                src_port = manipulator.get_port()
                source_address = ("", src_port)
            return original(address, timeout=timeout,
                            source_address=source_address, **kwargs)

        socket.create_connection = _patched
        try:
            yield self
        finally:
            socket.create_connection = original
