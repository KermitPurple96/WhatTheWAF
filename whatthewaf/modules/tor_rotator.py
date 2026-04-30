"""
Tor IP rotation module with multi-instance support.

Manages multiple Tor SOCKS/control port pairs for round-robin proxy
rotation and NEWNYM-based IP cycling.
"""

import socket
import struct
import threading
import time
import logging

try:
    import requests
except ImportError:
    requests = None

try:
    from stem import Signal
    from stem.control import Controller

    HAS_STEM = True
except ImportError:
    HAS_STEM = False

logger = logging.getLogger(__name__)

# Default Tor instance definitions: (socks_port, control_port)
DEFAULT_INSTANCES = [
    (9050, 9051),
    (9052, 9053),
    (9054, 9055),
    (9056, 9057),
    (9058, 9059),
]


class TorRotator:
    """Manages multiple Tor instances for IP rotation and proxy distribution."""

    def __init__(self, control_password="", min_rotate_interval=3):
        """
        Args:
            control_password: Password for Tor control port authentication.
            min_rotate_interval: Minimum seconds between NEWNYM signals per instance.
        """
        self.control_password = control_password
        self.min_rotate_interval = min_rotate_interval
        self.instances = list(DEFAULT_INSTANCES)
        self.alive_instances = []
        self._lock = threading.Lock()
        self._counter = 0
        self._last_rotate_time = {}  # socks_port -> last rotate timestamp

    def probe_instances(self):
        """Auto-detect which Tor instances are alive by connecting to each SOCKS port.

        Returns:
            list: Alive instances as (socks_port, control_port) tuples.
        """
        alive = []
        for socks_port, control_port in self.instances:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(("127.0.0.1", socks_port))
                sock.close()
                alive.append((socks_port, control_port))
                logger.info("Tor instance alive on SOCKS port %d", socks_port)
            except (socket.error, OSError):
                logger.debug("Tor instance not reachable on SOCKS port %d", socks_port)
        with self._lock:
            self.alive_instances = alive
        if not alive:
            logger.warning("No alive Tor instances detected")
        return alive

    def get_proxy(self):
        """Return next alive proxy dict in round-robin fashion.

        Returns:
            dict: Proxy dict with 'http' and 'https' keys, or None if no
            instances are alive.
        """
        with self._lock:
            if not self.alive_instances:
                logger.warning("No alive Tor instances available")
                return None
            socks_port, _ = self.alive_instances[self._counter % len(self.alive_instances)]
            self._counter += 1

        proxy_url = f"socks5://127.0.0.1:{socks_port}"
        return {"http": proxy_url, "https": proxy_url}

    def rotate_ip(self, socks_port=None):
        """Send NEWNYM signal to obtain a new exit IP.

        If stem is installed, uses stem's Controller. Otherwise falls back to
        raw socket-based control protocol communication.

        Args:
            socks_port: Specific SOCKS port whose paired control port to signal.
                        If None, rotates all alive instances.

        Returns:
            bool: True if at least one rotation succeeded.
        """
        targets = []
        with self._lock:
            if socks_port is not None:
                for sp, cp in self.alive_instances:
                    if sp == socks_port:
                        targets.append((sp, cp))
                        break
            else:
                targets = list(self.alive_instances)

        if not targets:
            logger.warning("No targets for IP rotation")
            return False

        success = False
        now = time.time()
        for sp, cp in targets:
            last = self._last_rotate_time.get(sp, 0)
            if now - last < self.min_rotate_interval:
                wait = self.min_rotate_interval - (now - last)
                logger.debug(
                    "Rate-limiting NEWNYM for port %d, waiting %.1fs", sp, wait
                )
                time.sleep(wait)

            if self._send_newnym(cp):
                self._last_rotate_time[sp] = time.time()
                success = True
                logger.info("Rotated IP via control port %d", cp)
            else:
                logger.warning("Failed to rotate IP via control port %d", cp)

        return success

    def _send_newnym(self, control_port):
        """Send NEWNYM signal to a single control port.

        Tries stem first, then falls back to raw socket protocol.

        Returns:
            bool: True on success.
        """
        if HAS_STEM:
            return self._send_newnym_stem(control_port)
        return self._send_newnym_socket(control_port)

    def _send_newnym_stem(self, control_port):
        """Send NEWNYM using stem library."""
        try:
            with Controller.from_port(port=control_port) as controller:
                controller.authenticate(password=self.control_password)
                controller.signal(Signal.NEWNYM)
            return True
        except Exception as exc:
            logger.debug("stem NEWNYM failed on port %d: %s", control_port, exc)
            return False

    def _send_newnym_socket(self, control_port):
        """Send NEWNYM using raw socket-based Tor control protocol."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("127.0.0.1", control_port))

            response = self._recv_line(sock)
            if not response.startswith("250"):
                # Not a pre-auth greeting; some configs need AUTH first anyway
                pass

            if self.control_password:
                sock.sendall(
                    f'AUTHENTICATE "{self.control_password}"\r\n'.encode()
                )
            else:
                sock.sendall(b"AUTHENTICATE\r\n")

            auth_resp = self._recv_line(sock)
            if not auth_resp.startswith("250"):
                logger.debug(
                    "Control auth failed on port %d: %s", control_port, auth_resp
                )
                sock.close()
                return False

            sock.sendall(b"SIGNAL NEWNYM\r\n")
            signal_resp = self._recv_line(sock)
            sock.sendall(b"QUIT\r\n")
            sock.close()

            return signal_resp.startswith("250")
        except (socket.error, OSError) as exc:
            logger.debug(
                "Socket NEWNYM failed on port %d: %s", control_port, exc
            )
            return False

    @staticmethod
    def _recv_line(sock):
        """Read a single line from a socket."""
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", errors="replace").strip()

    def get_current_ip(self, socks_port=None):
        """Check current exit IP via check.torproject.org.

        Args:
            socks_port: SOCKS port to query through. If None, uses the next
                        proxy in rotation.

        Returns:
            str: The exit IP address, or None on failure.
        """
        if requests is None:
            logger.warning("requests library not installed; cannot check IP")
            return None

        if socks_port is not None:
            proxy_url = f"socks5://127.0.0.1:{socks_port}"
            proxies = {"http": proxy_url, "https": proxy_url}
        else:
            proxies = self.get_proxy()
            if proxies is None:
                return None

        try:
            resp = requests.get(
                "https://check.torproject.org/api/ip",
                proxies=proxies,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("IP")
        except Exception as exc:
            logger.debug("Failed to check exit IP: %s", exc)
            return None
