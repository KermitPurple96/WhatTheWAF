"""SOCKS5 UDP relay for HTTP/3 QUIC traffic.

Standard SOCKS5 proxies (ProtonVPN, Tor) expose TCP-only. But SOCKS5 also
supports UDP ASSOCIATE which allows routing UDP datagrams (QUIC) through
the proxy. This module enables HTTP/3 over SOCKS5 UDP proxies.

Flow:
1. TCP connect to SOCKS5 proxy for UDP ASSOCIATE handshake
2. Proxy returns a UDP relay address
3. QUIC packets are sent/received via the UDP relay
4. Proxy forwards UDP datagrams to the target
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class SOCKS5UDPError(Exception):
    """SOCKS5 UDP operation failed."""
    pass


class SOCKS5UDPRelay:
    """SOCKS5 UDP ASSOCIATE relay for routing QUIC through a SOCKS5 proxy.

    Usage:
        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        await relay.connect()
        # Now use relay.relay_address for QUIC
        await relay.send_udp(data, target_addr, target_port)
        data, addr = await relay.recv_udp()
        await relay.close()
    """

    def __init__(
        self,
        proxy_host: str,
        proxy_port: int = 1080,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self._tcp_reader: Optional[asyncio.StreamReader] = None
        self._tcp_writer: Optional[asyncio.StreamWriter] = None
        self._udp_socket: Optional[socket.socket] = None
        self._relay_addr: Optional[Tuple[str, int]] = None
        self._local_addr: Optional[Tuple[str, int]] = None

    @property
    def relay_address(self) -> Optional[Tuple[str, int]]:
        """The UDP relay address provided by the SOCKS5 proxy."""
        return self._relay_addr

    async def connect(self, timeout: float = 10) -> Tuple[str, int]:
        """Establish SOCKS5 UDP ASSOCIATE.

        Returns the relay address (host, port) for UDP communication.
        """
        # Step 1: TCP connection to SOCKS5 proxy
        try:
            self._tcp_reader, self._tcp_writer = await asyncio.wait_for(
                asyncio.open_connection(self.proxy_host, self.proxy_port),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise SOCKS5UDPError(f"TCP connection to {self.proxy_host}:{self.proxy_port} timed out")
        except Exception as e:
            raise SOCKS5UDPError(f"TCP connection failed: {e}")

        # Step 2: Authentication negotiation
        if self.username and self.password:
            # Offer no-auth and username/password
            self._tcp_writer.write(b"\x05\x02\x00\x02")
        else:
            # Offer no-auth only
            self._tcp_writer.write(b"\x05\x01\x00")
        await self._tcp_writer.drain()

        resp = await asyncio.wait_for(self._tcp_reader.read(2), timeout=timeout)
        if len(resp) < 2 or resp[0] != 0x05:
            raise SOCKS5UDPError("Invalid SOCKS5 greeting response")

        auth_method = resp[1]
        if auth_method == 0x02:
            # Username/password auth
            if not self.username or not self.password:
                raise SOCKS5UDPError("Proxy requires auth but no credentials provided")
            auth_msg = (
                b"\x01"
                + bytes([len(self.username)]) + self.username.encode()
                + bytes([len(self.password)]) + self.password.encode()
            )
            self._tcp_writer.write(auth_msg)
            await self._tcp_writer.drain()
            auth_resp = await asyncio.wait_for(self._tcp_reader.read(2), timeout=timeout)
            if len(auth_resp) < 2 or auth_resp[1] != 0x00:
                raise SOCKS5UDPError("SOCKS5 authentication failed")
        elif auth_method == 0xFF:
            raise SOCKS5UDPError("Proxy rejected all authentication methods")

        # Step 3: UDP ASSOCIATE request
        # Bind address 0.0.0.0:0 — proxy picks relay address
        # CMD=0x03 (UDP ASSOCIATE), ATYP=0x01 (IPv4)
        udp_req = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
        self._tcp_writer.write(udp_req)
        await self._tcp_writer.drain()

        # Read response
        resp = await asyncio.wait_for(self._tcp_reader.read(256), timeout=timeout)
        if len(resp) < 10 or resp[0] != 0x05:
            raise SOCKS5UDPError("Invalid UDP ASSOCIATE response")

        if resp[1] != 0x00:
            error_codes = {
                0x01: "general failure",
                0x02: "connection not allowed",
                0x03: "network unreachable",
                0x04: "host unreachable",
                0x05: "connection refused",
                0x07: "command not supported",
            }
            code = resp[1]
            raise SOCKS5UDPError(
                f"UDP ASSOCIATE failed: {error_codes.get(code, f'code {code}')}"
            )

        # Parse relay address from response
        atyp = resp[3]
        if atyp == 0x01:  # IPv4
            relay_ip = socket.inet_ntoa(resp[4:8])
            relay_port = struct.unpack("!H", resp[8:10])[0]
        elif atyp == 0x03:  # Domain
            domain_len = resp[4]
            relay_ip = resp[5:5 + domain_len].decode()
            relay_port = struct.unpack("!H", resp[5 + domain_len:7 + domain_len])[0]
        elif atyp == 0x04:  # IPv6
            relay_ip = socket.inet_ntop(socket.AF_INET6, resp[4:20])
            relay_port = struct.unpack("!H", resp[20:22])[0]
        else:
            raise SOCKS5UDPError(f"Unknown address type: {atyp}")

        # If relay is 0.0.0.0, use proxy host
        if relay_ip in ("0.0.0.0", "::"):
            relay_ip = self.proxy_host

        self._relay_addr = (relay_ip, relay_port)

        # Step 4: Create local UDP socket for the relay
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setblocking(False)
        self._udp_socket.bind(("0.0.0.0", 0))
        self._local_addr = self._udp_socket.getsockname()

        logger.debug("SOCKS5 UDP relay established: %s:%d", relay_ip, relay_port)
        return self._relay_addr

    def _wrap_udp(self, data: bytes, target_host: str, target_port: int) -> bytes:
        """Wrap UDP data in SOCKS5 UDP header for relay.

        Format: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT(2) + DATA
        """
        header = b"\x00\x00"  # RSV
        header += b"\x00"  # FRAG (no fragmentation)

        # Encode target address
        try:
            # Try as IPv4
            addr_bytes = socket.inet_aton(target_host)
            header += b"\x01" + addr_bytes
        except socket.error:
            try:
                # Try as IPv6
                addr_bytes = socket.inet_pton(socket.AF_INET6, target_host)
                header += b"\x04" + addr_bytes
            except socket.error:
                # Domain name
                encoded = target_host.encode()
                header += b"\x03" + bytes([len(encoded)]) + encoded

        header += struct.pack("!H", target_port)
        return header + data

    def _unwrap_udp(self, data: bytes) -> Tuple[bytes, str, int]:
        """Unwrap SOCKS5 UDP header, return (payload, src_host, src_port)."""
        if len(data) < 10:
            raise SOCKS5UDPError("UDP response too short")

        # Skip RSV(2) + FRAG(1)
        atyp = data[3]
        if atyp == 0x01:  # IPv4
            src_host = socket.inet_ntoa(data[4:8])
            src_port = struct.unpack("!H", data[8:10])[0]
            payload = data[10:]
        elif atyp == 0x03:  # Domain
            domain_len = data[4]
            src_host = data[5:5 + domain_len].decode()
            src_port = struct.unpack("!H", data[5 + domain_len:7 + domain_len])[0]
            payload = data[7 + domain_len:]
        elif atyp == 0x04:  # IPv6
            src_host = socket.inet_ntop(socket.AF_INET6, data[4:20])
            src_port = struct.unpack("!H", data[20:22])[0]
            payload = data[22:]
        else:
            raise SOCKS5UDPError(f"Unknown ATYP in UDP response: {atyp}")

        return payload, src_host, src_port

    async def send_udp(self, data: bytes, target_host: str, target_port: int) -> None:
        """Send a UDP datagram through the SOCKS5 relay."""
        if not self._udp_socket or not self._relay_addr:
            raise SOCKS5UDPError("Not connected — call connect() first")

        wrapped = self._wrap_udp(data, target_host, target_port)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._udp_socket.sendto, wrapped, self._relay_addr
        )

    async def recv_udp(self, bufsize: int = 65535, timeout: float = 5) -> Tuple[bytes, str, int]:
        """Receive a UDP datagram from the SOCKS5 relay.

        Returns (payload, source_host, source_port).
        """
        if not self._udp_socket:
            raise SOCKS5UDPError("Not connected")

        loop = asyncio.get_event_loop()
        try:
            data = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: self._udp_socket.recvfrom(bufsize)[0]),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise SOCKS5UDPError("UDP receive timed out")

        return self._unwrap_udp(data)

    async def close(self) -> None:
        """Close the SOCKS5 UDP relay."""
        if self._udp_socket:
            self._udp_socket.close()
            self._udp_socket = None
        if self._tcp_writer:
            self._tcp_writer.close()
            try:
                await self._tcp_writer.wait_closed()
            except Exception:
                pass
            self._tcp_writer = None
            self._tcp_reader = None
        self._relay_addr = None


def check_socks5_udp_support(
    proxy_host: str,
    proxy_port: int = 1080,
    timeout: float = 5,
) -> bool:
    """Check if a SOCKS5 proxy supports UDP ASSOCIATE.

    Returns True if UDP relay is available.
    """
    async def _check():
        relay = SOCKS5UDPRelay(proxy_host, proxy_port)
        try:
            await relay.connect(timeout=timeout)
            await relay.close()
            return True
        except SOCKS5UDPError:
            return False
        except Exception:
            return False

    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(_check())
        loop.close()
        return result
    except Exception:
        return False
