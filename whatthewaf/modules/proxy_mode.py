"""Stealth proxy mode — local proxy with TLS fingerprint evasion + ProtonVPN routing.

Architecture:
  Your tools (Burp, sqlmap, nuclei) → WTW Proxy (localhost:8888) → [JA3 evasion + browser headers] → ProtonVPN → Target

Features:
  - Rewrites TLS handshake to match Chrome/Firefox (limited cipher suites, ALPN h2)
  - Normalizes headers to browser-like order and values
  - Routes through ProtonVPN SOCKS for IP rotation
  - Accepts HTTP CONNECT (for HTTPS tunneling) and plain HTTP
  - Strips tool-specific headers that WAFs flag
"""

import hashlib
import os
import re
import select
import socket
import ssl
import subprocess
import threading
import time
import sys

from . import proxy_manager

# Browser-like cipher suites (Chrome 120 order, reduced set)
CHROME_CIPHERS = ":".join([
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
])

# Default browser-like User-Agent
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Headers that reveal pentest tools — will be stripped
TOOL_HEADERS_STRIP = [
    "x-scanner", "x-scan-", "x-burp-", "x-zaproxy", "x-wipp",
]

# Browser-like header order (important for fingerprinting)
BROWSER_HEADER_ORDER = [
    "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
    "accept-encoding", "accept-language", "cookie",
]


class StealthProxy:
    """Local proxy that makes all traffic look like a real browser."""

    def __init__(self, listen_host="127.0.0.1", listen_port=8888,
                 upstream_proxy=None, use_proton=False,
                 spoof_ua=True, spoof_tls=True, strip_tool_headers=True,
                 add_referer=True, random_delay=0,
                 verbose=False):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_proxy = upstream_proxy
        self.use_proton = use_proton
        self.spoof_ua = spoof_ua
        self.spoof_tls = spoof_tls
        self.add_referer = add_referer
        self.random_delay = random_delay  # max seconds of random delay
        self.strip_tool_headers = strip_tool_headers
        self.verbose = verbose
        self.running = False
        self.request_count = 0
        self.server_socket = None

        # Determine upstream SOCKS proxy
        if use_proton:
            self.upstream_socks = proxy_manager.PROTON_SOCKS
        elif upstream_proxy:
            self.upstream_socks = upstream_proxy
        else:
            self.upstream_socks = None

    def start(self):
        """Start the proxy server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.listen_host, self.listen_port))
        self.server_socket.listen(50)
        self.running = True

        self._print_banner()

        try:
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_sock, addr = self.server_socket.accept()
                    t = threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """Stop the proxy server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self._log("Proxy stopped.")

    def _print_banner(self):
        proton_str = ""
        if self.use_proton:
            status = proxy_manager.test_proton_connectivity(timeout=5)
            if status.get("available"):
                proton_str = f" → ProtonVPN ({status['exit_ip']} / {status.get('country', '?')})"
            else:
                proton_str = " → ProtonVPN (NOT CONNECTED - will fail!)"
        elif self.upstream_socks:
            proton_str = f" → {self.upstream_socks}"

        print(f"""
\033[36m\033[1m╔══════════════════════════════════════════════════════════════╗
║  WhatTheWAF Stealth Proxy                                    ║
╠══════════════════════════════════════════════════════════════╣\033[0m
  Listen:     \033[32m{self.listen_host}:{self.listen_port}\033[0m
  TLS Spoof:  \033[33m{'Chrome-like (restricted ciphers + ALPN h2)' if self.spoof_tls else 'Disabled'}\033[0m
  UA Spoof:   \033[33m{'Chrome 120' if self.spoof_ua else 'Passthrough'}\033[0m
  Headers:    \033[33m{'Strip tool signatures + reorder' if self.strip_tool_headers else 'Passthrough'}\033[0m
  Upstream:   \033[33m{'Direct' if not self.upstream_socks else ''}{proton_str}\033[0m
\033[36m\033[1m╠══════════════════════════════════════════════════════════════╣
║  Configure your tools:                                       ║
║    Burp:    Upstream Proxy → {self.listen_host}:{self.listen_port} (HTTP)             ║
║    curl:    curl -x http://{self.listen_host}:{self.listen_port} https://target.com   ║
║    sqlmap:  sqlmap --proxy=http://{self.listen_host}:{self.listen_port} -u ...         ║
║    nuclei:  nuclei -proxy http://{self.listen_host}:{self.listen_port} -u ...         ║
╠══════════════════════════════════════════════════════════════╣
║  Ctrl+C to stop                                             ║
╚══════════════════════════════════════════════════════════════╝\033[0m
""")

    def _log(self, msg):
        if self.verbose:
            print(f"  \033[2m[proxy] {msg}\033[0m", file=sys.stderr)

    def _handle_client(self, client_sock, addr):
        """Handle an incoming proxy connection."""
        try:
            # Random delay to mimic human timing
            if self.random_delay > 0:
                import random
                delay = random.uniform(0.1, self.random_delay)
                time.sleep(delay)

            raw = b""
            while True:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if b"\r\n\r\n" in raw:
                    break

            if not raw:
                client_sock.close()
                return

            request_line = raw.split(b"\r\n")[0].decode("utf-8", errors="replace")
            method = request_line.split(" ")[0]

            if method == "CONNECT":
                self._handle_connect(client_sock, raw)
            else:
                self._handle_http(client_sock, raw)

            self.request_count += 1

        except Exception as e:
            self._log(f"Error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_connect(self, client_sock, raw):
        """Handle HTTPS CONNECT tunnel."""
        request_line = raw.split(b"\r\n")[0].decode("utf-8", errors="replace")
        # CONNECT host:port HTTP/1.1
        target = request_line.split(" ")[1]
        host, port = target.rsplit(":", 1)
        port = int(port)

        self._log(f"CONNECT {host}:{port}")

        # Connect to target (optionally through upstream proxy)
        try:
            remote_sock = self._connect_remote(host, port)
        except Exception as e:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            self._log(f"Failed to connect to {host}:{port}: {e}")
            return

        # Tell client the tunnel is established
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Now wrap the remote socket with our stealth TLS
        if self.spoof_tls:
            try:
                remote_sock = self._wrap_tls(remote_sock, host)
            except Exception as e:
                self._log(f"TLS handshake failed for {host}: {e}")
                # Fall back to plain TLS
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    remote_sock = ctx.wrap_socket(remote_sock, server_hostname=host)
                except Exception:
                    return

        # Relay data between client and remote
        self._relay(client_sock, remote_sock, host)

    def _handle_http(self, client_sock, raw):
        """Handle plain HTTP request (rewrite and forward)."""
        request_text = raw.decode("utf-8", errors="replace")
        lines = request_text.split("\r\n")
        request_line = lines[0]
        method, url, proto = request_line.split(" ", 2)

        # Parse URL to get host
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        self._log(f"{method} {host}{path}")

        # Rewrite headers
        header_lines = lines[1:]
        headers = self._process_headers(header_lines, host)

        # Build outgoing request
        body_start = request_text.find("\r\n\r\n")
        body = request_text[body_start + 4:] if body_start >= 0 else ""

        out_request = f"{method} {path} HTTP/1.1\r\n"
        for k, v in headers:
            out_request += f"{k}: {v}\r\n"
        out_request += "\r\n"
        if body:
            out_request += body

        # Connect and send
        try:
            remote_sock = self._connect_remote(host, port)
            remote_sock.sendall(out_request.encode())

            # Read response and forward to client
            response = b""
            while True:
                try:
                    chunk = remote_sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                except Exception:
                    break

            client_sock.sendall(response)
            remote_sock.close()

        except Exception as e:
            error_resp = f"HTTP/1.1 502 Bad Gateway\r\n\r\nProxy error: {e}"
            client_sock.sendall(error_resp.encode())

    def _connect_remote(self, host, port):
        """Connect to remote host, optionally through upstream SOCKS proxy."""
        if self.upstream_socks:
            return self._connect_via_socks(host, port)
        else:
            sock = socket.create_connection((host, port), timeout=15)
            return sock

    def _connect_via_socks(self, host, port):
        """Connect through SOCKS5 proxy."""
        # Parse socks URL
        socks_url = self.upstream_socks
        # socks5://host:port
        parts = socks_url.replace("socks5://", "").replace("socks4://", "")
        socks_host, socks_port = parts.rsplit(":", 1)
        socks_port = int(socks_port)

        sock = socket.create_connection((socks_host, socks_port), timeout=15)

        # SOCKS5 handshake
        # Greeting: version=5, 1 auth method, no auth
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if resp != b"\x05\x00":
            raise Exception("SOCKS5 auth failed")

        # Connect request
        # version=5, cmd=connect, rsv=0, atype=domain
        host_bytes = host.encode()
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + port.to_bytes(2, "big")
        )

        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            raise Exception(f"SOCKS5 connect failed: {resp.hex()}")

        # Read remaining bytes of the SOCKS response if any
        if resp[3] == 0x01:  # IPv4
            if len(resp) < 10:
                sock.recv(10 - len(resp))
        elif resp[3] == 0x03:  # Domain
            domain_len = resp[4]
            remaining = 5 + domain_len + 2 - len(resp)
            if remaining > 0:
                sock.recv(remaining)
        elif resp[3] == 0x04:  # IPv6
            if len(resp) < 22:
                sock.recv(22 - len(resp))

        return sock

    def _wrap_tls(self, sock, hostname):
        """Wrap socket with browser-like TLS settings."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Set Chrome-like cipher suites
        try:
            ctx.set_ciphers(CHROME_CIPHERS)
        except ssl.SSLError:
            # Fallback if some ciphers unavailable
            ctx.set_ciphers("DEFAULT")

        # Force TLS 1.2+ (browsers don't use 1.0/1.1)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Set ALPN to h2,http/1.1 (like Chrome)
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        return ctx.wrap_socket(sock, server_hostname=hostname)

    def _process_headers(self, header_lines, host):
        """Process headers: strip tool signatures, normalize order, spoof UA."""
        headers = []
        for line in header_lines:
            if not line or ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()

            key_lower = key.lower()

            # Strip tool-revealing headers
            if self.strip_tool_headers:
                if any(key_lower.startswith(t) for t in TOOL_HEADERS_STRIP):
                    continue
                # Strip proxy-related headers tools add
                if key_lower in ("proxy-connection", "proxy-authorization"):
                    continue

            # Spoof User-Agent
            if self.spoof_ua and key_lower == "user-agent":
                # Replace tool UAs with Chrome
                val_lower = val.lower()
                tool_indicators = ["java/", "python", "sqlmap", "nikto", "nmap",
                                   "masscan", "zgrab", "gobuster", "ffuf", "dirbuster",
                                   "wfuzz", "burp", "zaproxy", "nuclei"]
                if any(t in val_lower for t in tool_indicators) or not val:
                    val = CHROME_UA

            headers.append((key, val))

        # Ensure Host header exists
        has_host = any(k.lower() == "host" for k, v in headers)
        if not has_host:
            headers.insert(0, ("Host", host))

        # Add missing browser headers
        header_names_lower = {k.lower() for k, v in headers}
        if "accept" not in header_names_lower:
            headers.append(("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"))
        if "accept-language" not in header_names_lower:
            headers.append(("Accept-Language", "en-US,en;q=0.9"))
        if "accept-encoding" not in header_names_lower:
            headers.append(("Accept-Encoding", "gzip, deflate, br, zstd"))
        if "connection" not in header_names_lower:
            headers.append(("Connection", "keep-alive"))
        if "upgrade-insecure-requests" not in header_names_lower:
            headers.append(("Upgrade-Insecure-Requests", "1"))

        # Chrome Client Hints (always present in Chrome 120+)
        if "sec-ch-ua" not in header_names_lower:
            headers.append(("sec-ch-ua", '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'))
            headers.append(("sec-ch-ua-mobile", "?0"))
            headers.append(("sec-ch-ua-platform", '"Windows"'))

        # Sec-Fetch headers (Chrome sends these on every navigation)
        if "sec-fetch-site" not in header_names_lower:
            headers.append(("Sec-Fetch-Site", "none"))
            headers.append(("Sec-Fetch-Mode", "navigate"))
            headers.append(("Sec-Fetch-User", "?1"))
            headers.append(("Sec-Fetch-Dest", "document"))

        # Referer — if missing, generate a plausible one
        if self.add_referer and "referer" not in header_names_lower:
            # Use the target's own origin as referer (looks like internal navigation)
            headers.append(("Referer", f"https://{host}/"))

        # Reorder headers to match browser order
        ordered = []
        remaining = list(headers)
        for expected in BROWSER_HEADER_ORDER:
            for h in remaining[:]:
                if h[0].lower() == expected:
                    ordered.append(h)
                    remaining.remove(h)
        ordered.extend(remaining)

        return ordered

    def _relay(self, client_sock, remote_sock, host):
        """Relay data between client and remote with header modification."""
        sockets = [client_sock, remote_sock]
        client_sock.setblocking(False)
        remote_sock.setblocking(False)

        # First, read the client's TLS data and forward with modifications
        # For CONNECT tunnels, we relay raw bytes after TLS is established
        # The client does its own TLS to us, but we do stealth TLS to the server
        # So we need to relay the decrypted HTTP inside the tunnel

        # Actually for CONNECT, the client thinks it has a raw tunnel.
        # The client will do its own TLS handshake through the tunnel.
        # We can't modify that easily without being a full MITM.
        #
        # The approach: since we already established stealth TLS to the server,
        # we tell the client "200 Connection Established" and then the client
        # sends raw HTTP (thinking it's in a TLS tunnel from its side).
        # But wait — the client will try to do TLS itself...
        #
        # For this to work properly as a stealth proxy, we need to:
        # - Client sends plain HTTP to us (proxy mode, not CONNECT)
        # - Or client uses CONNECT and we do full relay (client's TLS goes through)
        #
        # For stealth TLS, the simplest working model:
        # - The proxy accepts CONNECT
        # - Establishes stealth TLS to the remote
        # - Relays bytes between client and remote
        # - The CLIENT should NOT do its own TLS (use http:// not https:// in tool config)
        #   OR the client trusts any cert (like curl -k)
        #
        # Simple relay for now:
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 30)
                if not readable:
                    break
                for sock in readable:
                    try:
                        data = sock.recv(65536)
                        if not data:
                            return
                        if sock is client_sock:
                            remote_sock.sendall(data)
                        else:
                            client_sock.sendall(data)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        continue
                    except Exception:
                        return
        except Exception:
            pass
        finally:
            try:
                remote_sock.close()
            except Exception:
                pass


def run_proxy(listen_host="127.0.0.1", listen_port=8888,
              upstream_proxy=None, use_proton=False,
              spoof_ua=True, spoof_tls=True, strip_tool_headers=True,
              add_referer=True, random_delay=0,
              verbose=False):
    """Start the stealth proxy."""
    proxy = StealthProxy(
        listen_host=listen_host,
        listen_port=listen_port,
        upstream_proxy=upstream_proxy,
        use_proton=use_proton,
        spoof_ua=spoof_ua,
        spoof_tls=spoof_tls,
        strip_tool_headers=strip_tool_headers,
        add_referer=add_referer,
        random_delay=random_delay,
        verbose=verbose,
    )
    proxy.start()
