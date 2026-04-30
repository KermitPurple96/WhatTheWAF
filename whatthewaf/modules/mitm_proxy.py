"""Full HTTPS MITM proxy with dynamic certificate generation.

Architecture:
  Client (browser/tool) → MITMProxy (localhost:8888) → [intercept + modify cleartext HTTP] → Stealth TLS → Target

Unlike StealthProxy which just tunnels bytes, this proxy performs a full
man-in-the-middle: it generates per-host TLS certificates signed by a local CA,
terminates the client's TLS, reads/modifies cleartext HTTP, then forwards via
stealth TLS (browser-like ciphers, ALPN, header ordering) to the real server.

The user must trust the generated CA certificate for HTTPS interception to work
without browser warnings.
"""

import datetime
import hashlib
import io
import os
import select
import socket
import ssl
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .proxy_mode import (
    BROWSER_HEADER_ORDER,
    CHROME_CIPHERS,
    CHROME_UA,
    TOOL_HEADERS_STRIP,
    StealthProxy,
)

# ---------------------------------------------------------------------------
# Data classes for intercepted traffic
# ---------------------------------------------------------------------------

@dataclass
class InterceptedRequest:
    """Represents a decrypted HTTP request flowing through the MITM proxy."""
    method: str
    url: str
    host: str
    port: int
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""


@dataclass
class InterceptedResponse:
    """Represents a decrypted HTTP response flowing through the MITM proxy."""
    status_code: int
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""


# ---------------------------------------------------------------------------
# CA / certificate directory
# ---------------------------------------------------------------------------

CA_DIR = "/tmp/whatthewaf_ca"
CA_KEY_PATH = os.path.join(CA_DIR, "ca.key")
CA_CERT_PATH = os.path.join(CA_DIR, "ca.crt")


# ---------------------------------------------------------------------------
# MITMProxy
# ---------------------------------------------------------------------------

class MITMProxy:
    """HTTPS man-in-the-middle proxy with dynamic certificate generation.

    Extends the stealth proxy concept from ``proxy_mode.StealthProxy``:
    traffic toward the real server uses the same browser-like TLS settings
    (cipher suite, ALPN, header ordering, UA spoofing) while giving the
    caller full access to cleartext HTTP via ``intercept_callback``.
    """

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8888,
        upstream_proxy: Optional[str] = None,
        use_proton: bool = False,
        spoof_ua: bool = True,
        spoof_tls: bool = True,
        verbose: bool = False,
        intercept_callback: Optional[Callable[[InterceptedRequest, InterceptedResponse], Optional[InterceptedResponse]]] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_proxy = upstream_proxy
        self.use_proton = use_proton
        self.spoof_ua = spoof_ua
        self.spoof_tls = spoof_tls
        self.verbose = verbose
        self.intercept_callback = intercept_callback

        self.running = False
        self.request_count = 0
        self.server_socket: Optional[socket.socket] = None

        # Re-use StealthProxy internals for upstream connectivity & header
        # processing.  We instantiate one (never call .start()) just so we can
        # borrow its helper methods.
        self._stealth = StealthProxy(
            listen_host=listen_host,
            listen_port=listen_port,
            upstream_proxy=upstream_proxy,
            use_proton=use_proton,
            spoof_ua=spoof_ua,
            spoof_tls=spoof_tls,
            strip_tool_headers=True,
            add_referer=True,
            verbose=verbose,
        )

        # Certificate cache: hostname -> (cert_path, key_path)
        self._cert_cache: Dict[str, Tuple[str, str]] = {}
        self._cert_cache_lock = threading.Lock()

        # CA key & cert (loaded or generated on first use)
        self._ca_key: Optional[rsa.RSAPrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None

        # Ensure CA exists
        self._ensure_ca()

    # ------------------------------------------------------------------
    # CA management
    # ------------------------------------------------------------------

    def _ensure_ca(self) -> None:
        """Load existing CA from disk or generate a new one."""
        if os.path.isfile(CA_KEY_PATH) and os.path.isfile(CA_CERT_PATH):
            with open(CA_KEY_PATH, "rb") as f:
                self._ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(CA_CERT_PATH, "rb") as f:
                self._ca_cert = x509.load_pem_x509_certificate(f.read())
            self._log("Loaded existing CA from " + CA_DIR)
        else:
            self._generate_ca()

    def _generate_ca(self) -> None:
        """Generate a root CA key + certificate and save to ``CA_DIR``."""
        os.makedirs(CA_DIR, mode=0o700, exist_ok=True)

        # Generate RSA 2048 key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WhatTheWAF MITM CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "WhatTheWAF Root CA"),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        # Persist
        with open(CA_KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        os.chmod(CA_KEY_PATH, 0o600)

        with open(CA_CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self._ca_key = key
        self._ca_cert = cert
        self._log("Generated new CA -> " + CA_CERT_PATH)

    def _generate_host_cert(self, hostname: str) -> Tuple[str, str]:
        """Generate a TLS certificate for *hostname* signed by our CA.

        Returns ``(cert_path, key_path)`` on disk (inside ``CA_DIR``).
        Results are cached in ``_cert_cache`` so each host is generated once.
        """
        with self._cert_cache_lock:
            if hostname in self._cert_cache:
                return self._cert_cache[hostname]

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)

        san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        safe_name = hashlib.sha256(hostname.encode()).hexdigest()[:16]
        cert_path = os.path.join(CA_DIR, f"{safe_name}.crt")
        key_path = os.path.join(CA_DIR, f"{safe_name}.key")

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        os.chmod(key_path, 0o600)

        with self._cert_cache_lock:
            self._cert_cache[hostname] = (cert_path, key_path)

        self._log(f"Generated host cert for {hostname}")
        return cert_path, key_path

    def get_ca_cert_path(self) -> str:
        """Return the filesystem path to the CA certificate.

        Users need to add this certificate to their trust store for the
        MITM interception to work without TLS warnings.
        """
        return CA_CERT_PATH

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the MITM proxy server (blocking)."""
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
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the proxy server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self._log("MITM proxy stopped.")

    # ------------------------------------------------------------------
    # Logging / banner
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"  \033[2m[mitm] {msg}\033[0m", file=sys.stderr)

    def _print_banner(self) -> None:
        print(f"""
\033[35m\033[1m+================================================================+
|  WhatTheWAF MITM Proxy                                        |
+================================================================+\033[0m
  Listen:      \033[32m{self.listen_host}:{self.listen_port}\033[0m
  CA Cert:     \033[33m{CA_CERT_PATH}\033[0m
  TLS Spoof:   \033[33m{'Chrome-like ciphers + ALPN h2' if self.spoof_tls else 'Disabled'}\033[0m
  UA Spoof:    \033[33m{'Chrome 120' if self.spoof_ua else 'Passthrough'}\033[0m
  Callback:    \033[33m{'Registered' if self.intercept_callback else 'None'}\033[0m
\033[35m\033[1m+----------------------------------------------------------------+
|  Trust the CA cert to avoid TLS warnings:                      |
|    Linux:   sudo cp {CA_CERT_PATH} /usr/local/share/ca-certificates/  |
|             sudo update-ca-certificates                        |
|    macOS:   sudo security add-trusted-cert -d -r trustRoot \\  |
|             -k /Library/Keychains/System.keychain {CA_CERT_PATH}       |
+----------------------------------------------------------------+
|  Ctrl+C to stop                                                |
+================================================================+\033[0m
""")

    # ------------------------------------------------------------------
    # Client handling
    # ------------------------------------------------------------------

    def _handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        """Dispatch an incoming connection to CONNECT or plain HTTP handler."""
        try:
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
                self._handle_plain_http(client_sock, raw)

            self.request_count += 1
        except Exception as e:
            self._log(f"Client handler error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # CONNECT (HTTPS MITM)
    # ------------------------------------------------------------------

    def _handle_connect(self, client_sock: socket.socket, raw: bytes) -> None:
        """Full MITM for CONNECT tunnels.

        1. Parse CONNECT target.
        2. Send ``200 Connection Established`` to the client.
        3. Wrap the client socket with a generated cert for the target host.
        4. Connect to the remote server and wrap with stealth TLS.
        5. Read cleartext HTTP from the client, apply header modifications,
           forward to the server, read response, optionally invoke the
           intercept callback, then forward the response back.
        """
        request_line = raw.split(b"\r\n")[0].decode("utf-8", errors="replace")
        target = request_line.split(" ")[1]
        host, port_s = target.rsplit(":", 1)
        port = int(port_s)

        self._log(f"CONNECT {host}:{port}")

        # Step 1: Tell the client the tunnel is ready
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Step 2: Wrap client socket with our generated cert (client-side TLS)
        cert_path, key_path = self._generate_host_cert(host)
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        # Allow TLS 1.2+ on the client side too
        client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        try:
            client_tls = client_ctx.wrap_socket(client_sock, server_side=True)
        except ssl.SSLError as e:
            self._log(f"Client TLS handshake failed for {host}: {e} (is the CA trusted?)")
            return

        # Step 3: Connect to remote server
        try:
            remote_sock = self._stealth._connect_remote(host, port)
        except Exception as e:
            self._log(f"Failed to connect to {host}:{port}: {e}")
            try:
                client_tls.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                )
            except Exception:
                pass
            return

        # Step 4: Wrap remote socket with stealth TLS
        remote_tls: Optional[ssl.SSLSocket] = None
        if self.spoof_tls:
            try:
                remote_tls = self._stealth._wrap_tls(remote_sock, host)
            except Exception as e:
                self._log(f"Stealth TLS to {host} failed, falling back: {e}")
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    remote_tls = ctx.wrap_socket(remote_sock, server_hostname=host)
                except Exception as e2:
                    self._log(f"Fallback TLS to {host} also failed: {e2}")
                    return
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            remote_tls = ctx.wrap_socket(remote_sock, server_hostname=host)

        # Step 5: Relay cleartext HTTP, applying modifications
        try:
            self._intercept_loop(client_tls, remote_tls, host, port)
        finally:
            try:
                remote_tls.close()
            except Exception:
                pass
            try:
                client_tls.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Plain HTTP handling (non-CONNECT)
    # ------------------------------------------------------------------

    def _handle_plain_http(self, client_sock: socket.socket, raw: bytes) -> None:
        """Handle a plain HTTP proxy request (no TLS on either side)."""
        from urllib.parse import urlparse

        request_text = raw.decode("utf-8", errors="replace")
        lines = request_text.split("\r\n")
        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if len(parts) < 3:
            return
        method, url, proto = parts

        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        self._log(f"{method} {host}{path}")

        header_lines = lines[1:]
        headers = self._stealth._process_headers(header_lines, host)

        body_start = raw.find(b"\r\n\r\n")
        body = raw[body_start + 4:] if body_start >= 0 else b""

        req = InterceptedRequest(
            method=method, url=path, host=host, port=port,
            headers=headers, body=body,
        )

        # Connect to target
        try:
            remote_sock = self._stealth._connect_remote(host, port)
        except Exception as e:
            client_sock.sendall(f"HTTP/1.1 502 Bad Gateway\r\n\r\nProxy error: {e}".encode())
            return

        # Forward
        out = self._build_request_bytes(req)
        remote_sock.sendall(out)

        # Read response
        resp_data = self._read_http_response(remote_sock)
        remote_sock.close()

        resp = self._parse_response(resp_data)

        if self.intercept_callback:
            try:
                modified = self.intercept_callback(req, resp)
                if modified is not None:
                    resp = modified
            except Exception as e:
                self._log(f"Intercept callback error: {e}")

        client_sock.sendall(self._build_response_bytes(resp))

    # ------------------------------------------------------------------
    # Intercept loop (for CONNECT / MITM sessions)
    # ------------------------------------------------------------------

    def _intercept_loop(
        self,
        client_tls: ssl.SSLSocket,
        remote_tls: ssl.SSLSocket,
        host: str,
        port: int,
    ) -> None:
        """Read HTTP request from client, modify, forward, read response, forward back.

        Handles keep-alive: loops until the connection is closed.
        """
        while True:
            # Read a full HTTP request from the client
            try:
                req_raw = self._read_http_request(client_tls)
            except Exception:
                break
            if not req_raw:
                break

            req = self._parse_request(req_raw, host, port)
            if req is None:
                break

            # Apply header modifications using StealthProxy logic
            modified_headers = self._stealth._process_headers(
                [f"{k}: {v}" for k, v in req.headers], host
            )
            req.headers = modified_headers

            # Forward to server
            out = self._build_request_bytes(req)
            try:
                remote_tls.sendall(out)
            except Exception as e:
                self._log(f"Failed sending to {host}: {e}")
                break

            # Read response from server
            try:
                resp_raw = self._read_http_response(remote_tls)
            except Exception:
                break
            if not resp_raw:
                break

            resp = self._parse_response(resp_raw)

            # Intercept callback
            if self.intercept_callback:
                try:
                    modified = self.intercept_callback(req, resp)
                    if modified is not None:
                        resp = modified
                except Exception as e:
                    self._log(f"Intercept callback error: {e}")

            # Forward response to client
            try:
                client_tls.sendall(self._build_response_bytes(resp))
            except Exception:
                break

            # Check for Connection: close
            for k, v in resp.headers:
                if k.lower() == "connection" and v.lower() == "close":
                    return

    # ------------------------------------------------------------------
    # HTTP parsing helpers
    # ------------------------------------------------------------------

    def _read_http_request(self, sock: ssl.SSLSocket) -> bytes:
        """Read a complete HTTP request (headers + body) from *sock*."""
        data = b""
        sock.settimeout(30)
        # Read headers
        while b"\r\n\r\n" not in data:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, ssl.SSLError):
                return b""
            if not chunk:
                return data
            data += chunk

        # Determine body length
        header_end = data.index(b"\r\n\r\n") + 4
        headers_part = data[:header_end].decode("utf-8", errors="replace")
        body_remaining = self._get_content_length(headers_part)

        if body_remaining is not None:
            body_so_far = len(data) - header_end
            while body_so_far < body_remaining:
                try:
                    chunk = sock.recv(min(65536, body_remaining - body_so_far))
                except (socket.timeout, ssl.SSLError):
                    break
                if not chunk:
                    break
                data += chunk
                body_so_far += len(chunk)

        return data

    def _read_http_response(self, sock) -> bytes:
        """Read a complete HTTP response (headers + body) from *sock*.

        Handles Content-Length, chunked transfer-encoding, and connection
        close.
        """
        data = b""
        sock.settimeout(30)

        # Read headers
        while b"\r\n\r\n" not in data:
            try:
                chunk = sock.recv(8192)
            except (socket.timeout, ssl.SSLError):
                return data
            if not chunk:
                return data
            data += chunk

        header_end = data.index(b"\r\n\r\n") + 4
        headers_part = data[:header_end].decode("utf-8", errors="replace")

        # Check transfer-encoding
        is_chunked = "transfer-encoding: chunked" in headers_part.lower()

        if is_chunked:
            # Read until we see the final 0\r\n\r\n chunk terminator
            while not data.endswith(b"0\r\n\r\n") and b"\r\n0\r\n\r\n" not in data:
                try:
                    chunk = sock.recv(8192)
                except (socket.timeout, ssl.SSLError):
                    break
                if not chunk:
                    break
                data += chunk
        else:
            content_length = self._get_content_length(headers_part)
            if content_length is not None:
                body_so_far = len(data) - header_end
                while body_so_far < content_length:
                    try:
                        chunk = sock.recv(min(65536, content_length - body_so_far))
                    except (socket.timeout, ssl.SSLError):
                        break
                    if not chunk:
                        break
                    data += chunk
                    body_so_far += len(chunk)
            else:
                # No content-length, no chunked — read until close or timeout
                sock.settimeout(2)
                while True:
                    try:
                        chunk = sock.recv(8192)
                    except (socket.timeout, ssl.SSLError):
                        break
                    if not chunk:
                        break
                    data += chunk

        return data

    @staticmethod
    def _get_content_length(headers_text: str) -> Optional[int]:
        """Extract Content-Length from raw header text."""
        for line in headers_text.split("\r\n"):
            if line.lower().startswith("content-length:"):
                try:
                    return int(line.split(":", 1)[1].strip())
                except ValueError:
                    return None
        return None

    def _parse_request(self, raw: bytes, host: str, port: int) -> Optional[InterceptedRequest]:
        """Parse raw HTTP request bytes into an ``InterceptedRequest``."""
        try:
            header_end = raw.index(b"\r\n\r\n")
        except ValueError:
            return None

        header_section = raw[:header_end].decode("utf-8", errors="replace")
        body = raw[header_end + 4:]

        lines = header_section.split("\r\n")
        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if len(parts) < 2:
            return None

        method = parts[0]
        url = parts[1]

        headers: List[Tuple[str, str]] = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))

        return InterceptedRequest(
            method=method, url=url, host=host, port=port,
            headers=headers, body=body,
        )

    @staticmethod
    def _parse_response(raw: bytes) -> InterceptedResponse:
        """Parse raw HTTP response bytes into an ``InterceptedResponse``."""
        if not raw:
            return InterceptedResponse(status_code=502, headers=[], body=b"")

        try:
            header_end = raw.index(b"\r\n\r\n")
        except ValueError:
            return InterceptedResponse(status_code=502, headers=[], body=raw)

        header_section = raw[:header_end].decode("utf-8", errors="replace")
        body = raw[header_end + 4:]

        lines = header_section.split("\r\n")
        status_line = lines[0]
        # e.g. "HTTP/1.1 200 OK"
        status_parts = status_line.split(" ", 2)
        try:
            status_code = int(status_parts[1])
        except (IndexError, ValueError):
            status_code = 502

        headers: List[Tuple[str, str]] = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))

        return InterceptedResponse(status_code=status_code, headers=headers, body=body)

    # ------------------------------------------------------------------
    # HTTP serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_request_bytes(req: InterceptedRequest) -> bytes:
        """Serialize an ``InterceptedRequest`` back to raw HTTP bytes."""
        out = f"{req.method} {req.url} HTTP/1.1\r\n"
        for k, v in req.headers:
            out += f"{k}: {v}\r\n"
        out += "\r\n"
        result = out.encode("utf-8", errors="replace")
        if req.body:
            result += req.body if isinstance(req.body, bytes) else req.body.encode()
        return result

    @staticmethod
    def _build_response_bytes(resp: InterceptedResponse) -> bytes:
        """Serialize an ``InterceptedResponse`` back to raw HTTP bytes."""
        out = f"HTTP/1.1 {resp.status_code} {_status_phrase(resp.status_code)}\r\n"
        for k, v in resp.headers:
            out += f"{k}: {v}\r\n"
        out += "\r\n"
        result = out.encode("utf-8", errors="replace")
        if resp.body:
            result += resp.body if isinstance(resp.body, bytes) else resp.body.encode()
        return result


# ---------------------------------------------------------------------------
# Utility: print CA trust instructions
# ---------------------------------------------------------------------------

def print_ca_setup_instructions() -> None:
    """Print instructions for trusting the WhatTheWAF CA certificate."""
    print(f"""
\033[1mWhatTheWAF MITM CA Setup\033[0m
========================

CA certificate location:
  {CA_CERT_PATH}

\033[1mLinux (Debian/Ubuntu/Kali):\033[0m
  sudo cp {CA_CERT_PATH} /usr/local/share/ca-certificates/whatthewaf_ca.crt
  sudo update-ca-certificates

\033[1mLinux (Fedora/RHEL):\033[0m
  sudo cp {CA_CERT_PATH} /etc/pki/ca-trust/source/anchors/whatthewaf_ca.crt
  sudo update-ca-trust

\033[1mmacOS:\033[0m
  sudo security add-trusted-cert -d -r trustRoot \\
    -k /Library/Keychains/System.keychain {CA_CERT_PATH}

\033[1mFirefox (all platforms):\033[0m
  Preferences -> Privacy & Security -> View Certificates -> Import
  Select: {CA_CERT_PATH}
  Check "Trust this CA to identify websites"

\033[1mChrome/Chromium (uses system store on Linux/macOS):\033[0m
  Follow the OS-level instructions above, then restart the browser.

\033[1mcurl:\033[0m
  curl --cacert {CA_CERT_PATH} -x http://127.0.0.1:8888 https://example.com
  # Or trust system-wide and just use:
  curl -x http://127.0.0.1:8888 https://example.com

\033[1mPython requests:\033[0m
  import requests
  proxies = {{"https": "http://127.0.0.1:8888"}}
  requests.get("https://example.com", proxies=proxies, verify="{CA_CERT_PATH}")
""")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STATUS_PHRASES = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}


def _status_phrase(code: int) -> str:
    return _STATUS_PHRASES.get(code, "Unknown")
