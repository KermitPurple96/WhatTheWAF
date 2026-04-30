"""
Per-request TLS fingerprint rotation using tls-client library.

Rotates through browser TLS fingerprints to avoid WAF detection based on
JA3/JA4 fingerprint analysis. Falls back to httpx with a browser-like
SSL context when tls-client is not installed.
"""

import ssl
import threading
from typing import Any, Dict, List, Optional

try:
    import tls_client

    _TLS_CLIENT_AVAILABLE = True
except ImportError:
    _TLS_CLIENT_AVAILABLE = False

try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


# Browser identifiers supported by tls-client
BROWSER_IDENTIFIERS: List[str] = [
    "chrome_120",
    "chrome_117",
    "chrome_116",
    "firefox_121",
    "firefox_120",
    "firefox_117",
    "safari_17_0",
    "safari_16_5",
    "edge_120",
    "edge_117",
    "opera_90",
]

# Custom profiles with fine-grained TLS settings per browser family
CUSTOM_PROFILES: Dict[str, Dict[str, Any]] = {
    "chrome_120": {
        "client_identifier": "chrome_120",
        "random_tls_extension_order": True,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ],
    },
    "chrome_117": {
        "client_identifier": "chrome_117",
        "random_tls_extension_order": True,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ],
    },
    "chrome_116": {
        "client_identifier": "chrome_116",
        "random_tls_extension_order": True,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ],
    },
    "firefox_121": {
        "client_identifier": "firefox_121",
        "random_tls_extension_order": False,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
        ],
    },
    "firefox_120": {
        "client_identifier": "firefox_120",
        "random_tls_extension_order": False,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
        ],
    },
    "firefox_117": {
        "client_identifier": "firefox_117",
        "random_tls_extension_order": False,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
        ],
    },
    "safari_17_0": {
        "client_identifier": "safari_17_0",
        "random_tls_extension_order": False,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
        ],
    },
    "safari_16_5": {
        "client_identifier": "safari_16_5",
        "random_tls_extension_order": False,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp521r1_sha512",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
        ],
    },
    "edge_120": {
        "client_identifier": "edge_120",
        "random_tls_extension_order": True,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ],
    },
    "edge_117": {
        "client_identifier": "edge_117",
        "random_tls_extension_order": True,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ],
    },
    "opera_90": {
        "client_identifier": "opera_90",
        "random_tls_extension_order": True,
        "force_http1": False,
        "alpn_protocols": ["h2", "http/1.1"],
        "signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
        ],
    },
}


def _build_browser_ssl_context() -> ssl.SSLContext:
    """Build an SSL context that mimics modern browser defaults."""
    ctx = ssl.create_default_context()
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class TLSRotator:
    """
    Rotates TLS fingerprints across requests to evade JA3/JA4-based
    WAF detection.

    Uses tls-client when available for accurate browser TLS emulation.
    Falls back to httpx with a browser-like SSL context otherwise.
    """

    def __init__(
        self,
        identities: Optional[List[str]] = None,
        custom_profiles: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self._identities = list(identities or BROWSER_IDENTIFIERS)
        self._profiles = dict(custom_profiles or CUSTOM_PROFILES)
        self._index: int = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Class-level availability check
    # ------------------------------------------------------------------

    @classmethod
    def is_available(cls) -> bool:
        """Return True if tls-client is installed and usable."""
        return _TLS_CLIENT_AVAILABLE

    # ------------------------------------------------------------------
    # Identity rotation
    # ------------------------------------------------------------------

    def get_current_identity(self) -> str:
        """Return the current browser identity string."""
        with self._lock:
            return self._identities[self._index]

    def rotate(self) -> str:
        """Advance to the next identity and return it."""
        with self._lock:
            self._index = (self._index + 1) % len(self._identities)
            return self._identities[self._index]

    # ------------------------------------------------------------------
    # Session factory
    # ------------------------------------------------------------------

    def get_session(self) -> Any:
        """
        Return a ``tls_client.Session`` configured with the current
        rotated browser identity.  If tls-client is not installed, raises
        ``RuntimeError``.
        """
        if not _TLS_CLIENT_AVAILABLE:
            raise RuntimeError(
                "tls-client is not installed. "
                "Use fetch() for automatic fallback or install tls-client."
            )

        identity = self.get_current_identity()
        profile = self._profiles.get(identity, {})

        session = tls_client.Session(
            client_identifier=profile.get("client_identifier", identity),
            random_tls_extension_order=profile.get(
                "random_tls_extension_order", False
            ),
        )

        if profile.get("force_http1"):
            session.force_http1 = True

        self.rotate()
        return session

    # ------------------------------------------------------------------
    # High-level fetch
    # ------------------------------------------------------------------

    def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        timeout: int = 15,
        proxy: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Make an HTTP request using a rotated TLS identity.

        Returns a dict with keys:
            status_code  - HTTP status code (int or None on error)
            headers      - response headers as dict
            body         - response body text
            error        - error message string or None
            tls_identity - the browser identity string used
        """
        identity = self.get_current_identity()
        result: Dict[str, Any] = {
            "status_code": None,
            "headers": {},
            "body": "",
            "error": None,
            "tls_identity": identity,
        }

        if _TLS_CLIENT_AVAILABLE:
            result = self._fetch_tls_client(
                url, method, headers, data, timeout, proxy, identity, result
            )
        elif _HTTPX_AVAILABLE:
            result = self._fetch_httpx_fallback(
                url, method, headers, data, timeout, proxy, identity, result
            )
        else:
            result["error"] = (
                "Neither tls-client nor httpx is installed. "
                "Install at least one to use fetch()."
            )

        self.rotate()
        return result

    # ------------------------------------------------------------------
    # Private transport methods
    # ------------------------------------------------------------------

    def _fetch_tls_client(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]],
        data: Any,
        timeout: int,
        proxy: Optional[str],
        identity: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            profile = self._profiles.get(identity, {})
            session = tls_client.Session(
                client_identifier=profile.get("client_identifier", identity),
                random_tls_extension_order=profile.get(
                    "random_tls_extension_order", False
                ),
            )

            if profile.get("force_http1"):
                session.force_http1 = True

            if proxy:
                session.proxies = {"http": proxy, "https": proxy}

            kwargs: Dict[str, Any] = {
                "url": url,
                "timeout_seconds": timeout,
            }
            if headers:
                kwargs["headers"] = headers
            if data is not None:
                kwargs["data"] = data

            response = getattr(session, method.lower())(**kwargs)

            result["status_code"] = response.status_code
            result["headers"] = dict(response.headers)
            result["body"] = response.text
        except Exception as exc:
            result["error"] = f"tls-client error: {exc}"

        return result

    def _fetch_httpx_fallback(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]],
        data: Any,
        timeout: int,
        proxy: Optional[str],
        identity: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            ssl_ctx = _build_browser_ssl_context()
            transport = httpx.HTTPTransport(
                verify=ssl_ctx,
                proxy=proxy,
            )
            with httpx.Client(transport=transport, timeout=timeout) as client:
                kwargs: Dict[str, Any] = {
                    "method": method.upper(),
                    "url": url,
                }
                if headers:
                    kwargs["headers"] = headers
                if data is not None:
                    kwargs["content"] = (
                        data if isinstance(data, (bytes, str)) else str(data)
                    )

                response = client.request(**kwargs)

                result["status_code"] = response.status_code
                result["headers"] = dict(response.headers)
                result["body"] = response.text
        except Exception as exc:
            result["error"] = f"httpx fallback error: {exc}"

        return result
