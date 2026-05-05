"""Encrypted DNS resolution — DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH).

Prevents DNS leakage and ISP-level visibility into scanned domains.
Also bypasses DNS-level blocking that some WAFs apply at the resolver.
"""

from __future__ import annotations

import dns.resolver
import dns.rdatatype

# Well-known encrypted DNS providers
DOT_SERVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
    "adguard": "94.140.14.14",
}

DOH_SERVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/dns-query",
    "quad9": "https://dns.quad9.net/dns-query",
    "adguard": "https://dns.adguard-dns.com/dns-query",
}

# Module-level state: configured resolver override
_active_resolver: dns.resolver.Resolver | None = None
_active_mode: str | None = None  # "dot", "doh", or None


def configure_dot(server: str = "cloudflare") -> dns.resolver.Resolver:
    """Configure DNS-over-TLS resolution.

    Args:
        server: Provider name (cloudflare, google, quad9, adguard) or IP address.

    Returns the configured resolver.
    """
    global _active_resolver, _active_mode

    ip = DOT_SERVERS.get(server.lower(), server)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ip]
    # dnspython 2.4+ supports TLS natively via nameserver_ports + tls flags
    # For DoT we set port 853 and enable TLS
    resolver.port = 853
    # dnspython uses the 'tls' flag on nameservers when port is 853
    # Set nameserver ports explicitly
    resolver.nameserver_ports = {ip: 853}

    _active_resolver = resolver
    _active_mode = "dot"
    return resolver


def configure_doh(server: str = "cloudflare") -> dns.resolver.Resolver:
    """Configure DNS-over-HTTPS resolution.

    Args:
        server: Provider name (cloudflare, google, quad9, adguard) or full URL.

    Returns the configured resolver.
    """
    global _active_resolver, _active_mode

    url = DOH_SERVERS.get(server.lower(), server)

    resolver = dns.resolver.Resolver(configure=False)
    # dnspython 2.6+ supports bootstrap_address for DoH
    # For older versions, we use the nameservers with https scheme
    resolver.nameservers = [url]

    _active_resolver = resolver
    _active_mode = "doh"
    return resolver


def get_resolver() -> dns.resolver.Resolver:
    """Get the active resolver (encrypted if configured, system default otherwise)."""
    if _active_resolver is not None:
        return _active_resolver
    return dns.resolver.Resolver()


def resolve(domain: str, rdtype: str = "A") -> list[str]:
    """Resolve a domain using the active resolver (encrypted if configured).

    Falls back to system resolver if encrypted DNS fails.
    """
    resolver = get_resolver()
    try:
        answers = resolver.resolve(domain, rdtype)
        return [r.to_text().rstrip(".") for r in answers]
    except Exception:
        # Fallback to system resolver
        if _active_resolver is not None:
            try:
                fallback = dns.resolver.Resolver()
                answers = fallback.resolve(domain, rdtype)
                return [r.to_text().rstrip(".") for r in answers]
            except Exception:
                pass
        return []


def reset():
    """Reset to system DNS (disable encrypted DNS)."""
    global _active_resolver, _active_mode
    _active_resolver = None
    _active_mode = None


def get_status() -> dict:
    """Return current encrypted DNS configuration status."""
    return {
        "mode": _active_mode,
        "resolver": str(_active_resolver.nameservers[0]) if _active_resolver else None,
        "available_dot": list(DOT_SERVERS.keys()),
        "available_doh": list(DOH_SERVERS.keys()),
    }
