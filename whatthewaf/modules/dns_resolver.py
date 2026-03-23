"""DNS resolution: A records, CNAME chains, NS, MX, TXT."""

import socket
import dns.resolver


def resolve_domain(domain):
    """Resolve a domain to its full DNS info."""
    domain = _clean_domain(domain)
    info = {
        "domain": domain,
        "a_records": [],
        "cnames": [],
        "ns_records": [],
        "mx_records": [],
        "txt_records": [],
    }

    # A records
    try:
        answers = dns.resolver.resolve(domain, "A")
        info["a_records"] = [r.to_text() for r in answers]
    except Exception:
        pass

    # CNAME chain
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        info["cnames"] = [r.to_text().rstrip(".") for r in answers]
    except Exception:
        pass

    # NS records
    try:
        answers = dns.resolver.resolve(domain, "NS")
        info["ns_records"] = [r.to_text().rstrip(".") for r in answers]
    except Exception:
        pass

    # MX records
    try:
        answers = dns.resolver.resolve(domain, "MX")
        info["mx_records"] = [r.exchange.to_text().rstrip(".") for r in answers]
    except Exception:
        pass

    # TXT records
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        info["txt_records"] = [r.to_text().strip('"') for r in answers]
    except Exception:
        pass

    return info


def resolve_ip(domain):
    """Simple A record resolution, returns list of IPs."""
    domain = _clean_domain(domain)
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [r.to_text() for r in answers]
    except Exception:
        # Fallback to socket
        try:
            return [socket.gethostbyname(domain)]
        except Exception:
            return []


def _clean_domain(domain):
    """Strip protocol, path, port from input."""
    domain = domain.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    if ":" in domain:
        parts = domain.rsplit(":", 1)
        if parts[1].isdigit():
            domain = parts[0]
    return domain
