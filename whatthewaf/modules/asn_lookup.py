"""ASN lookup via Team Cymru WHOIS — ported from the origins() shell function."""

import socket
import re

# Known CDN/WAF provider keywords for ASN classification
CDN_KEYWORDS = [
    "fastly", "cloudflare", "akamai", "edgecast", "cloudfront",
    "amazon", "aws", "google", "gcp", "shopify", "salesforce",
    "azure", "microsoft", "cdn", "incapsula", "imperva", "sucuri",
    "stackpath", "limelight", "verizon", "radware", "f5", "barracuda",
    "fortinet", "citrix", "netlify", "vercel", "bunny", "keycdn",
    "maxcdn", "level3", "leaseweb", "ddos-guard", "ovh-hosting",
]

IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def lookup_asn(ip):
    """Query Team Cymru WHOIS for ASN info on a single IP.

    Returns dict with: ip, asn, provider, country, classification
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect(("whois.cymru.com", 43))
        sock.sendall(f" -v {ip}\n".encode())

        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()

        lines = data.decode("utf-8", errors="replace").strip().split("\n")
        # Last non-empty line has the data
        line = ""
        for l in reversed(lines):
            if l.strip() and not l.strip().startswith("AS"):
                line = l.strip()
                break

        if not line:
            return _unknown(ip)

        return _parse_cymru_line(ip, line)

    except Exception:
        return _unknown(ip)


def lookup_asn_bulk(ips):
    """Bulk query Team Cymru for multiple IPs."""
    if not ips:
        return []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect(("whois.cymru.com", 43))

        query = "begin\nverbose\n"
        for ip in ips:
            query += f"{ip}\n"
        query += "end\n"
        sock.sendall(query.encode())

        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()

        results = {}
        for line in data.decode("utf-8", errors="replace").strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("Bulk") or line.startswith("AS") or line.startswith("Error"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 7:
                ip_str = parts[1]
                if IP_RE.match(ip_str):
                    results[ip_str] = _parse_cymru_parts(ip_str, parts)

        # Fill in missing
        out = []
        for ip in ips:
            out.append(results.get(ip, _unknown(ip)))
        return out

    except Exception:
        # Fallback to individual lookups
        return [lookup_asn(ip) for ip in ips]


def classify_provider(provider):
    """Classify ASN provider as CDN or potential origin."""
    lower = provider.lower()
    for kw in CDN_KEYWORDS:
        if kw in lower:
            return "CDN"
    if not lower or lower in ("unknown", "lookup failed", "no result"):
        return "UNKNOWN"
    return "ORIGIN?"


def is_ip(text):
    """Check if input is an IPv4 address."""
    return bool(IP_RE.match(text.strip()))


def _parse_cymru_line(ip, line):
    parts = [p.strip() for p in line.split("|")]
    if len(parts) >= 7:
        return _parse_cymru_parts(ip, parts)
    return _unknown(ip)


def _parse_cymru_parts(ip, parts):
    # Verbose format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    asn = parts[0] if parts[0].isdigit() else None
    bgp_prefix = parts[2] if len(parts) > 2 else ""
    country = parts[3] if len(parts) > 3 else "??"
    registry = parts[4] if len(parts) > 4 else ""
    allocated = parts[5] if len(parts) > 5 else ""
    provider = parts[6] if len(parts) > 6 else "unknown"
    return {
        "ip": ip,
        "asn": asn,
        "bgp_prefix": bgp_prefix,
        "country": country,
        "registry": registry,
        "allocated": allocated,
        "provider": provider,
        "classification": classify_provider(provider),
    }


def _unknown(ip):
    return {
        "ip": ip,
        "asn": None,
        "bgp_prefix": "",
        "country": "??",
        "registry": "",
        "allocated": "",
        "provider": "unknown",
        "classification": "UNKNOWN",
    }
