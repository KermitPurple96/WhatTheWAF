"""WHOIS domain information lookup."""

import re
import socket


def lookup_whois(domain, timeout=10):
    """Query WHOIS for domain registration info.

    Returns dict: registrar, creation_date, expiry_date, updated_date, name_servers, status
    """
    result = {
        "domain": domain,
        "registrar": "",
        "creation_date": "",
        "expiry_date": "",
        "updated_date": "",
        "name_servers": [],
        "status": [],
        "raw": "",
    }

    # Determine WHOIS server based on TLD
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    whois_server = _get_whois_server(tld)

    try:
        raw = _query_whois(whois_server, domain, timeout)
        if not raw:
            return result
        result["raw"] = raw

        # If we got a referral, follow it
        refer_match = re.search(r"(?:Registrar WHOIS Server|whois):\s*(\S+)", raw, re.IGNORECASE)
        if refer_match:
            referral_server = refer_match.group(1).strip().rstrip(".")
            if referral_server != whois_server and "." in referral_server:
                raw2 = _query_whois(referral_server, domain, timeout)
                if raw2 and len(raw2) > len(raw):
                    raw = raw2
                    result["raw"] = raw

        # Parse common WHOIS fields
        patterns = {
            "registrar": [r"Registrar:\s*(.+)", r"registrar:\s*(.+)", r"Registrar Name:\s*(.+)"],
            "creation_date": [r"Creat(?:ion|ed)\s*Date:\s*(.+)", r"created:\s*(.+)", r"Registration Date:\s*(.+)"],
            "expiry_date": [r"(?:Registry\s+)?Expir(?:y|ation)\s*Date:\s*(.+)", r"expires:\s*(.+)", r"paid-till:\s*(.+)"],
            "updated_date": [r"Updated\s*Date:\s*(.+)", r"last-modified:\s*(.+)", r"changed:\s*(.+)"],
        }

        for field, pats in patterns.items():
            for pat in pats:
                m = re.search(pat, raw, re.IGNORECASE)
                if m:
                    result[field] = m.group(1).strip()
                    break

        # Name servers
        for m in re.finditer(r"Name Server:\s*(\S+)", raw, re.IGNORECASE):
            ns = m.group(1).strip().lower().rstrip(".")
            if ns and ns not in result["name_servers"]:
                result["name_servers"].append(ns)

        # Domain status
        for m in re.finditer(r"(?:Domain\s+)?Status:\s*(\S+)", raw, re.IGNORECASE):
            status = m.group(1).strip()
            if status and "http" not in status.lower():
                result["status"].append(status)

    except Exception:
        pass

    return result


def _get_whois_server(tld):
    """Get WHOIS server for a TLD."""
    servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "me": "whois.nic.me",
        "dev": "whois.nic.google",
        "app": "whois.nic.google",
        "xyz": "whois.nic.xyz",
        "online": "whois.nic.online",
        "tech": "whois.nic.tech",
        "site": "whois.nic.site",
        "shop": "whois.nic.shop",
        "cloud": "whois.nic.cloud",
        # Country codes
        "uk": "whois.nic.uk",
        "de": "whois.denic.de",
        "fr": "whois.nic.fr",
        "es": "whois.nic.es",
        "it": "whois.nic.it",
        "nl": "whois.sidn.nl",
        "eu": "whois.eu",
        "ru": "whois.tcinet.ru",
        "br": "whois.registro.br",
        "au": "whois.auda.org.au",
        "ca": "whois.cira.ca",
        "jp": "whois.jprs.jp",
        "cn": "whois.cnnic.cn",
        "in": "whois.inregistry.net",
    }
    return servers.get(tld, "whois.iana.org")


def _query_whois(server, domain, timeout=10):
    """Raw WHOIS TCP query."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 43))
        sock.sendall(f"{domain}\r\n".encode())

        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""
