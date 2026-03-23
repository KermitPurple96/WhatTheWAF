"""HTTP utilities — redirect chain tracking, response hashing, robots.txt parsing."""

import hashlib
import re
import httpx


def trace_redirects(url, timeout=10, max_redirects=10, headers=None, proxy=None):
    """Follow redirects and return the full chain.

    Returns list of dicts: url, status_code, location, server
    """
    chain = []
    current_url = url
    seen = set()

    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": False,
        "verify": False,
        "headers": headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    try:
        with httpx.Client(**client_kwargs) as client:
            for _ in range(max_redirects):
                if current_url in seen:
                    chain.append({"url": current_url, "status_code": 0, "note": "redirect loop"})
                    break
                seen.add(current_url)

                try:
                    resp = client.get(current_url)
                except Exception as e:
                    chain.append({"url": current_url, "status_code": 0, "error": str(e)})
                    break

                entry = {
                    "url": current_url,
                    "status_code": resp.status_code,
                    "server": resp.headers.get("server", ""),
                }

                if resp.is_redirect:
                    location = resp.headers.get("location", "")
                    # Handle relative redirects
                    if location and not location.startswith("http"):
                        from urllib.parse import urljoin
                        location = urljoin(current_url, location)
                    entry["location"] = location
                    chain.append(entry)
                    current_url = location
                else:
                    entry["final"] = True
                    chain.append(entry)
                    break
    except Exception as e:
        chain.append({"url": current_url, "status_code": 0, "error": str(e)})

    return chain


def hash_response(body):
    """SHA256 hash of response body."""
    if not body:
        return ""
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def parse_robots_txt(url, timeout=5, proxy=None):
    """Fetch and parse robots.txt for interesting paths.

    Returns dict: raw, disallowed, sitemaps, interesting_paths
    """
    base = url.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"

    # Try to figure out the root URL
    from urllib.parse import urlparse
    parsed = urlparse(base)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    result = {
        "url": robots_url,
        "exists": False,
        "disallowed": [],
        "sitemaps": [],
        "interesting": [],
    }

    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "verify": False,
        "headers": {"User-Agent": "Mozilla/5.0"},
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    try:
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(robots_url)

        if resp.status_code != 200:
            return result

        result["exists"] = True
        body = resp.text

        for line in body.split("\n"):
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    result["disallowed"].append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                # Re-join if split on the http: part
                if sitemap.startswith("//") or sitemap.startswith("http"):
                    pass
                elif ":" in line:
                    sitemap = line.split(" ", 1)[1].strip() if " " in line else sitemap
                result["sitemaps"].append(sitemap)

        # Flag interesting paths
        interesting_patterns = [
            r"/admin", r"/wp-admin", r"/login", r"/api", r"/graphql",
            r"/debug", r"/console", r"/dashboard", r"/phpmyadmin",
            r"/\.env", r"/\.git", r"/backup", r"/config", r"/staging",
            r"/test", r"/dev", r"/private", r"/internal", r"/secret",
            r"/cgi-bin", r"/xmlrpc", r"/server-status", r"/server-info",
        ]
        for path in result["disallowed"]:
            for pattern in interesting_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    if path not in result["interesting"]:
                        result["interesting"].append(path)
                    break

    except Exception:
        pass

    return result


def probe_ports(host, ports=None, timeout=2):
    """Quick TCP connect probe on common ports.

    Returns list of dicts: port, open, service
    """
    import socket

    if ports is None:
        ports = [80, 443, 8080, 8443, 8888, 3000, 3443, 4443, 9443, 8000, 8081, 9090]

    # Known service names
    services = {
        80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        8888: "HTTP-Alt", 3000: "Dev/Node", 3443: "HTTPS-Alt", 4443: "HTTPS-Alt",
        9443: "HTTPS-Alt", 8000: "HTTP-Alt", 8081: "HTTP-Alt", 9090: "HTTP-Alt/Proxy",
    }

    results = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                results.append({
                    "port": port,
                    "open": True,
                    "service": services.get(port, "unknown"),
                })
        except Exception:
            pass

    return results
