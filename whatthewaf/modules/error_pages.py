"""Error page probing — trigger 404, 403, 500, and WAF block pages for fingerprinting.

WAFs reveal themselves most clearly when they block a request. Error pages
from the origin server leak web server software, framework details, and
debug information that the homepage may not expose.
"""

import re
import concurrent.futures
import httpx

from . import waf_signatures

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Probes designed to trigger specific status codes and WAF reactions.
# (path, description, expected_trigger)
PROBES = [
    # --- 404 triggers ---
    ("/thispagedoesnotexist-wtw7x2q", "Non-existent path", "404"),
    ("/WTW-404-test.php", "Non-existent PHP file", "404"),
    ("/WTW-404-test.asp", "Non-existent ASP file", "404"),

    # --- 403 triggers ---
    ("/.htaccess", "Apache config file", "403"),
    ("/.env", "Environment file", "403"),
    ("/.git/config", "Git config", "403"),
    ("/server-status", "Apache server-status", "403"),
    ("/web.config", "IIS config file", "403"),

    # --- 500 triggers ---
    ("/%00", "Null byte in URL", "500"),
    ("/%%", "Double percent encoding", "500"),

    # --- WAF trigger payloads (look malicious to WAFs) ---
    ("/?id=1'+OR+1=1--", "SQL injection probe", "waf"),
    ("/<script>alert(1)</script>", "XSS probe", "waf"),
    ("/?file=../../../etc/passwd", "Path traversal probe", "waf"),
    ("/?cmd=;cat+/etc/passwd", "Command injection probe", "waf"),
    ("/?page=php://filter/convert.base64-encode/resource=index", "PHP filter probe", "waf"),
]


def _fetch_probe(url, path, timeout=8, user_agent=None, proxy=None):
    """Fetch a single probe path and return response data."""
    probe_url = url.rstrip("/") + path
    try:
        client_kwargs = {
            "timeout": timeout,
            "follow_redirects": False,
            "verify": False,
            "headers": {"User-Agent": user_agent or DEFAULT_UA},
        }
        if proxy:
            client_kwargs["proxy"] = proxy

        with httpx.Client(**client_kwargs) as client:
            resp = client.get(probe_url)

        headers = dict(resp.headers)
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        cookies = set_cookies if set_cookies else [f"{k}={v}" for k, v in resp.cookies.items()]

        body = resp.text[:100000]  # cap at 100KB for error pages

        return {
            "url": probe_url,
            "status": resp.status_code,
            "headers": headers,
            "cookies": cookies,
            "body": body,
        }
    except Exception as e:
        return {"url": probe_url, "error": str(e)}


def _detect_error_server(status, headers, body):
    """Identify the server software from error page signatures."""
    server = headers.get("server", headers.get("Server", ""))
    detections = []

    body_lower = body.lower() if body else ""

    # Apache error page signatures
    if re.search(r"<address>apache/[\d.]+", body_lower):
        m = re.search(r"<address>(apache/[\d.]+[^<]*)</address>", body_lower)
        if m:
            detections.append(("Apache", m.group(1).strip(), "error page footer"))
    elif "apache" in body_lower and ("not found" in body_lower or "forbidden" in body_lower):
        if re.search(r"apache/[\d.]+", body_lower):
            m = re.search(r"(apache/[\d.]+)", body_lower)
            if m:
                detections.append(("Apache", m.group(1), "error page"))

    # Nginx error page signatures
    if re.search(r"<center>nginx/[\d.]+</center>", body_lower):
        m = re.search(r"<center>(nginx/[\d.]+)</center>", body_lower)
        if m:
            detections.append(("Nginx", m.group(1), "error page"))
    elif re.search(r"<hr><center>nginx</center>", body_lower):
        detections.append(("Nginx", "", "error page"))

    # IIS error page signatures
    if "iis" in body_lower or "internet information services" in body_lower:
        m = re.search(r"microsoft-iis/([\d.]+)", body_lower)
        ver = m.group(1) if m else ""
        detections.append(("Microsoft IIS", ver, "error page"))
    if "detailed error" in body_lower and "iis" in body_lower:
        detections.append(("Microsoft IIS", "", "detailed error page"))

    # LiteSpeed
    if re.search(r"litespeed", body_lower) and ("not found" in body_lower or "forbidden" in body_lower):
        detections.append(("LiteSpeed", "", "error page"))

    # Tomcat
    if "apache tomcat" in body_lower:
        m = re.search(r"apache tomcat/([\d.]+)", body_lower)
        ver = m.group(1) if m else ""
        detections.append(("Apache Tomcat", ver, "error page"))

    # Jetty
    if re.search(r"powered by jetty", body_lower):
        m = re.search(r"jetty[/\s]*([\d.]+)", body_lower)
        ver = m.group(1) if m else ""
        detections.append(("Jetty", ver, "error page"))

    # Django debug page
    if "you're seeing this error because you have" in body_lower and "debug" in body_lower:
        detections.append(("Django", "", "debug error page"))
    elif "django" in body_lower and ("traceback" in body_lower or "exception" in body_lower):
        detections.append(("Django", "", "error page"))

    # Flask / Werkzeug debugger
    if "werkzeug" in body_lower or ("traceback" in body_lower and "debugger" in body_lower):
        detections.append(("Flask/Werkzeug", "", "debug error page"))

    # Laravel
    if "laravel" in body_lower or "symfony" in body_lower and "exception" in body_lower:
        detections.append(("Laravel", "", "error page"))
    if "whoops!" in body_lower and "filp/whoops" in body_lower:
        detections.append(("Laravel (Whoops)", "", "debug error page"))

    # ASP.NET
    if "asp.net" in body_lower or "aspnetcore" in body_lower:
        detections.append(("ASP.NET", "", "error page"))
    if "server error in" in body_lower and "application" in body_lower:
        detections.append(("ASP.NET", "", "detailed error page"))
    if "runtime error" in body_lower and "description:" in body_lower:
        detections.append(("ASP.NET", "", "runtime error page"))

    # Spring Boot / Java
    if "whitelabel error page" in body_lower:
        detections.append(("Spring Boot", "", "whitelabel error page"))
    if "java.lang" in body_lower or "javax.servlet" in body_lower:
        detections.append(("Java", "", "stack trace in error"))

    # Ruby on Rails
    if "action_controller" in body_lower or "actioncontroller" in body_lower:
        detections.append(("Ruby on Rails", "", "error page"))
    if "routing error" in body_lower and "rails" in body_lower:
        detections.append(("Ruby on Rails", "", "routing error"))

    # Express / Node.js
    if "cannot get /" in body_lower or "cannot get" in body_lower:
        detections.append(("Express.js", "", "error page"))
    if "rangeerror" in body_lower or "referenceerror" in body_lower:
        detections.append(("Node.js", "", "unhandled error"))

    # ColdFusion
    if "coldfusion" in body_lower:
        detections.append(("ColdFusion", "", "error page"))

    # OpenResty
    if "openresty" in body_lower:
        m = re.search(r"openresty/([\d.]+)", body_lower)
        ver = m.group(1) if m else ""
        detections.append(("OpenResty", ver, "error page"))

    return detections


def probe_error_pages(url, timeout=8, user_agent=None, proxy=None, max_workers=8):
    """Probe error-triggering paths and analyze responses for WAF/tech leaks.

    Returns dict with:
      - probes: list of per-probe results
      - extra_waf: WAF detections found only in error responses
      - extra_tech: tech detections found only in error responses
      - server_leaks: server software revealed by error pages
      - status_map: mapping of triggered status codes
    """
    results = {
        "probes": [],
        "extra_waf": [],
        "extra_tech": [],
        "server_leaks": [],
        "status_map": {},
    }

    # Fetch all probes in parallel
    probe_responses = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for path, desc, trigger in PROBES:
            fut = pool.submit(_fetch_probe, url, path, timeout, user_agent, proxy)
            futures[fut] = (path, desc, trigger)

        for fut in concurrent.futures.as_completed(futures):
            path, desc, trigger = futures[fut]
            try:
                resp = fut.result()
                resp["path"] = path
                resp["description"] = desc
                resp["trigger"] = trigger
                probe_responses.append(resp)
            except Exception:
                pass

    # Sort by path order for consistent output
    path_order = {p[0]: i for i, p in enumerate(PROBES)}
    probe_responses.sort(key=lambda r: path_order.get(r.get("path", ""), 999))

    # Track all seen WAF names to find extras
    all_waf_names = set()
    all_server_leaks = []
    seen_leaks = set()
    status_codes_seen = {}

    for resp in probe_responses:
        if resp.get("error"):
            results["probes"].append({
                "path": resp["path"],
                "description": resp["description"],
                "trigger": resp["trigger"],
                "error": resp["error"],
            })
            continue

        status = resp["status"]
        path = resp["path"]

        # Track status codes
        if status not in status_codes_seen:
            status_codes_seen[status] = []
        status_codes_seen[status].append(path)

        # WAF detection on this response
        waf_hits = waf_signatures.detect_waf(
            resp["headers"], resp["cookies"], resp["body"], status
        )
        waf_names = [w["name"] for w in waf_hits]
        all_waf_names.update(waf_names)

        # Error page server detection
        server_leaks = _detect_error_server(status, resp["headers"], resp["body"])
        for name, ver, source in server_leaks:
            key = (name, ver)
            if key not in seen_leaks:
                seen_leaks.add(key)
                all_server_leaks.append({
                    "name": name,
                    "version": ver,
                    "source": source,
                    "path": path,
                    "status": status,
                })

        # Title extraction for display
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", resp["body"][:5000], re.I | re.DOTALL)
        if m:
            title = m.group(1).strip()[:80]

        results["probes"].append({
            "path": path,
            "description": resp["description"],
            "trigger": resp["trigger"],
            "status": status,
            "title": title,
            "server": resp["headers"].get("server", resp["headers"].get("Server", "")),
            "waf_hits": [w["name"] for w in waf_hits],
            "tech_hits": [],
            "server_leaks": [f"{s['name']} {s['version']}".strip() for s in server_leaks if s["path"] == path],
        })

    results["status_map"] = status_codes_seen
    results["server_leaks"] = all_server_leaks
    results["_all_waf_names"] = list(all_waf_names)

    return results
