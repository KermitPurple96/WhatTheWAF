"""Error page probing — trigger 404, 403, 500, and WAF block pages for fingerprinting.

WAFs reveal themselves most clearly when they block a request. Error pages
from the origin server leak web server software, framework details, and
debug information that the homepage may not expose.
"""

import re
import concurrent.futures
import httpx

from . import waf_signatures

from ..constants import DEFAULT_UA

# Probes designed to trigger specific status codes and WAF reactions.
# (path, description, expected_trigger, relevant_tech)
# relevant_tech: None = always probe, set = only if detected tech matches
PROBES = [
    # --- Generic 404 triggers (always) ---
    ("/thispagedoesnotexist-wtw7x2q", "Non-existent path", "404", None),

    # --- Technology-specific 404 triggers ---
    ("/WTW-404-test.php", "Non-existent PHP file", "404", {"apache", "nginx", "litespeed", "php", "openresty"}),
    ("/WTW-404-test.asp", "Non-existent ASP file", "404", {"iis", "asp.net"}),
    ("/WTW-404-test.jsp", "Non-existent JSP file", "404", {"tomcat", "java", "wildfly", "weblogic", "websphere", "jetty"}),

    # --- Generic file exposure (any server) ---
    ("/.env", "Environment file", "403", None),
    ("/.git/config", "Git config", "403", None),

    # --- Apache / LiteSpeed ---
    ("/.htaccess", "Apache config file", "403", {"apache", "litespeed"}),
    ("/server-status", "Apache mod_status", "403", {"apache"}),
    ("/server-info", "Apache mod_info", "403", {"apache"}),

    # --- Nginx ---
    ("/nginx.conf", "Nginx config file", "403", {"nginx", "openresty"}),

    # --- IIS / ASP.NET ---
    ("/web.config", "IIS config file", "403", {"iis", "asp.net"}),
    ("/elmah.axd", "ASP.NET error log", "403", {"iis", "asp.net"}),
    ("/trace.axd", "ASP.NET trace", "403", {"iis", "asp.net"}),

    # --- Java (Tomcat, WildFly, WebLogic, Jetty, Spring) ---
    ("/WEB-INF/web.xml", "Java deployment descriptor", "403", {"tomcat", "java", "wildfly", "weblogic", "websphere", "jetty"}),
    ("/actuator", "Spring Boot Actuator", "403", {"spring", "java", "tomcat"}),
    ("/actuator/health", "Spring Boot health endpoint", "403", {"spring", "java", "tomcat"}),
    ("/manager/html", "Tomcat Manager", "403", {"tomcat"}),

    # --- Node.js ---
    ("/package.json", "Node.js package manifest", "403", {"node", "express", "deno"}),

    # --- Python (Django, Flask) ---
    ("/admin/", "Django admin", "403", {"django", "python"}),
    ("/__debug__/", "Django Debug Toolbar", "403", {"django", "python"}),

    # --- Ruby (Rails) ---
    ("/rails/info/properties", "Rails info", "403", {"rails", "ruby"}),

    # --- PHP frameworks ---
    ("/phpinfo.php", "PHP info page", "403", {"php"}),
    ("/wp-login.php", "WordPress login", "403", {"wordpress", "php"}),

    # --- Generic error triggers ---
    ("/%00", "Null byte in URL", "500", None),
    ("/%%", "Double percent encoding", "500", None),

    # --- WAF trigger payloads (always probed, including SaaS) ---
    ("/?id=1'+OR+1=1--", "SQL injection probe", "waf", None),
    ("/<script>alert(1)</script>", "XSS probe", "waf", None),
    ("/?file=../../../etc/passwd", "Path traversal probe", "waf", None),
    ("/?cmd=;cat+/etc/passwd", "Command injection probe", "waf", None),
    ("/?page=php://filter/convert.base64-encode/resource=index", "PHP filter probe", "waf", None),
]

# Provider-hosted SaaS — customer does NOT control server infrastructure.
# File access probes are skipped (server config is the provider's, not reportable).
# WAF attack probes always run (lack of WAF IS reportable).
# NOTE: Self-hostable platforms (WordPress.org, Ghost OSS, GitLab) are NOT here —
# if a client self-hosts them, everything is reportable.
SAAS_PLATFORMS = {
    # Website builders
    "wix", "squarespace", "webflow", "weebly", "jimdo",
    "strikingly", "tilda", "carrd", "webnode", "duda",
    "site123", "format", "cargo", "readymag",
    # E-commerce (provider-hosted)
    "shopify", "bigcommerce", "volusion", "bigcartel", "ecwid",
    "storenvy", "gumroad", "lemon squeezy", "sellfy",
    # Blogging / CMS (provider-hosted only)
    "wordpress.com", "medium", "blogger", "tumblr",
    "substack", "ghost.io", "hashnode", "devto",
    # Marketing / Landing pages
    "hubspot", "unbounce", "leadpages", "instapage", "clickfunnels",
    "mailchimp", "convertkit", "kajabi", "systeme",
    # Support / CRM / SaaS apps
    "zendesk", "freshdesk", "intercom", "helpscout",
    "salesforce", "servicenow",
    # Documentation
    "notion.site", "gitbook", "readme.io", "archbee",
    # Booking / Appointments
    "calendly", "acuity",
    # No-code apps
    "bubble.io", "adalo", "glide", "softr",
}

# Server header keywords → detected technology set
_SERVER_TECH_MAP = {
    # Web servers
    "apache": {"apache"}, "nginx": {"nginx"}, "litespeed": {"litespeed"},
    "openresty": {"openresty", "nginx"}, "microsoft-iis": {"iis", "asp.net"},
    "caddy": {"caddy"},
    # Java (note: "apache tomcat" must not trigger apache httpd probes)
    "apache tomcat": {"tomcat", "java"}, "tomcat": {"tomcat", "java"},
    "jetty": {"jetty", "java"},
    "wildfly": {"wildfly", "java"}, "jboss": {"wildfly", "java"},
    "weblogic": {"weblogic", "java"}, "websphere": {"websphere", "java"},
    "glassfish": {"java"}, "payara": {"java"},
    # Python
    "gunicorn": {"gunicorn", "python"}, "uvicorn": {"uvicorn", "python"},
    "waitress": {"waitress", "python"}, "daphne": {"python", "django"},
    "werkzeug": {"python", "flask"},
    # Ruby
    "puma": {"puma", "ruby", "rails"}, "thin": {"ruby", "rails"},
    "passenger": {"passenger", "ruby"},
    # Node.js
    "express": {"express", "node"}, "deno": {"deno", "node"},
    "next.js": {"node"}, "koa": {"node"},
    # .NET
    "kestrel": {"asp.net"},
    # SaaS server headers (trigger SaaS detection)
    "pepyaka": {"wix"}, "squarespace": {"squarespace"},
    "shopify": {"shopify"}, "cowboy": {"cowboy", "elixir"},
    # Proxies / LBs (don't filter probes — origin is behind them)
    "envoy": set(), "istio-envoy": set(), "haproxy": set(),
    "varnish": set(), "traefik": set(),
}

# CNAME keywords that indicate provider-hosted SaaS
_SAAS_CNAME_KEYWORDS = {
    "wixdns", "squarespace", "shopify", "myshopify",
    "wordpress.com", "ghost.io", "medium.com",
    "hubspot", "unbounce", "webflow.io",
    "zendesk.com", "freshdesk.com",
    "bigcommerce", "volusion",
    "tilda.ws", "strikingly.com",
}


def _select_probes(server_header="", cnames=None, platform=None):
    """Select relevant probes based on detected server/platform.

    Returns (filtered_probes, is_saas):
    - Provider-hosted SaaS: only WAF attack probes + generic error triggers
      (file access probes not reportable — provider controls server config)
    - Self-hosted / IaaS / PaaS: filter file access probes by detected technology
    - Unknown server: include all probes (we don't know what's behind it)
    """
    # 1. Detect if this is a provider-hosted SaaS
    is_saas = False
    if platform and platform.lower() in SAAS_PLATFORMS:
        is_saas = True
    if not is_saas and cnames:
        cname_str = " ".join(cnames).lower()
        for keyword in _SAAS_CNAME_KEYWORDS:
            if keyword in cname_str:
                is_saas = True
                break

    # 2. Build detected tech set from server header
    detected_tech = set()
    server_lower = server_header.lower() if server_header else ""
    # Match longer patterns first to avoid false positives
    # (e.g. "apache tomcat" should NOT trigger "apache" httpd probes)
    skip_keywords = set()
    for keyword in sorted(_SERVER_TECH_MAP.keys(), key=len, reverse=True):
        if keyword in skip_keywords:
            continue
        if keyword in server_lower:
            detected_tech.update(_SERVER_TECH_MAP[keyword])
            # "apache tomcat" / "apache traffic server" → skip bare "apache"
            if keyword != "apache" and "apache" in keyword:
                skip_keywords.add("apache")
    # SaaS detection from server header
    if not is_saas and detected_tech & SAAS_PLATFORMS:
        is_saas = True

    # Servers commonly used as reverse proxies — backend tech is unknown,
    # so we probe everything to discover what's behind them
    _PROXY_SERVERS = {"nginx", "openresty", "caddy", "envoy", "haproxy",
                      "traefik", "varnish", "istio-envoy"}
    is_proxy = bool(detected_tech & _PROXY_SERVERS) or not detected_tech

    # 3. Select probes
    selected = []
    for entry in PROBES:
        path, desc, trigger, relevant = entry[0], entry[1], entry[2], entry[3]

        if trigger == "waf":
            # WAF attack probes ALWAYS run — lack of WAF is reportable everywhere
            selected.append((path, desc, trigger))
            continue

        if is_saas:
            # SaaS: skip file access probes (provider controls server config)
            continue

        if is_proxy:
            # Proxy/reverse proxy detected — probe everything, backend is unknown
            selected.append((path, desc, trigger))
            continue

        if relevant is None:
            # Generic probe (e.g. .env, .git) — always relevant on non-SaaS
            selected.append((path, desc, trigger))
        elif detected_tech:
            # Only include if detected technology matches
            if relevant & detected_tech:
                selected.append((path, desc, trigger))
        else:
            # Unknown server — include all probes
            selected.append((path, desc, trigger))

    return selected, is_saas


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


def probe_error_pages(url, timeout=8, user_agent=None, proxy=None, max_workers=8,
                      server_header="", cnames=None, platform=None):
    """Probe error-triggering paths and analyze responses for WAF/tech leaks.

    Probes are filtered dynamically based on detected technology:
    - Server-specific probes only run for matching servers
      (e.g. .htaccess only for Apache, web.config only for IIS)
    - Provider-hosted SaaS (Wix, Shopify...): file access probes skipped
      (customer doesn't control server config) but attack probes always run
      (WAF status IS reportable — lack of WAF / WAF bypass)

    Returns dict with:
      - probes: list of per-probe results
      - extra_waf: WAF detections found only in error responses
      - extra_tech: tech detections found only in error responses
      - server_leaks: server software revealed by error pages
      - status_map: mapping of triggered status codes
      - is_saas: whether target is provider-hosted SaaS
    """
    selected_probes, is_saas = _select_probes(server_header, cnames, platform)

    results = {
        "probes": [],
        "extra_waf": [],
        "extra_tech": [],
        "server_leaks": [],
        "status_map": {},
        "is_saas": is_saas,
    }

    # Fetch selected probes in parallel
    probe_responses = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for path, desc, trigger in selected_probes:
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
    path_order = {p[0]: i for i, p in enumerate(selected_probes)}
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
            "headers": resp["headers"],
            "waf_hits": [w["name"] for w in waf_hits],
            "tech_hits": [],
            "server_leaks": [f"{name} {ver}".strip() for name, ver, source in server_leaks],
        })

    results["status_map"] = status_codes_seen
    results["server_leaks"] = all_server_leaks
    results["_all_waf_names"] = list(all_waf_names)

    return results
