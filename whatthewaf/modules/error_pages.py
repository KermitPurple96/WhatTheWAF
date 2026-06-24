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
    # ── Generic (always) ──
    ("/thispagedoesnotexist-wtw7x2q", "Non-existent path", "404", None),
    ("/.env", "Environment file", "403", None),
    ("/.git/config", "Git config", "403", None),
    ("/.svn/entries", "SVN metadata", "403", None),
    ("/.DS_Store", "macOS directory metadata", "403", None),
    ("/crossdomain.xml", "Flash cross-domain policy", "403", None),
    ("/robots.txt", "Robots file", "404", None),
    ("/sitemap.xml", "Sitemap", "404", None),

    # ── Technology-specific 404 triggers ──
    ("/WTW-404-test.php", "Non-existent PHP file", "404", {"apache", "nginx", "litespeed", "php", "openresty"}),
    ("/WTW-404-test.asp", "Non-existent ASP file", "404", {"iis", "asp.net"}),
    ("/WTW-404-test.jsp", "Non-existent JSP file", "404", {"tomcat", "java", "wildfly", "weblogic", "websphere", "jetty", "spring"}),
    ("/WTW-404-test.py", "Non-existent Python file", "404", {"python", "django", "flask"}),

    # ── Apache / LiteSpeed ──
    ("/.htaccess", "Apache config file", "403", {"apache", "litespeed"}),
    ("/.htpasswd", "Apache password file", "403", {"apache", "litespeed"}),
    ("/server-status", "Apache mod_status", "403", {"apache"}),
    ("/server-info", "Apache mod_info", "403", {"apache"}),
    ("/cgi-bin/", "CGI directory", "403", {"apache", "litespeed"}),

    # ── Nginx / OpenResty ──
    ("/nginx.conf", "Nginx config file", "403", {"nginx", "openresty"}),
    ("/nginx_status", "Nginx stub_status", "403", {"nginx", "openresty"}),

    # ── IIS / ASP.NET ──
    ("/web.config", "IIS config file", "403", {"iis", "asp.net"}),
    ("/elmah.axd", "ASP.NET error log (ELMAH)", "403", {"iis", "asp.net"}),
    ("/trace.axd", "ASP.NET trace handler", "403", {"iis", "asp.net"}),
    ("/aspnet_client/", "ASP.NET client scripts", "403", {"iis", "asp.net"}),
    ("/_vti_bin/", "FrontPage extensions", "403", {"iis"}),
    ("/_vti_pvt/", "FrontPage private dir", "403", {"iis"}),

    # ── Java — Tomcat ──
    ("/WEB-INF/web.xml", "Java deployment descriptor", "403", {"tomcat", "java", "wildfly", "weblogic", "websphere", "jetty", "spring"}),
    ("/META-INF/MANIFEST.MF", "Java manifest", "403", {"tomcat", "java", "wildfly", "weblogic", "websphere", "jetty"}),
    ("/manager/html", "Tomcat Manager", "403", {"tomcat"}),
    ("/host-manager/html", "Tomcat Host Manager", "403", {"tomcat"}),
    ("/manager/status", "Tomcat server status", "403", {"tomcat"}),
    ("/examples/", "Tomcat examples", "403", {"tomcat"}),

    # ── Java — Spring Boot ──
    ("/actuator", "Spring Boot Actuator", "403", {"spring", "java", "tomcat"}),
    ("/actuator/health", "Spring Boot health endpoint", "403", {"spring", "java", "tomcat"}),
    ("/actuator/env", "Spring Boot environment", "403", {"spring", "java"}),
    ("/actuator/configprops", "Spring Boot config props", "403", {"spring", "java"}),
    ("/actuator/mappings", "Spring Boot URL mappings", "403", {"spring", "java"}),
    ("/actuator/beans", "Spring Boot beans", "403", {"spring", "java"}),
    ("/api-docs", "Swagger/OpenAPI docs", "403", {"spring", "java", "node"}),
    ("/swagger-ui.html", "Swagger UI", "403", {"spring", "java"}),
    ("/swagger-ui/", "Swagger UI (new)", "403", {"spring", "java"}),
    ("/v2/api-docs", "Swagger v2 JSON", "403", {"spring", "java"}),
    ("/v3/api-docs", "OpenAPI v3 JSON", "403", {"spring", "java"}),

    # ── Java — WebLogic ──
    ("/console/", "WebLogic admin console", "403", {"weblogic"}),
    ("/wls-wsat/", "WebLogic WSAT", "403", {"weblogic"}),
    ("/_async/", "WebLogic async servlet", "403", {"weblogic"}),

    # ── Java — JBoss / WildFly ──
    ("/admin-console/", "JBoss admin console", "403", {"wildfly"}),
    ("/jmx-console/", "JBoss JMX console", "403", {"wildfly"}),
    ("/web-console/", "JBoss web console", "403", {"wildfly"}),
    ("/invoker/JMXInvokerServlet", "JBoss JMX invoker", "403", {"wildfly"}),

    # ── Node.js / Express / Next.js ──
    ("/package.json", "Node.js package manifest", "403", {"node", "express", "deno", "next"}),
    ("/package-lock.json", "Node.js lock file", "403", {"node", "express"}),
    ("/yarn.lock", "Yarn lock file", "403", {"node", "express"}),
    ("/.npmrc", "NPM config", "403", {"node", "express"}),
    ("/node_modules/", "Node modules directory", "403", {"node", "express"}),
    ("/_next/data/", "Next.js data directory", "403", {"next", "node"}),
    ("/api/", "API endpoint", "404", {"node", "express", "next"}),
    ("/graphql", "GraphQL endpoint", "404", {"node", "express", "next", "python", "ruby", "java"}),

    # ── Python — Django ──
    ("/admin/", "Django admin", "403", {"django", "python"}),
    ("/admin/login/", "Django admin login", "403", {"django", "python"}),
    ("/__debug__/", "Django Debug Toolbar", "403", {"django", "python"}),
    ("/static/admin/", "Django admin static files", "403", {"django", "python"}),
    ("/api/schema/", "Django REST Framework schema", "403", {"django", "python"}),

    # ── Python — Flask / FastAPI ──
    ("/docs", "FastAPI Swagger docs", "403", {"python", "flask", "uvicorn", "gunicorn"}),
    ("/redoc", "FastAPI ReDoc docs", "403", {"python", "flask", "uvicorn"}),
    ("/openapi.json", "FastAPI OpenAPI spec", "403", {"python", "flask", "uvicorn"}),

    # ── Ruby — Rails ──
    ("/rails/info/properties", "Rails info page", "403", {"rails", "ruby"}),
    ("/rails/info/routes", "Rails routes", "403", {"rails", "ruby"}),
    ("/rails/mailers", "Rails mailer previews", "403", {"rails", "ruby"}),
    ("/assets/", "Rails assets pipeline", "403", {"rails", "ruby"}),
    ("/sidekiq/", "Sidekiq web UI", "403", {"rails", "ruby"}),

    # ── PHP ──
    ("/phpinfo.php", "PHP info page", "403", {"php"}),
    ("/info.php", "PHP info (alt name)", "403", {"php"}),
    ("/php-fpm-status", "PHP-FPM status", "403", {"php"}),

    # ── PHP — WordPress ──
    ("/wp-login.php", "WordPress login", "403", {"wordpress", "php"}),
    ("/wp-admin/", "WordPress admin", "403", {"wordpress", "php"}),
    ("/wp-config.php.bak", "WordPress config backup", "403", {"wordpress", "php"}),
    ("/wp-json/wp/v2/users", "WordPress REST API users", "403", {"wordpress", "php"}),
    ("/xmlrpc.php", "WordPress XML-RPC", "403", {"wordpress", "php"}),
    ("/readme.html", "WordPress readme", "403", {"wordpress", "php"}),

    # ── PHP — Laravel ──
    ("/telescope", "Laravel Telescope debugger", "403", {"php", "laravel"}),
    ("/horizon", "Laravel Horizon queue dashboard", "403", {"php", "laravel"}),
    ("/_ignition/health-check", "Laravel Ignition", "403", {"php", "laravel"}),
    ("/storage/logs/laravel.log", "Laravel log file", "403", {"php", "laravel"}),

    # ── PHP — Other CMS ──
    ("/administrator/", "Joomla admin", "403", {"php", "joomla"}),
    ("/user/login", "Drupal login", "403", {"php", "drupal"}),
    ("/admin/config/", "Drupal admin", "403", {"php", "drupal"}),
    ("/typo3/", "TYPO3 admin", "403", {"php", "typo3"}),

    # ── Go ──
    ("/debug/pprof/", "Go pprof profiler", "403", {"go", "golang"}),
    ("/debug/vars", "Go expvar debug", "403", {"go", "golang"}),

    # ── Elixir / Erlang ──
    ("/dashboard", "Phoenix LiveDashboard", "403", {"elixir", "cowboy"}),

    # ── Hosting panels ──
    ("/cpanel", "cPanel login", "403", {"cpanel"}),
    ("/whm/", "WHM admin panel", "403", {"cpanel"}),
    ("/:2083/", "cPanel HTTPS port", "403", {"cpanel"}),
    ("/plesk/", "Plesk panel", "403", {"plesk"}),
    ("/webmail/", "Webmail interface", "403", {"cpanel", "plesk"}),

    # ── CI/CD / DevOps (common misconfigs) ──
    ("/.github/workflows/", "GitHub Actions workflows", "403", None),
    ("/.gitlab-ci.yml", "GitLab CI config", "403", None),
    ("/Dockerfile", "Docker build file", "403", None),
    ("/docker-compose.yml", "Docker Compose config", "403", None),
    ("/.dockerenv", "Docker environment marker", "403", None),

    # ── Backup / config leak (generic) ──
    ("/backup.zip", "Backup archive", "403", None),
    ("/backup.sql", "Database backup", "403", None),
    ("/dump.sql", "Database dump", "403", None),
    ("/config.yml", "YAML config file", "403", None),
    ("/config.json", "JSON config file", "403", None),
    ("/composer.json", "PHP Composer manifest", "403", {"php"}),
    ("/composer.lock", "PHP Composer lock", "403", {"php"}),
    ("/Gemfile", "Ruby Gemfile", "403", {"ruby", "rails"}),
    ("/Gemfile.lock", "Ruby Gemfile lock", "403", {"ruby", "rails"}),
    ("/requirements.txt", "Python requirements", "403", {"python"}),
    ("/Pipfile", "Python Pipfile", "403", {"python"}),
    ("/pom.xml", "Maven POM", "403", {"java"}),
    ("/build.gradle", "Gradle build file", "403", {"java"}),
    ("/go.mod", "Go module file", "403", {"go", "golang"}),
    ("/Cargo.toml", "Rust Cargo manifest", "403", {"rust"}),

    # ── Generic error triggers ──
    ("/%00", "Null byte in URL", "500", None),
    ("/%%", "Double percent encoding", "500", None),

    # ── WAF trigger payloads (always probed, including SaaS) ──
    # All payloads as query parameters — path-based payloads cause false 404s
    ("/?id=1'+OR+1=1--", "SQL injection probe", "waf", None),
    ("/?q=<script>alert(1)</script>", "XSS probe", "waf", None),
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
# NOTE: reverse proxies (nginx, openresty, etc.) are handled separately in
# _PROXY_SERVERS — they probe everything since the backend is unknown.
_SERVER_TECH_MAP = {
    # ── Web servers ──
    "apache": {"apache"}, "litespeed": {"litespeed"},
    "nginx": {"nginx"}, "openresty": {"openresty", "nginx"},
    "microsoft-iis": {"iis", "asp.net"}, "microsoft-httpapi": {"iis", "asp.net"},
    "caddy": {"caddy"},
    "cherokee": {"apache"},  # Cherokee behaves like Apache
    "hiawatha": {"apache"},  # Hiawatha behaves like Apache

    # ── Java (note: "apache tomcat" must not trigger apache httpd probes) ──
    "apache tomcat": {"tomcat", "java"}, "tomcat": {"tomcat", "java"},
    "jetty": {"jetty", "java"},
    "wildfly": {"wildfly", "java"}, "jboss": {"wildfly", "java"},
    "weblogic": {"weblogic", "java"}, "websphere": {"websphere", "java"},
    "glassfish": {"java"}, "payara": {"java"},
    "resin": {"java"},  # Caucho Resin
    "undertow": {"wildfly", "java"},  # WildFly/Undertow
    "spring": {"spring", "java"},

    # ── Python ──
    "gunicorn": {"gunicorn", "python"}, "uvicorn": {"uvicorn", "python"},
    "waitress": {"waitress", "python"}, "daphne": {"python", "django"},
    "werkzeug": {"python", "flask"}, "hypercorn": {"python"},
    "twisted": {"python"}, "tornado": {"python"},
    "cherrypy": {"python"},

    # ── Ruby ──
    "puma": {"puma", "ruby", "rails"}, "thin": {"ruby", "rails"},
    "passenger": {"passenger", "ruby"},
    "webrick": {"ruby"},  # Ruby stdlib server

    # ── Node.js ──
    "express": {"express", "node"}, "deno": {"deno", "node"},
    "next.js": {"next", "node"}, "koa": {"node"},
    "hapi": {"node"}, "fastify": {"node"},

    # ── Go ──
    "fasthttp": {"go", "golang"},

    # ── Elixir / Erlang ──
    "cowboy": {"cowboy", "elixir"},
    "bandit": {"elixir"},  # Bandit (Elixir)

    # ── Rust ──
    "actix-web": {"rust"}, "hyper": {"rust"},
    "warp": {"rust"}, "axum": {"rust"},

    # ── .NET ──
    "kestrel": {"asp.net"}, "microsoft-kestrel": {"asp.net"},

    # ── PHP-specific headers ──
    "php": {"php"},  # X-Powered-By: PHP/8.x

    # ── CMS detection (from headers/body in other modules, but map here too) ──
    "wordpress": {"wordpress", "php"}, "drupal": {"drupal", "php"},
    "joomla": {"joomla", "php"}, "typo3": {"typo3", "php"},
    "laravel": {"laravel", "php"},
    "magento": {"php"},  # Magento e-commerce

    # ── Hosting panels ──
    "cpanel": {"cpanel"}, "plesk": {"plesk"},
    "directadmin": {"cpanel"},  # Similar probe set
    "cwpsrv": {"cpanel"},  # CentOS Web Panel

    # ── SaaS server headers (trigger SaaS detection) ──
    "pepyaka": {"wix"}, "squarespace": {"squarespace"},
    "shopify": {"shopify"},

    # ── Proxies / LBs (empty set = handled by _PROXY_SERVERS logic) ──
    "envoy": set(), "istio-envoy": set(), "haproxy": set(),
    "varnish": set(), "traefik": set(),
    "tengine": {"nginx"},  # Alibaba nginx fork — treat as proxy
    "kong": set(),  # Kong API gateway
    "apisix": set(),  # Apache APISIX gateway
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
    _PROXY_SERVERS = {
        "nginx", "openresty", "caddy", "envoy", "istio-envoy",
        "haproxy", "traefik", "varnish", "tengine",
        "kong", "apisix",  # API gateways
    }
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
    """Fetch a single probe path and return response data.

    On redirects (301/302/307/308): checks if the payload is preserved in the
    Location header. If preserved, follows the redirect to get the final status
    (the WAF may block after redirect). If stripped, returns the redirect as-is
    with redirect_payload_stripped=True.
    """
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
        body = resp.text[:100000]

        result = {
            "url": probe_url,
            "status": resp.status_code,
            "headers": headers,
            "cookies": cookies,
            "body": body,
        }

        # On redirect: check if payload is preserved and follow if so
        if resp.status_code in (301, 302, 307, 308):
            location = headers.get("location", headers.get("Location", ""))
            # Extract the "dangerous" part of the path (query string or path payload)
            from urllib.parse import urlparse, parse_qs
            original = urlparse(probe_url)
            payload_parts = []
            if original.query:
                payload_parts.append(original.query)
            # Check path-based payloads (e.g. /<script>)
            dangerous_path_chars = {"'", '"', "<", ">", ";", "|", ".."}
            if any(c in original.path for c in dangerous_path_chars):
                payload_parts.append(original.path)

            if location and payload_parts:
                loc_lower = location.lower()
                payload_preserved = any(p.lower() in loc_lower for p in payload_parts)
                result["redirect_location"] = location
                result["redirect_payload_preserved"] = payload_preserved

                if payload_preserved:
                    # Payload kept in redirect — follow to see if WAF blocks after redirect
                    try:
                        follow_kw = dict(client_kwargs)
                        follow_kw["follow_redirects"] = True
                        with httpx.Client(**follow_kw) as client2:
                            resp2 = client2.get(probe_url)
                        result["final_status"] = resp2.status_code
                        result["final_url"] = str(resp2.url)
                        # Use the final status for WAF analysis
                        result["status"] = resp2.status_code
                        result["headers"] = dict(resp2.headers)
                        result["body"] = resp2.text[:100000]
                    except Exception:
                        pass  # keep original redirect status
                else:
                    result["redirect_payload_stripped"] = True

        return result
    except Exception as e:
        return {"url": probe_url, "error": str(e)}


def _detect_error_server(status, headers, body, probe_path=""):
    """Identify the server software from error page signatures."""
    server = headers.get("server", headers.get("Server", ""))
    detections = []

    body_lower = body.lower() if body else ""

    # Strip reflected probe path from body to prevent false positives
    # (e.g. captcha redirects that embed the original URL in the response)
    if probe_path and body_lower:
        # Remove URL-encoded and raw variants of the probe path
        from urllib.parse import quote
        for variant in (probe_path.lower(), quote(probe_path, safe="").lower()):
            body_lower = body_lower.replace(variant, "")

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
    # Apache default error pages (no version) — detect by HTML structure
    # <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"> + "Forbidden" / "Not Found"
    elif (re.search(r'<!doctype html public.*ietf.*html 2\.0', body_lower) and
          re.search(r'<h1>(forbidden|not found)</h1>', body_lower) and
          "you don't have permission" in body_lower or "the requested url was not found" in body_lower):
        detections.append(("Apache", "", "error page structure"))

    # Nginx error page signatures
    if re.search(r"<center>nginx/[\d.]+</center>", body_lower):
        m = re.search(r"<center>(nginx/[\d.]+)</center>", body_lower)
        if m:
            detections.append(("Nginx", m.group(1), "error page"))
    elif re.search(r"<hr><center>nginx</center>", body_lower):
        detections.append(("Nginx", "", "error page"))

    # IIS error page signatures — use specific patterns to avoid false positives
    # (e.g. "iis" as substring in base64/encoded content)
    if re.search(r"microsoft-iis/([\d.]+)", body_lower):
        m = re.search(r"microsoft-iis/([\d.]+)", body_lower)
        detections.append(("Microsoft IIS", m.group(1), "error page"))
    elif "internet information services" in body_lower:
        m = re.search(r"internet information services.*([\d.]+)", body_lower)
        ver = m.group(1) if m else ""
        detections.append(("Microsoft IIS", ver, "error page"))
    elif re.search(r"<title>.*iis\b.*error", body_lower):
        detections.append(("Microsoft IIS", "", "error page title"))
    if "detailed error" in body_lower and re.search(r"\biis\b", body_lower):
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

    # Cato Networks SASE (corporate proxy/VPN that intercepts traffic)
    if "cato_variables" in body_lower or "cato networks" in body_lower:
        detections.append(("Cato Networks SASE", "", "block page"))

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
        server_leaks = _detect_error_server(status, resp["headers"], resp["body"], path)
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
