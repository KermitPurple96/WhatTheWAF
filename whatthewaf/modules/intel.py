"""Contextual intelligence — enrich scan results with actionable insights.

Uses all detected signals (WAF, server header, CNAME, ASN, error pages)
to build a human-readable picture of what the target stack is and what it means.
"""

import re

# ── WAF/CDN knowledge base ──
# Each entry: desc, strengths (what it typically blocks well),
# weaknesses (common gaps), notes (practical tips)
WAF_INTEL = {
    "Cloudflare": {
        "desc": "CDN + WAF + DDoS protection (reverse proxy)",
        "strengths": ["SQLi", "XSS", "RCE", "DDoS", "bot detection"],
        "weaknesses": ["Free plan has limited WAF rules", "origin IP leak via DNS history/certs"],
        "notes": "Proxies all traffic. Origin IP exposure = full bypass. Check --ip auto.",
    },
    "Akamai": {
        "desc": "Enterprise CDN + WAF (Kona Site Defender / App & API Protector)",
        "strengths": ["SQLi", "XSS", "RCE", "bot management", "API protection"],
        "weaknesses": ["complex rule config leads to gaps", "custom rules may miss edge cases"],
        "notes": "Enterprise-grade. Bypass usually requires origin IP or rule misconfiguration.",
    },
    "AWS CloudFront": {
        "desc": "CDN only (no WAF unless paired with AWS WAF)",
        "strengths": ["caching", "DDoS absorption (Shield)"],
        "weaknesses": ["no WAF rules by default", "just a CDN without AWS WAF"],
        "notes": "CloudFront alone does NOT filter attacks. Check if AWS WAF is also present.",
    },
    "AWS WAF": {
        "desc": "Cloud WAF (rule-based, often behind CloudFront/ALB)",
        "strengths": ["SQLi", "XSS", "rate limiting", "geo-blocking", "custom rules"],
        "weaknesses": ["depends entirely on configured rules", "no rules = no protection"],
        "notes": "Protection quality varies wildly — some deployments have minimal rules.",
    },
    "AWS ELB": {
        "desc": "Load balancer, not a WAF (ALB/NLB/CLB)",
        "strengths": ["load distribution", "SSL termination"],
        "weaknesses": ["no attack filtering", "not a security product"],
        "notes": "ELB does NOT filter attacks. It's infrastructure, not protection.",
    },
    "Fastly": {
        "desc": "CDN + Next-Gen WAF (formerly Signal Sciences)",
        "strengths": ["SQLi", "XSS", "RCE", "account takeover", "API abuse"],
        "weaknesses": ["WAF is optional add-on", "CDN-only deploys have no WAF rules"],
        "notes": "Fastly CDN != Fastly WAF. If attacks pass, WAF module may not be enabled.",
    },
    "Sucuri": {
        "desc": "Cloud WAF + CDN (website firewall, popular with WordPress)",
        "strengths": ["SQLi", "XSS", "RCE", "brute force", "virtual patching"],
        "weaknesses": ["origin IP often discoverable", "DNS history leaks"],
        "notes": "Reverse proxy. Origin IP = full bypass. Common on WordPress sites.",
    },
    "Imperva Incapsula": {
        "desc": "Enterprise cloud WAF + CDN + DDoS (Imperva Cloud WAF)",
        "strengths": ["SQLi", "XSS", "RCE", "bot mitigation", "API security"],
        "weaknesses": ["complex config", "custom rules may have gaps"],
        "notes": "Enterprise-grade. Look for origin IP leaks or subdomain misconfigs.",
    },
    "ModSecurity": {
        "desc": "Open-source WAF engine (Apache/Nginx module)",
        "strengths": ["depends on ruleset — OWASP CRS covers SQLi/XSS/RCE"],
        "weaknesses": ["often misconfigured", "partial rulesets common", "performance tuning disables rules"],
        "notes": "Only as good as its rules. Check which attack categories are actually blocked.",
    },
    "ModSecurity OWASP CRS": {
        "desc": "ModSecurity with OWASP Core Rule Set — comprehensive open-source WAF rules",
        "strengths": ["SQLi", "XSS", "RCE", "LFI", "scanner detection"],
        "weaknesses": ["paranoia level 1 misses advanced payloads", "often tuned down to avoid false positives"],
        "notes": "CRS paranoia level matters: PL1 = basic, PL4 = strict. Most run PL1-2.",
    },
    "F5 BIG-IP": {
        "desc": "Enterprise load balancer + WAF (Application Security Manager)",
        "strengths": ["SQLi", "XSS", "protocol compliance", "bot detection"],
        "weaknesses": ["ASM is optional module", "BIG-IP without ASM = no WAF"],
        "notes": "BIG-IP is a load balancer. WAF requires ASM/Advanced WAF license.",
    },
    "Wordfence": {
        "desc": "WordPress WAF plugin (application-level, not network)",
        "strengths": ["WordPress-specific attacks", "brute force", "known exploit signatures"],
        "weaknesses": ["free version has delayed rules (30 days)", "no protection for non-WP paths"],
        "notes": "Plugin-level WAF — runs inside PHP. Bypassed if origin is accessed directly.",
    },
    "Cloudflare": {
        "desc": "CDN + WAF + DDoS protection (reverse proxy)",
        "strengths": ["SQLi", "XSS", "RCE", "DDoS", "bot detection"],
        "weaknesses": ["Free plan has limited WAF rules", "origin IP leak via DNS history/certs"],
        "notes": "Proxies all traffic. Origin IP exposure = full bypass. Check --ip auto.",
    },
    "DDoS-Guard": {
        "desc": "Russian DDoS protection + CDN (reverse proxy)",
        "strengths": ["DDoS mitigation", "basic WAF rules"],
        "weaknesses": ["WAF rules are basic", "limited attack coverage compared to enterprise WAFs"],
        "notes": "Primarily DDoS protection. WAF capabilities are minimal.",
    },
    "Google Cloud Armor": {
        "desc": "Google Cloud WAF (works with Cloud Load Balancing)",
        "strengths": ["SQLi", "XSS", "LFI", "RCE", "preconfigured OWASP rules"],
        "weaknesses": ["requires explicit rule configuration", "default policies may be permissive"],
        "notes": "Only active if rules are configured. Check if managed rules are enabled.",
    },
    "Varnish": {
        "desc": "HTTP cache/reverse proxy — NOT a WAF",
        "strengths": ["caching", "performance"],
        "weaknesses": ["no attack filtering", "not a security product"],
        "notes": "Varnish is a cache layer. It does not inspect or block attacks.",
    },
    "StackPath": {
        "desc": "CDN + WAF + DDoS (edge security platform)",
        "strengths": ["SQLi", "XSS", "DDoS", "bot management"],
        "weaknesses": ["WAF rules depend on plan/config"],
        "notes": "Similar model to Cloudflare. Origin IP = bypass.",
    },
    "Citrix NetScaler": {
        "desc": "Enterprise ADC + WAF (Citrix Application Firewall)",
        "strengths": ["SQLi", "XSS", "CSRF", "cookie tampering", "protocol enforcement"],
        "weaknesses": ["complex config", "WAF is optional module"],
        "notes": "AppFW must be explicitly enabled and configured on NetScaler.",
    },
    "Barracuda WAF": {
        "desc": "Dedicated WAF appliance / cloud WAF",
        "strengths": ["SQLi", "XSS", "CSRF", "data leak prevention"],
        "weaknesses": ["signature-based", "custom encoding bypasses possible"],
        "notes": "Hardware or cloud WAF. Check for encoding bypass opportunities.",
    },
    "FortiWeb": {
        "desc": "Fortinet WAF (hardware appliance / VM / cloud)",
        "strengths": ["SQLi", "XSS", "bot detection", "API protection"],
        "weaknesses": ["depends on security profile config"],
        "notes": "Enterprise WAF. Quality depends on configured security profiles.",
    },
    "Wallarm": {
        "desc": "API security platform + WAF (AI-based detection)",
        "strengths": ["API attacks", "SQLi", "XSS", "behavioral analysis"],
        "weaknesses": ["AI detection can have blind spots"],
        "notes": "Modern API-focused WAF. May miss traditional web attack variants.",
    },
    "Reblaze": {
        "desc": "Cloud WAF + bot management + DDoS",
        "strengths": ["SQLi", "XSS", "bot detection", "behavioral analysis"],
        "weaknesses": ["origin IP exposure = bypass"],
        "notes": "Reverse proxy model. Same bypass approach as Cloudflare.",
    },
    "PerimeterX": {
        "desc": "Bot management platform (now HUMAN Security)",
        "strengths": ["bot detection", "credential stuffing", "scraping prevention"],
        "weaknesses": ["focused on bots, not traditional WAF attacks"],
        "notes": "Bot protection, not a WAF. SQLi/XSS may not be filtered.",
    },
    "Zscaler": {
        "desc": "Cloud security proxy (ZTNA / secure web gateway)",
        "strengths": ["URL filtering", "malware inspection", "DLP"],
        "weaknesses": ["outbound proxy, not inbound WAF"],
        "notes": "Zscaler protects outbound traffic (users). It's not a website WAF.",
    },
    "Apache Generic": {
        "desc": "Apache web server with basic access controls (not a WAF)",
        "strengths": ["file access control (.htaccess Deny rules)", "directory listing prevention"],
        "weaknesses": ["no attack payload inspection", "no SQLi/XSS/RCE filtering"],
        "notes": "Server-level config only. 403 on .env/.git = good hygiene, but attacks reach the app.",
    },
    "Nginx Generic": {
        "desc": "Nginx web server (not a WAF)",
        "strengths": ["file access control", "rate limiting (if configured)"],
        "weaknesses": ["no attack payload inspection by default"],
        "notes": "Web server, not a WAF. May have basic location blocks but no attack filtering.",
    },
    "LiteSpeed": {
        "desc": "LiteSpeed web server (not a WAF, but has basic ModSecurity compat)",
        "strengths": ["file access control", "optional ModSecurity compatibility"],
        "weaknesses": ["ModSecurity rules must be explicitly loaded"],
        "notes": "Check if ModSecurity rules are active. LiteSpeed alone = just a web server.",
    },
}

# ── Server header → platform mapping ──
# Maps known Server header values to (name, description)
# Ordered: more specific patterns first to avoid partial matches
SERVER_PLATFORMS = {
    # SaaS (provider-hosted)
    "pepyaka": ("Wix", "SaaS website builder — provider-hosted"),
    "squarespace": ("Squarespace", "SaaS website builder — provider-hosted"),
    "shopify": ("Shopify", "E-commerce SaaS — provider-hosted"),
    # CDN / WAF / Proxy
    "cloudflare": ("Cloudflare", "Cloudflare reverse proxy"),
    "akamaighost": ("Akamai", "Akamai Ghost CDN edge"),
    "netlify": ("Netlify", "Jamstack CDN + hosting"),
    "trailer park": ("Netlify", "Netlify CDN edge"),
    "vercel": ("Vercel", "Jamstack CDN + edge functions"),
    # Load balancers / Proxies
    "bigip": ("F5 BIG-IP", "F5 load balancer / ADC"),
    "awselb": ("AWS ELB", "AWS Elastic Load Balancer"),
    "envoy": ("Envoy Proxy", "Cloud-native proxy (Kubernetes / service mesh)"),
    "istio-envoy": ("Istio/Envoy", "Kubernetes service mesh proxy"),
    "haproxy": ("HAProxy", "TCP/HTTP load balancer"),
    "traefik": ("Traefik", "Cloud-native reverse proxy"),
    "varnish": ("Varnish", "HTTP cache / reverse proxy"),
    # Web servers
    "openresty": ("OpenResty", "Nginx + Lua — custom CDN/API/WAF setups"),
    "tengine": ("Tengine", "Alibaba's Nginx fork — Alibaba Cloud"),
    "caddy": ("Caddy", "Modern Go web server with automatic HTTPS"),
    "litespeed": ("LiteSpeed", "LiteSpeed web server"),
    # Google
    "gws": ("Google Web Server", "Google-served content"),
    "gse": ("Google Servlet Engine", "Google App Engine"),
    # Python
    "gunicorn": ("Gunicorn", "Python WSGI — Django/Flask app"),
    "uvicorn": ("Uvicorn", "Python ASGI — FastAPI/Starlette app"),
    "waitress": ("Waitress", "Python WSGI — Pyramid/Flask app"),
    "daphne": ("Daphne", "Python ASGI — Django Channels"),
    "werkzeug": ("Werkzeug", "Python WSGI toolkit — Flask debug server"),
    "hypercorn": ("Hypercorn", "Python ASGI server"),
    # Ruby
    "phusion passenger": ("Passenger", "Ruby/Node.js app server"),
    "puma": ("Puma", "Ruby HTTP server — Rails app"),
    "thin": ("Thin", "Ruby HTTP server"),
    "unicorn": ("Unicorn", "Ruby HTTP server — Rails app"),
    # Node.js
    "express": ("Express.js", "Node.js web framework"),
    "deno": ("Deno", "Deno runtime — TypeScript/JavaScript"),
    "next.js": ("Next.js", "React SSR framework — Node.js"),
    # Elixir / Erlang
    "cowboy": ("Cowboy", "Erlang/Elixir HTTP server — Phoenix framework"),
    # .NET
    "kestrel": ("Kestrel", "ASP.NET Core server"),
    "microsoft-httpapi": ("HTTP.sys", "Windows HTTP server — .NET / IIS kernel driver"),
    # Java
    "jetty": ("Jetty", "Java servlet container"),
    "wildfly": ("WildFly", "Java EE app server (formerly JBoss)"),
    "jboss": ("JBoss/WildFly", "Java EE app server"),
    "weblogic": ("Oracle WebLogic", "Java EE app server"),
    "websphere": ("IBM WebSphere", "Java EE app server"),
    "tomcat": ("Apache Tomcat", "Java servlet container"),
    "glassfish": ("GlassFish", "Java EE app server"),
    "payara": ("Payara", "Java EE app server (GlassFish fork)"),
    # Go
    "fasthttp": ("FastHTTP", "Go HTTP server"),
    # Hosting panels
    "cpanel": ("cPanel", "Web hosting control panel"),
    "plesk": ("Plesk", "Web hosting control panel"),
    "directadmin": ("DirectAdmin", "Web hosting control panel"),
    "cwpsrv": ("CentOS Web Panel", "Server management panel"),
}

# ── CNAME → platform mapping ──
# (keyword_in_cname, name, description, hosting_type)
# hosting_type: "saas" = provider-hosted, "paas" = customer deploys code,
#               "cdn" = proxy layer, "hosting" = managed hosting
CNAME_PLATFORMS = {
    # SaaS (provider-hosted — customer has no server access)
    "wixdns": ("Wix", "SaaS website builder"),
    "squarespace": ("Squarespace", "SaaS website builder"),
    "shopify": ("Shopify", "E-commerce SaaS"),
    "myshopify": ("Shopify", "E-commerce SaaS"),
    "bigcommerce": ("BigCommerce", "E-commerce SaaS"),
    "wordpress.com": ("WordPress.com", "Managed WordPress (Automattic)"),
    "ghost.io": ("Ghost Pro", "Managed Ghost hosting"),
    "hubspot": ("HubSpot", "Marketing SaaS"),
    "unbounce": ("Unbounce", "Landing page SaaS"),
    "webflow.io": ("Webflow", "SaaS website builder"),
    "tilda.ws": ("Tilda", "SaaS website builder"),
    "strikingly": ("Strikingly", "SaaS website builder"),
    "zendesk.com": ("Zendesk", "Support SaaS"),
    "freshdesk.com": ("Freshdesk", "Support SaaS"),
    # PaaS (customer deploys code — file access probes ARE relevant)
    "herokuapp": ("Heroku", "PaaS — customer deploys code"),
    "vercel": ("Vercel", "Jamstack PaaS — customer deploys code"),
    "netlify": ("Netlify", "Jamstack PaaS — customer deploys code"),
    "azurewebsites": ("Azure App Service", "Microsoft PaaS"),
    "appspot": ("Google App Engine", "Google PaaS"),
    "onrender": ("Render", "PaaS — customer deploys code"),
    "railway.app": ("Railway", "PaaS — customer deploys code"),
    "fly.dev": ("Fly.io", "PaaS — edge compute"),
    # Static hosting (customer deploys files — .env/.git ARE relevant)
    "github.io": ("GitHub Pages", "Static hosting"),
    "gitlab.io": ("GitLab Pages", "Static hosting"),
    "firebaseapp": ("Firebase", "Google Firebase hosting"),
    "pages.dev": ("Cloudflare Pages", "Static hosting + CDN"),
    "surge.sh": ("Surge", "Static hosting"),
    # Managed WordPress hosting (customer controls WP — file probes relevant)
    "wpengine": ("WP Engine", "Managed WordPress hosting"),
    "pantheon": ("Pantheon", "Managed Drupal/WordPress hosting"),
    "kinsta": ("Kinsta", "Managed WordPress hosting"),
    "pressable": ("Pressable", "Managed WordPress hosting"),
    "flywheel": ("Flywheel", "Managed WordPress hosting"),
    # CDN / WAF (proxy layer — not the origin)
    "cloudfront": ("AWS CloudFront", "CDN"),
    "fastly": ("Fastly", "CDN/WAF"),
    "incapsula": ("Imperva", "Cloud WAF"),
    "sucuri": ("Sucuri", "Cloud WAF"),
    "edgekey": ("Akamai", "CDN/WAF edge"),
    "akamaiedge": ("Akamai", "CDN/WAF edge"),
    "cdn77": ("CDN77", "CDN"),
    "stackpathdns": ("StackPath", "CDN/WAF"),
}


def identify_server(server_header):
    """Identify platform from Server header value. Returns (name, desc) or None."""
    if not server_header:
        return None
    server_lower = server_header.lower()
    for keyword, (name, desc) in SERVER_PLATFORMS.items():
        if keyword in server_lower:
            return (name, desc)
    return None


def identify_cname_platform(cnames):
    """Identify platform from CNAME chain. Returns (name, desc) or None."""
    if not cnames:
        return None
    cname_str = " ".join(cnames).lower()
    for keyword, (name, desc) in CNAME_PLATFORMS.items():
        if keyword in cname_str:
            return (name, desc)
    return None


def build_insights(report):
    """Build contextual insights from all scan data.

    Returns a list of insight strings, each one a concise actionable observation.
    """
    insights = []
    waf_detections = report.get("waf", [])
    waf_names = {d["name"] for d in waf_detections}
    waf_categories = {d["name"]: d["category"] for d in waf_detections}
    http = report.get("http", {})
    server_header = http.get("server", "")
    cnames = report.get("cnames", [])
    ips = report.get("ips", [])

    # 1. Identify the platform from server header + CNAME
    server_id = identify_server(server_header)
    cname_id = identify_cname_platform(cnames)
    platform = server_id or cname_id

    if platform and cname_id and server_id and server_id[0] != cname_id[0]:
        # Different platforms from server vs CNAME = interesting stack
        insights.append(
            f"Platform: {server_id[0]} ({server_id[1]}) behind {cname_id[0]} ({cname_id[1]})"
        )
    elif platform:
        insights.append(f"Platform: {platform[0]} — {platform[1]}")

    # 2. WAF-specific intel
    for name in waf_names:
        intel = WAF_INTEL.get(name)
        if not intel:
            continue
        cat = waf_categories.get(name, "")

        # Only show desc for WAFs/CDNs, not web servers (those get server hardening treatment)
        if cat in ("WAF", "CDN/WAF"):
            insights.append(f"{name}: {intel['desc']}")
        elif cat == "CDN":
            insights.append(f"{name}: {intel['desc']}")
        elif cat == "Web Server":
            insights.append(f"{name}: {intel['desc']}")

    # 3. Analyze protection gaps vs WAF capabilities
    ep = report.get("error_pages", {})
    ep_probes = ep.get("probes", [])
    passed_attacks = []
    blocked_attacks = []
    waf_trigger_statuses = {403, 406, 429, 451, 493, 503}

    for p in ep_probes:
        if p.get("error") or p.get("trigger") != "waf":
            continue
        status = p.get("status", 0)
        has_waf_hit = bool(p.get("waf_hits"))
        is_blocked = status in waf_trigger_statuses or (has_waf_hit and status not in (200, 201, 301, 302))
        if is_blocked:
            blocked_attacks.append(p["description"])
        else:
            passed_attacks.append(p["description"])

    # Check if a known WAF is present but attacks pass through
    real_wafs = [n for n in waf_names if waf_categories.get(n) in ("WAF", "CDN/WAF")]
    if real_wafs and passed_attacks:
        waf_name = real_wafs[0]
        intel = WAF_INTEL.get(waf_name)
        if intel:
            expected_strengths = intel.get("strengths", [])
            # Map attack probes to capability names
            attack_to_cap = {
                "SQL injection probe": "SQLi",
                "XSS probe": "XSS",
                "Command injection probe": "RCE",
                "Path traversal probe": "LFI",
                "PHP filter probe": "LFI",
            }
            for attack in passed_attacks:
                cap = attack_to_cap.get(attack)
                if cap and any(cap.lower() in s.lower() for s in expected_strengths):
                    insights.append(
                        f"{waf_name} should block {cap} but didn't — rules may be misconfigured or disabled"
                    )

    if real_wafs and not blocked_attacks and not passed_attacks:
        pass  # no probe data, skip
    elif real_wafs and not blocked_attacks and passed_attacks:
        insights.append(
            f"{real_wafs[0]} detected but blocking nothing — WAF may be in monitor/log-only mode"
        )

    # 4. No WAF insights
    if not real_wafs:
        server_only = [n for n in waf_names if waf_categories.get(n) == "Web Server"]
        if server_only and passed_attacks:
            insights.append(
                "No WAF — only server-level file access controls. "
                "Attack payloads reach the application directly."
            )
        elif not waf_names and not blocked_attacks:
            insights.append(
                "No WAF or CDN detected. Application is directly exposed to attacks."
            )

    # 5. CDN without WAF
    cdn_only = [n for n in waf_names if waf_categories.get(n) == "CDN"]
    for cdn in cdn_only:
        intel = WAF_INTEL.get(cdn)
        if intel and "not a WAF" in intel.get("desc", "").lower():
            insights.append(f"{cdn} is a CDN, not a WAF — no attack filtering")
        elif intel and "no waf" in intel.get("notes", "").lower():
            insights.append(f"{cdn}: {intel['notes']}")

    # 6. SaaS platform detection — explain what's reportable
    is_saas = report.get("error_pages", {}).get("is_saas", False)
    if is_saas and platform:
        insights.append(
            f"{platform[0]} is provider-hosted SaaS — server config controlled by provider. "
            "File access findings are not reportable, but WAF gaps (SQLi/XSS passing through) ARE."
        )

    # 7. Practical notes from WAF intel
    for name in real_wafs:
        intel = WAF_INTEL.get(name)
        if intel and intel.get("notes"):
            insights.append(f"{intel['notes']}")

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for i in insights:
        if i not in seen:
            seen.add(i)
            unique.append(i)

    return unique
