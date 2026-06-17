"""Infrastructure chain tracer — map every layer of the traffic path.

Reconstructs the full stack by fingerprinting each layer independently:

    Client → Cloudflare (CDN/WAF) → Varnish (cache) → nginx (reverse proxy)
           → SiteGround (hosting) → Apache/2.4 (web server) → PHP 8.1 (runtime)
           → WordPress 6.4 (CMS)

Signals used per layer:
  - DNS: CNAME chain, NS records
  - ASN/IP: provider classification
  - HTTP headers: Server, Via, X-Powered-By, X-Cache, X-Served-By, Age, etc.
  - Cookies: PHPSESSID, JSESSIONID, laravel_session, _rails_session, etc.
  - Response body: meta generator, CMS paths, framework signatures
  - Error pages: different software reveals itself on error paths
  - TLS certificate: issuer org, subject CN
  - WAF signatures: already-detected WAF/CDN
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────
#  Technology fingerprint database
# ──────────────────────────────────────────────────────────────

# Each entry: (name, layer, signals)
#   layer: cdn, waf, cache, loadbalancer, proxy, hosting, server, runtime, framework, cms
#   signals: list of (signal_type, pattern, confidence_boost)
#     signal_type: header, header_value, cookie, body, body_meta, cname, cert_issuer, cert_subject, via, server

_FINGERPRINTS: List[Tuple[str, str, List[Tuple[str, str, float]]]] = [
    # ── CDN/WAF ──────────────────────────────────────────────
    # (most CDN/WAF detection is via waf_signatures + ASN; these catch extras)
    ("Cloudflare", "cdn/waf", [
        ("header", "cf-ray", 0.9),
        ("header", "cf-cache-status", 0.8),
        ("server", "cloudflare", 0.9),
        ("cname", "cloudflare", 0.9),
        ("cert_issuer", "cloudflare", 0.7),
    ]),
    ("Akamai", "cdn/waf", [
        ("header", "x-akamai-transformed", 0.9),
        ("server", "akamaighost", 0.9),
        ("cname", "akamai", 0.9),
        ("cname", "edgekey", 0.9),
    ]),
    ("AWS CloudFront", "cdn", [
        ("header", "x-amz-cf-id", 0.9),
        ("header", "x-amz-cf-pop", 0.9),
        ("server", "cloudfront", 0.9),
        ("cname", "cloudfront", 0.9),
    ]),
    ("Fastly", "cdn", [
        ("header", "x-fastly-request-id", 0.9),
        ("header", "fastly-debug-digest", 0.8),
        ("cname", "fastly", 0.9),
    ]),
    ("Azure Front Door", "cdn/waf", [
        ("header", "x-azure-ref", 0.9),
        ("header", "x-fd-healthprobe", 0.8),
        ("cname", "azurefd", 0.9),
        ("cname", "azureedge", 0.9),
    ]),
    ("Sucuri", "waf", [
        ("header", "x-sucuri-id", 0.9),
        ("server", "sucuri", 0.9),
        ("cname", "sucuri", 0.9),
    ]),
    ("Imperva", "waf", [
        ("header", "x-iinfo", 0.9),
        ("cookie", "incap_ses_", 0.9),
        ("cookie", "visid_incap_", 0.9),
        ("cname", "incapsula", 0.9),
    ]),
    ("StackPath", "cdn/waf", [
        ("header", "x-sp-url", 0.8),
        ("header", "x-hw", 0.7),
    ]),
    ("DDoS-Guard", "waf", [
        ("server", "ddos-guard", 0.9),
        ("cookie", "__ddg", 0.8),
    ]),
    ("Edgecast", "cdn", [
        ("server", "ecs", 0.7),
        ("server", "ecacc", 0.7),
    ]),

    # ── Caching ──────────────────────────────────────────────
    ("Varnish", "cache", [
        ("header", "x-varnish", 0.9),
        ("via_contains", "varnish", 0.9),
        ("server", "varnish", 0.8),
    ]),
    ("Squid", "cache", [
        ("header", "x-squid-error", 0.9),
        ("via_contains", "squid", 0.9),
        ("server", "squid", 0.8),
    ]),
    ("Nginx Cache", "cache", [
        ("header_value", "x-cache-status", None, 0.7),  # any value = cache layer
    ]),
    ("Redis Cache", "cache", [
        ("header", "x-redis-cache", 0.8),
        ("header_value", "x-cache", "redis", 0.8),
    ]),
    ("WP Super Cache", "cache", [
        ("header", "wp-super-cache", 0.9),
        ("body", "wp-super-cache", 0.7),
    ]),
    ("W3 Total Cache", "cache", [
        ("header", "x-w3tc", 0.9),
        ("body", "w3 total cache", 0.7),
    ]),
    ("LiteSpeed Cache", "cache", [
        ("header", "x-litespeed-cache", 0.9),
        ("header_value", "x-lsadc-cache", None, 0.8),
    ]),

    # ── Load Balancers ───────────────────────────────────────
    ("HAProxy", "loadbalancer", [
        ("header", "x-haproxy-server-state", 0.9),
        ("server", "haproxy", 0.8),
        ("cookie", "SERVERID", 0.7),
    ]),
    ("AWS ALB/ELB", "loadbalancer", [
        ("cookie", "AWSALB", 0.9),
        ("cookie", "AWSALBCORS", 0.9),
        ("header", "x-amzn-trace-id", 0.7),
    ]),
    ("F5 BIG-IP", "loadbalancer", [
        ("cookie", "BIGipServer", 0.9),
        ("server", "bigip", 0.8),
        ("server", "big-ip", 0.8),
    ]),
    ("Citrix NetScaler", "loadbalancer", [
        ("cookie", "NSC_", 0.8),
        ("header", "cneonction", 0.9),
        ("header", "x-ns-id", 0.8),
    ]),
    ("Traefik", "loadbalancer", [
        ("server", "traefik", 0.9),
        ("header", "x-traefik", 0.8),
    ]),

    # ── Reverse Proxies ──────────────────────────────────────
    ("nginx", "proxy", [
        ("server", "nginx", 0.6),
        ("error_page", "nginx", 0.7),
    ]),
    ("Apache (proxy)", "proxy", [
        ("server", "apache", 0.5),
        # Lower confidence — could be origin too
    ]),
    ("Envoy", "proxy", [
        ("server", "envoy", 0.9),
        ("header", "x-envoy-upstream-service-time", 0.9),
    ]),
    ("Caddy", "proxy", [
        ("server", "caddy", 0.8),
    ]),
    ("OpenResty", "proxy", [
        ("server", "openresty", 0.8),
        ("error_page", "openresty", 0.8),
    ]),

    # ── Hosting Platforms ────────────────────────────────────
    ("SiteGround", "hosting", [
        ("header", "x-siteground", 0.9),
        ("cookie", "sg_cookies", 0.8),
        ("cert_subject", "siteground", 0.7),
        ("body", "siteground", 0.5),
    ]),
    ("WP Engine", "hosting", [
        ("header_value", "x-powered-by", "wpe", 0.9),
        ("header", "wpe-backend", 0.9),
        ("cname", "wpengine", 0.9),
    ]),
    ("Pantheon", "hosting", [
        ("header", "x-pantheon-styx-hostname", 0.9),
        ("header", "x-styx-req-id", 0.8),
        ("via_contains", "pantheon", 0.9),
        ("cname", "pantheon", 0.9),
    ]),
    ("Kinsta", "hosting", [
        ("header", "x-kinsta-cache", 0.9),
        ("cname", "kinsta", 0.9),
    ]),
    ("Flywheel", "hosting", [
        ("header", "x-fw-hash", 0.8),
        ("header", "x-fw-serve", 0.8),
        ("cname", "flywheel", 0.9),
    ]),
    ("Heroku", "hosting", [
        ("header", "x-heroku-dynos-in-use", 0.9),
        ("header", "x-heroku-queue-depth", 0.9),
        ("via_contains", "vegur", 0.9),
        ("cname", "heroku", 0.9),
    ]),
    ("Netlify", "hosting", [
        ("header", "x-nf-request-id", 0.9),
        ("server", "netlify", 0.9),
        ("cname", "netlify", 0.9),
    ]),
    ("Vercel", "hosting", [
        ("header", "x-vercel-id", 0.9),
        ("server", "vercel", 0.9),
        ("cname", "vercel", 0.9),
    ]),
    ("AWS (hosting)", "hosting", [
        ("header", "x-amz-request-id", 0.6),
        ("server", "amazons3", 0.8),
    ]),
    ("OVHcloud", "hosting", [
        ("server", "ovhcloud", 0.8),
        ("server", "ovh", 0.7),
    ]),
    ("Plesk", "hosting", [
        ("header_value", "x-powered-by", "plesk", 0.9),
        ("body", "plesk", 0.6),
    ]),
    ("cPanel", "hosting", [
        ("body", "cpanel", 0.6),
        ("header_value", "x-powered-by", "cpanel", 0.8),
    ]),
    ("Shopify", "hosting", [
        ("header", "x-shopid", 0.9),
        ("header", "x-shopify-stage", 0.9),
        ("cookie", "_shopify_", 0.9),
        ("cname", "shopify", 0.9),
    ]),

    # ── Web Servers (origin) ─────────────────────────────────
    ("Apache", "server", [
        ("error_page", "apache", 0.9),
        ("header_value", "server", "apache", 0.7),
    ]),
    ("nginx", "server", [
        ("error_page", "nginx", 0.8),
    ]),
    ("Microsoft IIS", "server", [
        ("server", "microsoft-iis", 0.9),
        ("header", "x-aspnet-version", 0.8),
        ("header_value", "x-powered-by", "asp.net", 0.8),
        ("error_page", "iis", 0.9),
    ]),
    ("LiteSpeed", "server", [
        ("server", "litespeed", 0.9),
        ("error_page", "litespeed", 0.8),
    ]),
    ("OpenResty", "server", [
        ("error_page", "openresty", 0.8),
    ]),

    # ── App Servers / Runtimes ───────────────────────────────
    ("PHP", "runtime", [
        ("header_value", "x-powered-by", "php", 0.9),
        ("cookie", "PHPSESSID", 0.9),
        ("header", "x-php-version", 0.9),
    ]),
    ("Java", "runtime", [
        ("cookie", "JSESSIONID", 0.9),
        ("error_page", "java.lang", 0.8),
        ("error_page", "javax.servlet", 0.8),
    ]),
    ("Apache Tomcat", "runtime", [
        ("server", "tomcat", 0.9),
        ("error_page", "apache tomcat", 0.9),
    ]),
    ("Jetty", "runtime", [
        ("server", "jetty", 0.9),
        ("error_page", "jetty", 0.8),
    ]),
    ("Node.js", "runtime", [
        ("header_value", "x-powered-by", "express", 0.9),
        ("cookie", "connect.sid", 0.8),
        ("error_page", "cannot get", 0.7),
        ("error_page", "rangeerror", 0.7),
    ]),
    ("Python", "runtime", [
        ("header_value", "server", "gunicorn", 0.9),
        ("header_value", "server", "uwsgi", 0.9),
        ("header_value", "server", "waitress", 0.8),
        ("header_value", "server", "daphne", 0.8),
        ("error_page", "traceback", 0.7),
    ]),
    ("Gunicorn", "runtime", [
        ("server", "gunicorn", 0.9),
    ]),
    ("uWSGI", "runtime", [
        ("server", "uwsgi", 0.9),
        ("header", "x-uwsgi", 0.8),
    ]),
    ("Phusion Passenger", "runtime", [
        ("header_value", "x-powered-by", "phusion", 0.9),
        ("server", "passenger", 0.8),
    ]),
    ("ASP.NET", "runtime", [
        ("header", "x-aspnet-version", 0.9),
        ("header_value", "x-powered-by", "asp.net", 0.9),
        ("cookie", "ASP.NET_SessionId", 0.9),
        ("error_page", "asp.net", 0.8),
    ]),
    ("Ruby", "runtime", [
        ("cookie", "_rails_session", 0.8),
        ("cookie", "rack.session", 0.8),
        ("server", "puma", 0.9),
        ("server", "unicorn", 0.8),
        ("server", "thin", 0.8),
    ]),

    # ── Frameworks ───────────────────────────────────────────
    ("Django", "framework", [
        ("cookie", "csrftoken", 0.6),
        ("cookie", "django_", 0.8),
        ("error_page", "django", 0.9),
        ("header_value", "x-frame-options", "deny", 0.3),  # Django default, low conf
    ]),
    ("Flask", "framework", [
        ("error_page", "werkzeug", 0.9),
        ("error_page", "flask", 0.8),
    ]),
    ("Laravel", "framework", [
        ("cookie", "laravel_session", 0.9),
        ("cookie", "XSRF-TOKEN", 0.5),
        ("header_value", "x-powered-by", "laravel", 0.9),
        ("error_page", "laravel", 0.8),
        ("error_page", "whoops", 0.7),
    ]),
    ("Spring Boot", "framework", [
        ("error_page", "whitelabel error page", 0.9),
        ("header", "x-application-context", 0.8),
    ]),
    ("Ruby on Rails", "framework", [
        ("cookie", "_rails_session", 0.9),
        ("header", "x-runtime", 0.6),
        ("header", "x-request-id", 0.3),
        ("error_page", "action_controller", 0.9),
        ("error_page", "routing error", 0.8),
    ]),
    ("Express.js", "framework", [
        ("header_value", "x-powered-by", "express", 0.9),
        ("error_page", "cannot get", 0.7),
    ]),
    ("Next.js", "framework", [
        ("header", "x-nextjs-page", 0.9),
        ("header", "x-nextjs-cache", 0.9),
        ("header_value", "x-powered-by", "next.js", 0.9),
        ("body", "__NEXT_DATA__", 0.9),
        ("body", "_next/static", 0.8),
    ]),
    ("Nuxt.js", "framework", [
        ("body", "__NUXT__", 0.9),
        ("body", "_nuxt/", 0.8),
    ]),
    ("ColdFusion", "framework", [
        ("cookie", "CFID", 0.9),
        ("cookie", "CFTOKEN", 0.9),
        ("error_page", "coldfusion", 0.9),
    ]),

    # ── CMS ──────────────────────────────────────────────────
    ("WordPress", "cms", [
        ("body", "wp-content/", 0.9),
        ("body", "wp-includes/", 0.9),
        ("body_meta", "wordpress", 0.9),
        ("cookie", "wordpress_", 0.8),
        ("cookie", "wp-settings-", 0.8),
        ("header", "x-pingback", 0.7),
        ("body", "wp-json", 0.7),
    ]),
    ("Drupal", "cms", [
        ("header", "x-drupal-cache", 0.9),
        ("header", "x-drupal-dynamic-cache", 0.9),
        ("header_value", "x-generator", "drupal", 0.9),
        ("body", "sites/default/files", 0.8),
        ("body_meta", "drupal", 0.9),
        ("cookie", "Drupal.", 0.8),
    ]),
    ("Joomla", "cms", [
        ("body_meta", "joomla", 0.9),
        ("body", "/media/jui/", 0.8),
        ("cookie", "joomla_", 0.7),
    ]),
    ("Magento", "cms", [
        ("cookie", "mage-cache", 0.9),
        ("cookie", "form_key", 0.6),
        ("body", "mage/cookies", 0.8),
        ("body", "Magento_", 0.7),
    ]),
    ("Shopify CMS", "cms", [
        ("body", "cdn.shopify.com", 0.9),
        ("body", "Shopify.theme", 0.8),
    ]),
    ("Wix", "cms", [
        ("header", "x-wix-request-id", 0.9),
        ("body", "wix.com", 0.7),
        ("cname", "wix", 0.9),
    ]),
    ("Squarespace", "cms", [
        ("server", "squarespace", 0.9),
        ("body", "squarespace", 0.7),
        ("cname", "squarespace", 0.9),
    ]),
    ("Ghost", "cms", [
        ("header_value", "x-powered-by", "ghost", 0.9),
        ("body", "ghost-", 0.6),
    ]),
    ("Webflow", "cms", [
        ("server", "webflow", 0.9),
        ("body", "webflow", 0.6),
    ]),
    ("PrestaShop", "cms", [
        ("body", "prestashop", 0.8),
        ("cookie", "PrestaShop-", 0.9),
    ]),
]

# Layer ordering (outermost → innermost)
LAYER_ORDER = [
    "cdn", "cdn/waf", "waf",
    "cache",
    "loadbalancer",
    "proxy",
    "hosting",
    "server",
    "runtime",
    "framework",
    "cms",
]


# ──────────────────────────────────────────────────────────────
#  Core tracer
# ──────────────────────────────────────────────────────────────

def trace_infra(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build an ordered infrastructure chain from scan report data.

    Returns list of nodes ordered outermost → innermost, each with:
        name, layer, confidence, evidence
    """
    detections: Dict[str, Dict[str, Any]] = {}  # name → {layer, confidence, evidence[]}

    # Gather all signal sources from the report
    headers = report.get("http", {}).get("headers", {})
    cookies = report.get("http", {}).get("cookies", [])
    body = report.get("http", {}).get("body", "")
    server_hdr = report.get("http", {}).get("server", "")
    cnames = report.get("cnames", [])
    error_pages = report.get("error_pages", {})
    cert = report.get("tls_fingerprint", {}).get("certificate", {})
    waf_dets = report.get("waf", [])
    ips = report.get("ips", [])

    cookie_str = "\n".join(cookies).lower() if cookies else ""
    body_lower = body.lower()[:50000] if body else ""
    cname_str = " ".join(cnames).lower()

    # Collect error page bodies and headers for deeper analysis
    error_servers = set()
    error_bodies = ""
    error_headers_all = {}
    error_cookies_all = ""
    for probe in error_pages.get("probes", []):
        srv = probe.get("server", "")
        if srv:
            error_servers.add(srv.lower())
        # Error page headers
        probe_hdrs = probe.get("headers", {})
        for k, v in probe_hdrs.items() if isinstance(probe_hdrs, dict) else []:
            if k.lower() not in error_headers_all:
                error_headers_all[k.lower()] = v

    for leak in error_pages.get("server_leaks", []):
        name = leak.get("name", "").lower()
        ver = leak.get("version", "")
        if name:
            error_bodies += f" {name} {ver}"

    # Via header parsing
    via_str = _hdr(headers, "via") or ""
    # Also check error page Via headers
    via_error = error_headers_all.get("via", "")

    # ─── Run fingerprint matching ───
    for tech_name, layer, signals in _FINGERPRINTS:
        score = 0.0
        evidence = []

        for signal in signals:
            sig_type = signal[0]
            match = False
            conf = signal[-1]  # confidence is always last

            if sig_type == "header":
                # Header exists (any value)
                pattern = signal[1]
                if _hdr(headers, pattern) is not None or pattern.lower() in error_headers_all:
                    match = True
                    val = _hdr(headers, pattern) or error_headers_all.get(pattern.lower(), "")
                    evidence.append(f"header:{pattern}={val[:50]}")

            elif sig_type == "header_value":
                # Header exists with specific value
                hdr_name = signal[1]
                hdr_pattern = signal[2]
                val = _hdr(headers, hdr_name) or error_headers_all.get(hdr_name.lower(), "")
                if val:
                    if hdr_pattern is None:
                        match = True
                        evidence.append(f"header:{hdr_name}={val[:50]}")
                    elif hdr_pattern.lower() in val.lower():
                        match = True
                        evidence.append(f"header:{hdr_name}={val[:50]}")

            elif sig_type == "server":
                pattern = signal[1]
                if pattern.lower() in server_hdr.lower():
                    match = True
                    evidence.append(f"server:{server_hdr}")
                elif any(pattern.lower() in s for s in error_servers):
                    match = True
                    evidence.append(f"error-page-server:{pattern}")

            elif sig_type == "cookie":
                pattern = signal[1]
                if re.search(pattern, cookie_str, re.IGNORECASE):
                    match = True
                    evidence.append(f"cookie:{pattern}")

            elif sig_type == "body":
                pattern = signal[1]
                if pattern.lower() in body_lower:
                    match = True
                    evidence.append(f"body:{pattern}")

            elif sig_type == "body_meta":
                # <meta name="generator" content="...">
                pattern = signal[1]
                meta_match = re.search(
                    r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']',
                    body_lower, re.IGNORECASE
                )
                if meta_match and pattern.lower() in meta_match.group(1).lower():
                    match = True
                    evidence.append(f"meta-generator:{meta_match.group(1)[:50]}")

            elif sig_type == "cname":
                pattern = signal[1]
                if pattern.lower() in cname_str:
                    match = True
                    matching_cname = next((c for c in cnames if pattern.lower() in c.lower()), "")
                    evidence.append(f"cname:{matching_cname}")

            elif sig_type == "via_contains":
                pattern = signal[1]
                combined_via = f"{via_str} {via_error}".lower()
                if pattern.lower() in combined_via:
                    match = True
                    evidence.append(f"via:{pattern}")

            elif sig_type == "error_page":
                pattern = signal[1]
                if pattern.lower() in error_bodies.lower():
                    match = True
                    evidence.append(f"error-page:{pattern}")

            elif sig_type == "cert_issuer":
                pattern = signal[1]
                issuer = (cert.get("issuer", "") + " " + cert.get("issuer_org", "")).lower()
                if pattern.lower() in issuer:
                    match = True
                    evidence.append(f"cert-issuer:{cert.get('issuer', '')}")

            elif sig_type == "cert_subject":
                pattern = signal[1]
                subject = cert.get("subject", "").lower()
                if pattern.lower() in subject:
                    match = True
                    evidence.append(f"cert-subject:{cert.get('subject', '')}")

            if match:
                score += conf

        if evidence:
            key = tech_name
            # If we already have this tech, merge evidence and take max confidence
            if key in detections:
                detections[key]["confidence"] = max(detections[key]["confidence"], min(score, 1.0))
                detections[key]["evidence"].extend(evidence)
            else:
                detections[key] = {
                    "name": tech_name,
                    "layer": layer,
                    "confidence": min(score, 1.0),
                    "evidence": evidence,
                }

    # ─── Inject WAF detections not already caught ───
    for det in waf_dets:
        cat = det.get("category", "")
        name = det.get("name", "")
        if cat == "Web Server":
            continue
        if name not in detections:
            layer = "cdn" if cat == "CDN" else "waf" if cat == "WAF" else "cdn/waf"
            detections[name] = {
                "name": name,
                "layer": layer,
                "confidence": det.get("confidence", 0.5),
                "evidence": det.get("evidence", []),
            }

    # ─── Server header as fallback ───
    if server_hdr and not any(
        server_hdr.lower() in d["name"].lower() or d["name"].lower() in server_hdr.lower()
        for d in detections.values()
    ):
        # Determine layer based on server type
        _server_lower = server_hdr.lower()
        _proxy_keywords = {"nginx", "openresty", "envoy", "haproxy", "traefik", "varnish",
                           "caddy", "tengine", "kong", "apisix"}
        _server_keywords = {"apache", "iis", "litespeed", "tomcat", "jetty", "gunicorn",
                            "uvicorn", "puma", "kestrel", "wildfly", "weblogic"}
        if any(k in _server_lower for k in _proxy_keywords):
            _fallback_layer = "proxy"
        elif any(k in _server_lower for k in _server_keywords):
            _fallback_layer = "server"
        else:
            _fallback_layer = "proxy"
        detections[server_hdr] = {
            "name": server_hdr,
            "layer": _fallback_layer,
            "confidence": 0.5,
            "evidence": [f"server:{server_hdr}"],
        }

    # ─── X-Backend / X-Upstream headers (reveal backend server behind proxy) ───
    for backend_hdr in ("x-backend", "x-upstream", "x-served-by-backend",
                         "x-origin-server", "x-real-server"):
        val = _hdr(headers, backend_hdr) or error_headers_all.get(backend_hdr, "")
        if val and val not in detections:
            detections[f"backend:{val}"] = {
                "name": val,
                "layer": "server",
                "confidence": 0.4,
                "evidence": [f"header:{backend_hdr}={val}"],
            }

    # ─── Hosting from ASN (if no hosting layer detected) ───
    has_hosting = any(d["layer"] == "hosting" for d in detections.values())
    if not has_hosting:
        for rec in ips:
            if rec.get("classification") != "CDN":
                provider = rec.get("provider", "")
                if provider and provider != "unknown":
                    detections[provider] = {
                        "name": provider,
                        "layer": "hosting",
                        "confidence": 0.4,
                        "evidence": [f"asn:{rec.get('asn', '?')}"],
                    }
                    break  # only one

    # ─── Build ordered chain ───
    nodes = list(detections.values())
    nodes = _deduplicate(nodes)
    nodes.sort(key=lambda n: (LAYER_ORDER.index(n["layer"]) if n["layer"] in LAYER_ORDER else 99, -n["confidence"]))

    return nodes


# ──────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────

def _hdr(headers, name):
    """Case-insensitive header lookup."""
    if not headers or not isinstance(headers, dict):
        return None
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _norm(name):
    return re.sub(r"[/\s\d.]+", "", name).lower().strip()


def _deduplicate(nodes):
    """Remove redundant nodes — e.g. 'nginx' detected as both proxy and server."""
    seen_norms = {}
    result = []
    for n in nodes:
        key = _norm(n["name"])
        if key in seen_norms:
            existing = seen_norms[key]
            # Keep the one at the more specific layer (deeper in stack)
            existing_order = LAYER_ORDER.index(existing["layer"]) if existing["layer"] in LAYER_ORDER else 99
            new_order = LAYER_ORDER.index(n["layer"]) if n["layer"] in LAYER_ORDER else 99
            if n["confidence"] > existing["confidence"]:
                result[result.index(existing)] = n
                seen_norms[key] = n
            elif new_order > existing_order and n["confidence"] >= existing["confidence"] * 0.8:
                # Prefer deeper layer if confidence is close
                result[result.index(existing)] = n
                seen_norms[key] = n
        else:
            seen_norms[key] = n
            result.append(n)
    return result


# ──────────────────────────────────────────────────────────────
#  Network traceroute (ICMP/UDP + TCP layers)
# ──────────────────────────────────────────────────────────────

def run_traceroute(domain: str, timeout: int = 3, max_hops: int = 30,
                   on_status=None) -> Dict[str, Any]:
    """Run traceroute at multiple layers and classify each hop by ASN.

    Runs UDP traceroute (no root) and TCP traceroute on port 443 (needs root).
    Merges results to get the most complete path.

    Returns dict with:
        hops: list of {hop, ip, rtt_ms, provider, asn, classification}
        method: which traceroute method(s) succeeded
        target_ip: resolved IP
    """
    import subprocess
    import shutil
    import concurrent.futures

    _status = on_status or (lambda *a: None)
    result = {"hops": [], "methods": [], "target_ip": ""}

    def _parse_traceroute(output: str) -> List[Dict]:
        """Parse traceroute output into hop list."""
        hops = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("traceroute"):
                continue
            # Parse: " 1  hostname (IP)  1.234 ms" or " 1  IP  1.234 ms" or " 1  * * *"
            m = re.match(r'\s*(\d+)\s+(.+)', line)
            if not m:
                continue
            hop_num = int(m.group(1))
            rest = m.group(2)

            if rest.strip() == "*" or rest.strip().startswith("* "):
                hops.append({"hop": hop_num, "ip": "*", "rtt_ms": None})
                continue

            # Extract IP — could be "hostname (IP)" or just "IP"
            ip_match = re.search(r'\(?((?:\d{1,3}\.){3}\d{1,3})\)?', rest)
            if not ip_match:
                hops.append({"hop": hop_num, "ip": "*", "rtt_ms": None})
                continue

            ip = ip_match.group(1)

            # Extract RTT
            rtt_match = re.search(r'([\d.]+)\s*ms', rest)
            rtt = float(rtt_match.group(1)) if rtt_match else None

            hops.append({"hop": hop_num, "ip": ip, "rtt_ms": rtt})
        return hops

    def _run_cmd(cmd: List[str], label: str) -> Optional[List[Dict]]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=max_hops * timeout + 10)
            if proc.returncode == 0 and proc.stdout.strip():
                return _parse_traceroute(proc.stdout)
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        return None

    # Run ICMP, UDP and TCP traceroutes in parallel
    methods = []
    needs_root = False

    # Build command list: (cmd, label, needs_root)
    cmds = []
    tr_bin = shutil.which("traceroute")
    tcptr_bin = shutil.which("tcptraceroute")
    is_root = os.geteuid() == 0

    if tr_bin:
        # ICMP (works without root on most systems, best firewall penetration)
        cmds.append((
            [tr_bin, "-I", "-n", "-q", "1", "-m", str(max_hops),
             "-w", str(timeout), domain],
            "icmp", False
        ))
        # UDP (default traceroute, different filtering behavior than ICMP)
        cmds.append((
            [tr_bin, "-n", "-q", "1", "-m", str(max_hops),
             "-w", str(timeout), domain],
            "udp", False
        ))
        # TCP on port 443 (needs root or setuid — best for web targets)
        tcp_cmd = [tr_bin, "-T", "-p", "443", "-n", "-q", "1",
                   "-m", str(max_hops), "-w", str(timeout), domain]
        cmds.append((tcp_cmd, "tcp:443", True))

    if tcptr_bin:
        tcp2_cmd = [tcptr_bin, "-n", "-q", "1",
                    "-m", str(max_hops), "-w", str(timeout), domain, "443"]
        cmds.append((tcp2_cmd, "tcptraceroute", True))

    if not cmds:
        result["methods"] = []
        result["error"] = "traceroute not installed"
        return result

    _status("trace", "Network traceroute (ICMP + UDP + TCP:443)")

    all_results = {}  # label -> hops

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {}
        for cmd, label, root in cmds:
            futures[pool.submit(_run_cmd, cmd, label)] = (label, root)

        for f in concurrent.futures.as_completed(futures):
            label, root = futures[f]
            hops_result = f.result()
            if hops_result:
                all_results[label] = hops_result
                methods.append(label)
            elif root and not hops_result:
                needs_root = True

    if not all_results:
        result["methods"] = []
        result["needs_root"] = needs_root
        return result

    # Merge all methods: prefer real IPs over *, priority TCP > ICMP > UDP
    merged = {}
    priority = ["udp", "icmp", "tcp:443", "tcptraceroute"]
    for label in priority:
        for h in all_results.get(label, []):
            hop_n = h["hop"]
            if hop_n not in merged or (h["ip"] != "*" and merged[hop_n]["ip"] == "*"):
                merged[hop_n] = h
    hops = [merged[k] for k in sorted(merged.keys())]

    # Filter trailing * hops
    while hops and hops[-1]["ip"] == "*":
        hops.pop()

    # ASN-classify all real IPs
    real_ips = [h["ip"] for h in hops if h["ip"] != "*" and not _is_private(h["ip"])]
    asn_map = {}
    if real_ips:
        _status("trace", f"ASN classification for {len(real_ips)} hop(s)")
        try:
            from . import asn_lookup
            asn_records = asn_lookup.lookup_asn_bulk(real_ips)
            asn_map = {r["ip"]: r for r in asn_records}
        except Exception:
            pass

    # Reverse DNS for all real IPs (parallel, fast)
    rdns_map = {}
    real_and_private = [h["ip"] for h in hops if h["ip"] != "*"]
    if real_and_private:
        _status("trace", f"Reverse DNS for {len(real_and_private)} hop(s)")
        rdns_map = _bulk_rdns(real_and_private)

    # Enrich hops with ASN data, rDNS, CDN CIDR, and role classification
    from . import asn_lookup as _asn_mod
    for h in hops:
        ip = h["ip"]
        asn = asn_map.get(ip, {})
        h["provider"] = asn.get("provider", "")
        h["asn"] = asn.get("asn", "")
        h["country"] = asn.get("country", "")
        h["bgp_prefix"] = asn.get("bgp_prefix", "")
        h["classification"] = asn.get("classification", "")
        h["hostname"] = rdns_map.get(ip, "")
        h["cdn_provider"] = _asn_mod.is_cdn_ip(ip) if ip != "*" and not _is_private(ip) else None
        h["role"] = _classify_hop_role(h)

    result["hops"] = hops
    result["methods"] = methods
    has_tcp = any(m.startswith("tcp") for m in methods)
    result["needs_root"] = needs_root and not has_tcp
    if hops:
        last_real = next((h for h in reversed(hops) if h["ip"] != "*"), None)
        if last_real:
            result["target_ip"] = last_real["ip"]

    # If many hops are filtered, fetch BGP AS path to show intermediate networks
    total = len(hops)
    filtered = sum(1 for h in hops if h["ip"] == "*")
    if total > 3 and filtered / total > 0.5 and result.get("target_ip"):
        _status("trace", "BGP AS path lookup (RIPE RIS)")
        # Detect user's ASN from public IP for accurate path
        my_asn = _detect_my_asn()
        result["as_path"] = _fetch_bgp_as_path(result["target_ip"], my_asn=my_asn)
        result["my_asn"] = my_asn

    return result


def _get_upstream_asns(asn, timeout=5):
    """Get upstream/peer ASNs for a given AS via RIPE RIS."""
    import urllib.request
    import ssl
    import json as _json
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}&sourceapp=whatthewaf"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        data = _json.loads(urllib.request.urlopen(req, timeout=timeout, context=ctx).read())
        neighbours = data.get("data", {}).get("neighbours", [])
        return {str(n["asn"]) for n in neighbours if n.get("type") == "left"}
    except Exception:
        return set()


def _detect_my_asn():
    """Detect the user's ASN from their public IP."""
    import urllib.request
    import ssl
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request("https://api.ipquery.io/?format=json",
                                     headers={"User-Agent": "Mozilla/5.0"})
        import json as _json
        data = _json.loads(urllib.request.urlopen(req, timeout=5, context=ctx).read())
        asn = str(data.get("isp", {}).get("asn", "")).replace("AS", "")
        return asn if asn else None
    except Exception:
        return None


def _fetch_bgp_as_path(target_ip, my_asn=None, timeout=10):
    """Fetch BGP AS path to target via RIPE RIS looking glass.

    If my_asn is provided, tries to find a path that starts from that AS
    or one of its known upstreams, for a more accurate "from your network" view.

    Returns list of dicts: [{asn, provider, country, role}] representing
    the AS path to the target.
    """
    import urllib.request
    import ssl
    import json as _json

    try:
        # Get BGP prefix for this IP first
        from . import asn_lookup
        asn_info = asn_lookup.lookup_asn_bulk([target_ip])
        prefix = asn_info[0].get("bgp_prefix", "") if asn_info else ""
        if not prefix:
            return []

        url = (f"https://stat.ripe.net/data/looking-glass/data.json"
               f"?resource={prefix}&sourceapp=whatthewaf")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        data = _json.loads(urllib.request.urlopen(req, timeout=timeout, context=ctx).read())

        # Collect all AS paths
        all_paths = []
        for rrc in data.get("data", {}).get("rrcs", []):
            for peer in rrc.get("peers", []):
                path = peer.get("as_path", "").strip()
                if path:
                    all_paths.append(path)

        if not all_paths:
            return []

        # Try to find a path from our AS or its upstreams
        best_path = None
        if my_asn:
            my_asn_str = str(my_asn).replace("AS", "")

            # Get our upstream ASNs
            my_upstreams = _get_upstream_asns(my_asn_str)
            search_asns = {my_asn_str} | my_upstreams

            # Find path containing our AS or an upstream, prefer shortest
            candidates = []
            for p in all_paths:
                parts = p.split()
                for sa in search_asns:
                    if sa in parts:
                        # Trim path to start from the matched AS
                        idx = parts.index(sa)
                        trimmed = parts[idx:]
                        candidates.append((sa == my_asn_str, len(trimmed), trimmed))
                        break

            if candidates:
                # Prefer exact AS match, then shortest path
                candidates.sort(key=lambda x: (-x[0], x[1]))
                best_parts = candidates[0][2]
                # Prepend our AS if path starts from upstream
                if best_parts[0] != my_asn_str:
                    best_parts = [my_asn_str] + best_parts
                best_path = " ".join(best_parts)

        # Fallback: most common path
        if not best_path:
            path_counts = {}
            for p in all_paths:
                path_counts[p] = path_counts.get(p, 0) + 1
            best_path = max(path_counts, key=path_counts.get)

        asns = best_path.split()

        # Resolve ASN names via Team Cymru
        result = []
        seen = set()
        for asn_str in asns:
            if asn_str in seen:
                continue
            seen.add(asn_str)
            try:
                info = _cymru_asn_name(asn_str)
                provider = info.get("provider", f"AS{asn_str}")
                country = info.get("country", "")
            except Exception:
                provider = f"AS{asn_str}"
                country = ""

            # Classify role
            provider_lower = provider.lower()
            transit_kw = ["telia", "cogent", "ntt", "lumen", "gtt", "zayo",
                          "level3", "hurricane", "seabone", "arelion"]
            ixp_kw = ["ix", "exchange", "peering"]
            cdn_kw = ["cloudflare", "akamai", "fastly", "cloudfront", "amazon"]

            if any(k in provider_lower for k in cdn_kw):
                role = "cdn"
            elif any(k in provider_lower for k in transit_kw):
                role = "transit"
            elif any(k in provider_lower for k in ixp_kw):
                role = "ixp"
            else:
                role = "isp"

            result.append({
                "asn": asn_str,
                "provider": provider,
                "country": country,
                "role": role,
            })

        return result

    except Exception:
        return []


def _cymru_asn_name(asn):
    """Lookup ASN name via Team Cymru DNS."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 5:
                return {"provider": parts[4], "country": parts[1]}
    except Exception:
        pass
    return {}


def _bulk_rdns(ips, timeout=3):
    """Parallel reverse DNS lookup for a list of IPs."""
    import concurrent.futures
    import socket

    def _rdns(ip):
        try:
            socket.setdefaulttimeout(timeout)
            host, _, _ = socket.gethostbyaddr(ip)
            return ip, host
        except Exception:
            return ip, ""

    result = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ips), 15)) as pool:
        futures = {pool.submit(_rdns, ip): ip for ip in ips}
        try:
            for f in concurrent.futures.as_completed(futures, timeout=timeout + 5):
                ip = futures[f]
                try:
                    _, host = f.result()
                    result[ip] = host
                except Exception:
                    result[ip] = ""
        except TimeoutError:
            for f, ip in futures.items():
                if ip not in result:
                    result[ip] = ""
                    f.cancel()
    return result


# Keywords for classifying hop roles
_IXP_KEYWORDS = ["ix", "ixp", "exchange", "peering", "nap", "cix", "linx",
                  "amsix", "de-cix", "espanix", "catnix"]
_TRANSIT_KEYWORDS = ["transit", "backbone", "core", "telia", "lumen", "ntt",
                     "cogent", "gtt", "zayo", "level3", "hurricane"]
_HOSTING_KEYWORDS = ["hosting", "hetzner", "ovh", "digitalocean", "linode",
                     "vultr", "rackspace"]


def _classify_hop_role(hop):
    """Classify a traceroute hop's network role.

    Returns: 'local', 'isp', 'ixp', 'transit', 'cdn', 'hosting', 'cloud', or 'target'
    """
    ip = hop.get("ip", "*")
    if ip == "*":
        return "filtered"
    if _is_private(ip):
        return "local"

    provider = hop.get("provider", "").lower()
    hostname = hop.get("hostname", "").lower()
    cdn_provider = hop.get("cdn_provider")
    cls = hop.get("classification", "")

    # CDN detection (CIDR match or ASN classification)
    if cdn_provider or cls == "CDN":
        return "cdn"

    # IXP detection from hostname or provider
    combined = f"{provider} {hostname}"
    if any(kw in combined for kw in _IXP_KEYWORDS):
        return "ixp"

    # Transit/backbone
    if any(kw in combined for kw in _TRANSIT_KEYWORDS):
        return "transit"

    # Cloud providers (not CDN but cloud infra)
    cloud_kw = ["amazon", "aws", "google", "gcp", "microsoft", "azure", "oracle"]
    if any(kw in provider for kw in cloud_kw):
        return "cloud"

    # Hosting
    if any(kw in combined for kw in _HOSTING_KEYWORDS):
        return "hosting"

    return "isp"


def _is_private(ip: str) -> bool:
    """Check if an IP is in a private/reserved range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def format_chain(nodes: List[Dict[str, Any]]) -> str:
    """Format as one-line arrow string."""
    if not nodes:
        return ""
    role_labels = {
        "cdn": "CDN", "waf": "WAF", "cdn/waf": "CDN/WAF",
        "cache": "cache", "loadbalancer": "LB",
        "proxy": "proxy", "hosting": "hosting",
        "server": "server", "runtime": "runtime",
        "framework": "framework", "cms": "CMS",
    }
    parts = []
    for n in nodes:
        label = role_labels.get(n["layer"], n["layer"])
        parts.append(f"{n['name']} ({label})")
    return " → ".join(parts)
