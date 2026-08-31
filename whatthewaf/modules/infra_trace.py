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
import sys
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
    ("Bunny CDN", "cdn", [
        ("header", "cdn-pullzone", 0.9),
        ("header", "cdn-uid", 0.9),
        ("header", "cdn-requestcountrycode", 0.8),
        ("server", "bunnycdn", 0.9),
    ]),
    ("GCore CDN", "cdn", [
        ("header", "x-gcore-request-id", 0.9),
        ("cname", "gcdn.co", 0.9),
        ("cname", "gcorelabs", 0.9),
    ]),
    ("Tencent Cloud CDN", "cdn", [
        ("header", "x-nws-log-uuid", 0.8),
        ("header", "x-cache-lookup", 0.7),
        ("cname", "cdn.dnsv1.com", 0.9),
    ]),

    # ── Bot Protection / Challenge ───────────────────────────
    ("DataDome", "waf", [
        ("header", "x-datadome", 0.9),
        ("cookie", "datadome", 0.9),
        ("body", "datadome.co", 0.8),
    ]),
    ("PerimeterX", "waf", [
        ("cookie", "_pxhd", 0.9),
        ("cookie", "_pxvid", 0.8),
        ("body", "perimeterx.net", 0.8),
        ("body", "captcha.px-cdn.net", 0.9),
    ]),
    ("Kasada", "waf", [
        ("header", "x-kpsdk-ct", 0.9),
        ("header", "x-kpsdk-v", 0.9),
    ]),
    ("Shape Security", "waf", [
        ("header", "x-distil-cs", 0.9),
        ("cookie", "D_SID", 0.8),
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
    ("WP Rocket", "cache", [
        ("body", "wp rocket", 0.8),
        ("body", "wprocketoptimized", 0.9),
    ]),
    ("WP Fastest Cache", "cache", [
        ("body", "wp fastest cache", 0.9),
        ("header", "x-wpfc-served", 0.9),
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
    ("Google Cloud LB", "loadbalancer", [
        ("header", "x-cloud-trace-context", 0.6),
        ("via_contains", "google", 0.7),
        ("server", "google frontend", 0.8),
    ]),
    ("Kong", "loadbalancer", [
        ("server", "kong", 0.9),
        ("header", "x-kong-upstream-latency", 0.9),
        ("header", "x-kong-proxy-latency", 0.9),
    ]),

    # ── Reverse Proxies ──────────────────────────────────────
    ("nginx", "proxy", [
        ("server", "nginx", 0.6),
        ("error_page", "nginx", 0.7),
    ]),
    # NOTE: Apache removed as proxy — it's almost always the origin server.
    # When Apache IS behind a proxy (nginx/openresty), error_page detection
    # correctly identifies it as SERVER layer.
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
    ("Tengine", "proxy", [
        ("server", "tengine", 0.9),
    ]),
    ("Apache Traffic Server", "proxy", [
        ("server", "ats", 0.8),
        ("via_contains", "apachetrafficserver", 0.9),
    ]),

    # ── Hosting Platforms ────────────────────────────────────
    ("SiteGround", "hosting", [
        ("header", "x-siteground", 0.9),
        ("header", "sg-captcha", 0.9),
        ("cookie", "sg_cookies", 0.8),
        ("cert_subject", "siteground", 0.7),
        ("body", "sgcaptcha", 0.8),
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
    ("Render", "hosting", [
        ("header", "x-render-origin-server", 0.9),
        ("cname", "onrender.com", 0.9),
    ]),
    ("Fly.io", "hosting", [
        ("header", "fly-request-id", 0.9),
        ("server", "fly", 0.8),
        ("cname", "fly.dev", 0.9),
    ]),
    ("Railway", "hosting", [
        ("cname", "railway.app", 0.9),
        ("header", "x-railway-", 0.8),
    ]),
    ("Platform.sh", "hosting", [
        ("header", "x-platform-server", 0.9),
        ("header", "x-platform-cluster", 0.9),
        ("cname", "platform.sh", 0.9),
    ]),
    ("Acquia", "hosting", [
        ("header", "x-ah-environment", 0.9),
        ("cname", "acquia", 0.9),
    ]),
    ("GCP App Engine", "hosting", [
        ("header", "x-appengine-resource-usage", 0.9),
        ("header", "x-google-backends", 0.8),
        ("cname", "appspot.com", 0.9),
    ]),
    ("Azure App Service", "hosting", [
        ("cookie", "ARRAffinity", 0.9),
        ("header", "x-azure-ref", 0.7),
        ("cname", "azurewebsites.net", 0.9),
    ]),
    ("Cloudways", "hosting", [
        ("header", "x-cw-cdn", 0.9),
        ("cname", "cloudwaysapps.com", 0.9),
    ]),
    ("DigitalOcean App", "hosting", [
        ("cname", "ondigitalocean.app", 0.9),
        ("header", "x-do-app-origin", 0.9),
    ]),

    # ── Web Servers (origin) ─────────────────────────────────
    # NOTE: "apache" error_page pattern must NOT match "apache tomcat"
    # The _detect_error_server output "Apache" (without "Tomcat") is safe to match
    ("Apache", "server", [
        ("error_page", "apache", 0.9),  # matches _detect_error_server output "Apache x.x"
        ("header_value", "server", "apache", 0.7),
    ]),
    ("Microsoft IIS", "server", [
        ("server", "microsoft-iis", 0.9),
        ("header", "x-aspnet-version", 0.8),
        ("header_value", "x-powered-by", "asp.net", 0.8),
        ("error_page", "iis", 0.9),
        ("error_page", "microsoft iis", 0.9),
    ]),
    ("LiteSpeed", "server", [
        ("server", "litespeed", 0.9),
        ("error_page", "litespeed", 0.8),
    ]),
    ("Kestrel", "server", [
        ("server", "kestrel", 0.9),
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
    ("Uvicorn", "runtime", [
        ("server", "uvicorn", 0.9),
    ]),
    ("Deno", "runtime", [
        ("server", "deno", 0.9),
        ("header", "x-deno-ray", 0.9),
    ]),
    ("Bun", "runtime", [
        ("server", "bun", 0.8),
    ]),
    ("Ruby", "runtime", [
        ("cookie", "_rails_session", 0.8),
        ("cookie", "rack.session", 0.8),
        ("server", "puma", 0.9),
        # NOTE: "unicorn" removed — substring matches "gunicorn" (Python).
        # Unicorn (Ruby) is rare; Puma/Passenger/Rails cookies cover Ruby detection.
        ("server", "thin", 0.8),
        ("server", "passenger", 0.8),
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
        ("error_page", "spring boot", 0.9),
        ("header", "x-application-context", 0.8),
    ]),
    ("Ruby on Rails", "framework", [
        ("cookie", "_rails_session", 0.9),
        ("header", "x-runtime", 0.6),
        ("header", "x-request-id", 0.3),
        ("error_page", "action_controller", 0.9),
        ("error_page", "routing error", 0.8),
        ("error_page", "ruby on rails", 0.9),
    ]),
    ("Express.js", "framework", [
        ("header_value", "x-powered-by", "express", 0.9),
        ("error_page", "cannot get", 0.7),
        ("error_page", "express.js", 0.9),
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
    ("FastAPI", "framework", [
        ("error_page", "fastapi", 0.9),
        ("body", "swagger-ui", 0.4),  # low conf — many APIs use Swagger
    ]),
    ("Symfony", "framework", [
        ("header_value", "x-powered-by", "symfony", 0.9),
        ("error_page", "symfony", 0.9),
        ("cookie", "symfony", 0.8),
    ]),
    ("SvelteKit", "framework", [
        ("body", "__sveltekit", 0.9),
        ("body", "_app/immutable", 0.7),
    ]),
    ("Remix", "framework", [
        ("body", "__remixContext", 0.9),
        ("body", "__remix", 0.8),
    ]),
    ("Gatsby", "framework", [
        ("body", "gatsby-", 0.7),
        ("header", "x-gatsby-cache", 0.9),
        ("body", "gatsby-image", 0.8),
    ]),
    ("Astro", "framework", [
        ("body", "astro-island", 0.9),
        ("body_meta", "astro", 0.8),
    ]),
    ("AdonisJS", "framework", [
        ("cookie", "adonis-session", 0.9),
        ("header_value", "x-powered-by", "adonis", 0.9),
    ]),
    ("CodeIgniter", "framework", [
        ("cookie", "ci_session", 0.8),
        ("error_page", "codeigniter", 0.9),
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
    ("TYPO3", "cms", [
        ("cookie", "fe_typo_user", 0.9),
        ("body", "typo3conf/", 0.9),
        ("body_meta", "typo3", 0.9),
        ("body", "typo3temp/", 0.8),
    ]),
    ("Craft CMS", "cms", [
        ("cookie", "CraftSessionId", 0.9),
        ("header", "x-craft-solo", 0.9),
        ("body_meta", "craft cms", 0.9),
    ]),
    ("HubSpot CMS", "cms", [
        ("body", "hs-scripts.com", 0.7),
        ("cname", "hubspot", 0.8),
        ("header", "x-hs-hub-id", 0.9),
    ]),
    ("Umbraco", "cms", [
        ("body", "umbraco", 0.7),
        ("cookie", "UMB_SESSION", 0.9),
        ("body_meta", "umbraco", 0.9),
    ]),
    ("MediaWiki", "cms", [
        ("body_meta", "mediawiki", 0.9),
        ("body", "mw-page-container", 0.8),
        ("body", "mediawiki", 0.7),
    ]),
    ("Moodle", "cms", [
        ("cookie", "MoodleSession", 0.9),
        ("body", "moodlelib", 0.8),
        ("body_meta", "moodle", 0.9),
    ]),
    ("Discourse", "cms", [
        ("body_meta", "discourse", 0.9),
        ("body", "discourse-", 0.7),
        ("header", "x-discourse-route", 0.9),
    ]),
    ("XenForo", "cms", [
        ("body", "xenforo", 0.8),
        ("cookie", "xf_session", 0.9),
        ("cookie", "xf_user", 0.9),
    ]),
    ("Concrete CMS", "cms", [
        ("body", "concretecms", 0.9),
        ("body", "concrete5", 0.8),
        ("cookie", "CONCRETE5", 0.9),
    ]),
    ("Blogger", "cms", [
        ("cname", "blogger", 0.9),
        ("body", "blogspot.com", 0.8),
        ("body_meta", "blogger", 0.9),
    ]),
    ("DNN (DotNetNuke)", "cms", [
        ("cookie", "dnn_IsMobile", 0.9),
        ("body", "dnnVariable", 0.9),
        ("body", "DotNetNuke", 0.8),
    ]),
    ("Adobe Experience Manager", "cms", [
        ("body", "/etc.clientlibs/", 0.8),
        ("body", "/content/dam/", 0.7),
        ("header", "x-aem-", 0.9),
    ]),
    ("Sitecore", "cms", [
        ("cookie", "SC_ANALYTICS", 0.9),
        ("cookie", "sitecore_", 0.8),
        ("body", "sitecore", 0.6),
    ]),
    ("Weebly", "cms", [
        ("body", "weebly.com", 0.8),
        ("cname", "weebly", 0.9),
    ]),
    ("ExpressionEngine", "cms", [
        ("cookie", "exp_tracker", 0.9),
        ("cookie", "exp_sessionid", 0.9),
    ]),
    ("DynamicWeb", "cms", [
        ("header_value", "x-powered-by", "dynamicweb", 0.9),
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
    "app-waf",
]

# WAFs that are CMS plugins / application-level (run inside PHP/app, not at network edge)
APP_LEVEL_WAFS = {
    "Wordfence", "Shield Security", "Malcare", "SecuPress",
    "RSFirewall", "Powerful Firewall", "aeSecure", "pkSecurityModule",
    "NinjaFirewall", "BulletProof Security", "All In One WP Security",
    "iThemes Security", "Cerber Security",
}

# Technologies in waf_signatures that are misclassified as WAFs — remap to correct trace layer
_WAF_LAYER_OVERRIDES = {
    "CodeIgniter": "framework",
    "ExpressionEngine": "cms",
    "DynamicWeb": "cms",
    "ASP.NET Generic": "runtime",
}


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
                        # Guard against "apache" matching "apache tomcat"
                        val_lower = val.lower()
                        if hdr_pattern.lower() == "apache" and "tomcat" in val_lower:
                            pass
                        else:
                            match = True
                            evidence.append(f"header:{hdr_name}={val[:50]}")

            elif sig_type == "server":
                pattern = signal[1]
                srv_lower = server_hdr.lower()
                pat_lower = pattern.lower()
                # Avoid "apache" matching "apache tomcat"
                if pat_lower in srv_lower:
                    if pat_lower == "apache" and "tomcat" in srv_lower:
                        pass  # skip — it's Tomcat, not Apache httpd
                    else:
                        match = True
                        evidence.append(f"server:{server_hdr}")
                if not match and any(pat_lower in s for s in error_servers):
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
                pat_lower = pattern.lower()
                eb_lower = error_bodies.lower()
                if pat_lower in eb_lower:
                    # Avoid false matches: "apache" should not match "apache tomcat"
                    # Check if the match is a standalone occurrence, not part of a longer tech name
                    _false_positive = False
                    if pat_lower == "apache" and "apache tomcat" in eb_lower:
                        _false_positive = True
                    elif pat_lower == "nginx" and "openresty" in eb_lower:
                        # nginx error page inside openresty = openresty, not separate nginx
                        _false_positive = True
                    if not _false_positive:
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
            # If we already have this tech, merge evidence (dedup) and take max confidence
            if key in detections:
                detections[key]["confidence"] = max(detections[key]["confidence"], min(score, 1.0))
                existing = set(detections[key]["evidence"])
                detections[key]["evidence"].extend(e for e in evidence if e not in existing)
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
            if name in _WAF_LAYER_OVERRIDES:
                layer = _WAF_LAYER_OVERRIDES[name]
            elif cat == "CDN":
                layer = "cdn"
            elif cat == "WAF" and name in APP_LEVEL_WAFS:
                layer = "app-waf"
            elif cat == "WAF":
                layer = "waf"
            else:
                layer = "cdn/waf"
            detections[name] = {
                "name": name,
                "layer": layer,
                "confidence": det.get("confidence", 0.5),
                "evidence": det.get("evidence", []),
            }

    # ─── Server header as fallback ───
    # Normalize for dedup: strip version, convert dashes/underscores to spaces
    def _norm(s):
        return re.sub(r'[/_-].*', '', s).replace('-', ' ').replace('_', ' ').lower().strip()
    _srv_norm = _norm(server_hdr)
    if server_hdr and not any(
        _srv_norm in _norm(d["name"]) or _norm(d["name"]) in _srv_norm
        or server_hdr.lower() in d["name"].lower() or d["name"].lower() in server_hdr.lower()
        for d in detections.values()
    ):
        # Determine layer based on server type
        _server_lower = server_hdr.lower()
        _proxy_keywords = {"nginx", "openresty", "envoy", "haproxy", "traefik", "varnish",
                           "caddy", "tengine", "kong", "apisix", "ats", "squid"}
        _server_keywords = {"apache", "iis", "litespeed", "tomcat", "jetty", "gunicorn",
                            "uvicorn", "puma", "kestrel", "wildfly", "weblogic",
                            "deno", "bun", "uwsgi", "waitress", "daphne", "hypercorn"}
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

    # ─── X-Backend / X-Upstream headers (add as evidence to existing server detection) ───
    for backend_hdr in ("x-backend", "x-upstream", "x-served-by-backend",
                         "x-origin-server", "x-real-server"):
        val = _hdr(headers, backend_hdr) or error_headers_all.get(backend_hdr, "")
        if val:
            # Add as evidence to existing server-layer detection (don't create separate layer)
            server_dets = [k for k, d in detections.items() if d["layer"] == "server"]
            if server_dets:
                detections[server_dets[0]]["evidence"].append(f"backend:{backend_hdr}={val}")
            else:
                # No server detected yet — show as standalone info
                detections[f"backend:{val}"] = {
                    "name": val,
                    "layer": "server",
                    "confidence": 0.3,
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

    # ─── Detect challenge/captcha pages ───
    challenge = _detect_challenge(body_lower, headers, cookie_str, error_headers_all)
    if challenge:
        report["_challenge_detected"] = challenge

    # ─── Build ordered chain ───
    nodes = list(detections.values())
    nodes = _deduplicate(nodes)
    nodes.sort(key=lambda n: (LAYER_ORDER.index(n["layer"]) if n["layer"] in LAYER_ORDER else 99, -n["confidence"]))

    return nodes


# ──────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────

def _detect_challenge(body_lower, headers, cookie_str, error_headers):
    """Detect if the response is a challenge/captcha page that blocks content analysis."""
    # Each check returns (challenge_name, evidence) or None
    checks = [
        # SiteGround captcha
        ("sg-captcha" in (headers or {}) or "sg-captcha" in error_headers,
         "SiteGround Captcha", "header:sg-captcha"),
        ("sgcaptcha" in body_lower,
         "SiteGround Captcha", "body:sgcaptcha redirect"),
        # Cloudflare challenge (Under Attack Mode / managed challenge)
        ("cf_chl_opt" in body_lower or "challenge-platform" in body_lower,
         "Cloudflare Challenge", "body:cf challenge script"),
        ("cf-mitigated" in (headers or {}),
         "Cloudflare Challenge", "header:cf-mitigated"),
        # Cloudflare Turnstile
        ("challenges.cloudflare.com/turnstile" in body_lower or "cf-turnstile" in body_lower,
         "Cloudflare Turnstile", "body:turnstile widget"),
        # hCaptcha
        ("hcaptcha.com" in body_lower or "h-captcha" in body_lower,
         "hCaptcha", "body:hcaptcha widget"),
        # Google reCAPTCHA
        ("google.com/recaptcha" in body_lower or "g-recaptcha" in body_lower,
         "Google reCAPTCHA", "body:recaptcha widget"),
        # DataDome
        ("datadome" in cookie_str or "x-datadome" in error_headers,
         "DataDome", "cookie/header:datadome"),
        # PerimeterX / HUMAN
        ("_pxhd" in cookie_str or "captcha.px-cdn.net" in body_lower,
         "PerimeterX", "cookie/body:perimeterx"),
        # Kasada
        ("x-kpsdk-ct" in error_headers,
         "Kasada", "header:x-kpsdk-ct"),
        # Akamai Bot Manager
        ("_abck" in cookie_str and "ak_bmsc" in cookie_str,
         "Akamai Bot Manager", "cookie:_abck+ak_bmsc"),
    ]
    for condition, name, evidence in checks:
        if condition:
            return {"name": name, "evidence": evidence}
    return None


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
    """Remove redundant nodes — e.g. 'nginx' detected as both cache and proxy."""
    # Known aliases — different detection names that refer to the same component
    _ALIASES = {
        "nginx cache": "nginx",
        "nginx": "nginx",
        "openresty": "openresty",
        "varnish cache": "varnish",
        "varnish": "varnish",
    }

    def _dedup_key(name):
        """Get dedup key — check aliases first, fall back to norm."""
        name_lower = name.lower().strip()
        for alias, canonical in _ALIASES.items():
            if alias in name_lower:
                return canonical
        return _norm(name)

    seen = {}
    result = []
    for n in nodes:
        key = _dedup_key(n["name"])
        if key in seen:
            existing = seen[key]
            existing_order = LAYER_ORDER.index(existing["layer"]) if existing["layer"] in LAYER_ORDER else 99
            new_order = LAYER_ORDER.index(n["layer"]) if n["layer"] in LAYER_ORDER else 99
            # Merge evidence into the winner
            if n["confidence"] > existing["confidence"]:
                n["evidence"] = list(dict.fromkeys(existing["evidence"] + n["evidence"]))
                result[result.index(existing)] = n
                seen[key] = n
            elif new_order > existing_order and n["confidence"] >= existing["confidence"] * 0.8:
                n["evidence"] = list(dict.fromkeys(existing["evidence"] + n["evidence"]))
                result[result.index(existing)] = n
                seen[key] = n
            else:
                # Keep existing but merge new evidence into it
                existing["evidence"] = list(dict.fromkeys(existing["evidence"] + n["evidence"]))
                existing["confidence"] = max(existing["confidence"], n["confidence"])
        else:
            seen[key] = n
            result.append(n)
    return result


# ──────────────────────────────────────────────────────────────
#  Network traceroute (ICMP/UDP + TCP layers)
# ──────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────
# Traceroute output parsers (module-level for reuse + unit testing)
# ─────────────────────────────────────────────────────────────────────────

def _tr_stats(rtts: List[float], timeouts: int) -> Dict[str, Any]:
    """Compute per-hop statistics from RTT samples and a timeout count."""
    recv = len(rtts)
    sent = recv + timeouts
    out: Dict[str, Any] = {
        "sent": sent, "recv": recv,
        "loss_pct": round(timeouts / sent * 100, 1) if sent else 0.0,
    }
    if rtts:
        avg = sum(rtts) / recv
        var = sum((x - avg) ** 2 for x in rtts) / recv
        out["best_ms"] = round(min(rtts), 3)
        out["worst_ms"] = round(max(rtts), 3)
        out["avg_ms"] = round(avg, 3)
        out["stddev_ms"] = round(var ** 0.5, 3)
        out["rtts"] = [round(x, 3) for x in rtts]
        out["rtt_ms"] = round(avg, 3)   # headline value (backwards-compatible)
    else:
        out["rtt_ms"] = None
    return out


def _parse_mpls(text: str) -> List[Dict]:
    """Parse GNU traceroute -e MPLS stacks: <MPLS:L=24012,E=0,S=1,T=1>."""
    labels = []
    for lbl, exp, s, ttl in re.findall(
            r'MPLS:?\s*L=(\d+),\s*E=(\d+),\s*S=(\d+),\s*T=(\d+)', text):
        labels.append({"label": int(lbl), "exp": int(exp),
                       "s": int(s), "ttl": int(ttl)})
    return labels


def _parse_traceroute(output: str) -> List[Dict]:
    """Parse GNU/BSD traceroute output (multi-probe stats, MPLS-aware)."""
    hops = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("traceroute"):
            continue
        # Parse: " 1  IP  1.2 ms  1.1 ms  1.0 ms" / " 3  * * *" / MPLS blocks
        m = re.match(r'\s*(\d+)\s+(.+)', line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2)

        # Extract first IP (hop may show multiple on ECMP — take first here)
        ip_match = re.search(r'\(?((?:\d{1,3}\.){3}\d{1,3})\)?', rest)
        if not ip_match:
            # Whole hop timed out (e.g. "* * *")
            hops.append({"hop": hop_num, "ip": "*", "rtt_ms": None,
                         "sent": rest.count("*") or None, "recv": 0,
                         "loss_pct": 100.0})
            continue

        ip = ip_match.group(1)
        rtts = [float(x) for x in re.findall(r'([\d.]+)\s*ms', rest)]
        timeouts = rest.count("*")
        hop: Dict[str, Any] = {"hop": hop_num, "ip": ip}
        hop.update(_tr_stats(rtts, timeouts))
        mpls = _parse_mpls(rest)
        if mpls:
            hop["mpls"] = mpls
        hops.append(hop)
    return hops


def _parse_tracert(output: str) -> List[Dict]:
    """Parse Windows tracert output (3 probes/hop, RTT columns in ms)."""
    hops = []
    for line in output.split("\n"):
        m = re.match(r'\s*(\d+)\s+(.+)', line.rstrip())
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2)
        # RTT columns look like "<1 ms", "10 ms", or "*"
        rtts = [0.5 if v.startswith("<") else float(v)
                for v in re.findall(r'(<?\d+)\s*ms', rest)]
        timeouts = len(re.findall(r'\*', rest))
        ip_match = re.search(r'((?:\d{1,3}\.){3}\d{1,3})', rest)
        if not ip_match:
            hops.append({"hop": hop_num, "ip": "*", "rtt_ms": None,
                         "sent": timeouts or None, "recv": 0,
                         "loss_pct": 100.0})
            continue
        hop: Dict[str, Any] = {"hop": hop_num, "ip": ip_match.group(1)}
        hop.update(_tr_stats(rtts, timeouts))
        hops.append(hop)
    return hops


def _run_tr_cmd(cmd: List[str], parser, timeout: int, max_hops: int) -> Optional[List[Dict]]:
    """Run one traceroute/tracert command and parse its output; None on failure."""
    import subprocess
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace",
                              timeout=max_hops * timeout + 30)
        # tracert/traceroute can exit non-zero yet still print usable hops
        if proc.stdout and proc.stdout.strip():
            parsed = parser(proc.stdout)
            if parsed:
                return parsed
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return None


def _path_signature(hops: List[Dict]) -> Tuple:
    """Canonical signature of a path (IP per hop, trailing timeouts trimmed)."""
    ips = [h.get("ip", "*") for h in hops]
    while ips and ips[-1] == "*":
        ips.pop()
    return tuple(ips)


def _enumerate_multipath(domain: str, max_hops: int, timeout: int,
                         is_root: bool, on_status, flows: int = 8) -> Dict[str, Any]:
    """Enumerate ECMP paths by tracing several distinct L4 flows in parallel.

    GNU traceroute is Paris-consistent within a run (fixed flow-id); varying the
    flow-id across runs enumerates load-balanced paths (Dublin-style). We vary the
    TCP source port (dst stays 443) with root, or the UDP dest port without root.
    Not available on Windows (tracert is ICMP-only and cannot set the flow-id).
    """
    import shutil
    import concurrent.futures

    tr_bin = shutil.which("traceroute")
    if os.name == "nt" or not tr_bin:
        return {"paths": [], "supported": False,
                "note": "multipath needs GNU traceroute (Linux); "
                        "tracert/Windows cannot vary the flow-id"}

    mpls_flag = ["-e"] if sys.platform.startswith("linux") else []
    transport = "tcp:443" if is_root else "udp"
    # ECMP branching we can observe is in the ISP/transit portion; cap the flow
    # depth and shorten the wait so 8 (serialised, root/TCP) flows stay tolerable.
    mp_hops = str(min(max_hops, 20))
    mp_wait = str(min(timeout, 2))

    # Build one command per flow with a distinct, fixed flow identifier.
    tasks = []  # (flow_id, port, cmd)
    for k in range(flows):
        if is_root:
            # Fix dst=443, vary source port. GNU traceroute needs --sport=NUM
            # (not space-separated); --sport implies -N 1 (serialised).
            sport = 33000 + k
            cmd = [tr_bin, "-T", "-p", "443", f"--sport={sport}",
                   *mpls_flag, "-n", "-q", "1", "-m", mp_hops,
                   "-w", mp_wait, domain]
            tasks.append((k, sport, cmd))
        else:
            # -U = fixed UDP dst port (Paris); vary it across flows.
            dport = 33434 + k
            cmd = [tr_bin, "-U", "-p", str(dport), *mpls_flag,
                   "-n", "-q", "1", "-N", "16", "-m", mp_hops,
                   "-w", mp_wait, domain]
            tasks.append((k, dport, cmd))

    on_status("trace", f"Multipath ECMP enumeration ({flows} flows, {transport})")

    paths = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(flows, 8)) as pool:
        futs = {}
        for k, port, cmd in tasks:
            futs[pool.submit(_run_tr_cmd, cmd, _parse_traceroute, timeout, max_hops)] = (k, port)
        for f in concurrent.futures.as_completed(futs):
            k, port = futs[f]
            hops = f.result()
            if hops:
                paths.append({"flow_id": k, "transport": transport,
                              "port": port, "hops": hops})

    paths.sort(key=lambda p: p["flow_id"])
    return {"paths": paths, "supported": True, "transport": transport}


def _build_multipath_summary(paths: List[Dict], asn_map: Dict,
                             rdns_map: Dict) -> Dict[str, Any]:
    """Collapse per-flow paths into an ECMP divergence map.

    Returns distinct_paths count, the first hop where paths diverge, and per-TTL
    branches listing every distinct next-hop IP (enriched) seen at that TTL.
    """
    summary: Dict[str, Any] = {"flows_sent": len(paths)}
    if not paths:
        summary["distinct_paths"] = 0
        summary["divergence_hop"] = None
        summary["branches"] = {}
        return summary

    # Per-TTL set of distinct real (public) IPs across all flows.
    by_ttl: Dict[int, set] = {}
    for p in paths:
        for h in p["hops"]:
            ip = h.get("ip", "*")
            if ip and ip != "*" and not _is_private(ip):
                by_ttl.setdefault(h["hop"], set()).add(ip)

    # A branch is a TTL where flows saw >1 distinct real next-hop (a balancer).
    branches: Dict[int, List[Dict]] = {}
    for ttl, ips in by_ttl.items():
        if len(ips) < 2:
            continue  # single next-hop → not a load-balancer
        entries = []
        for ip in sorted(ips):
            asn = asn_map.get(ip, {})
            entry = {
                "ip": ip,
                "provider": asn.get("provider", ""),
                "asn": asn.get("asn", ""),
                "country": asn.get("country", ""),
                "classification": asn.get("classification", ""),
                "hostname": rdns_map.get(ip, ""),
                "cdn_provider": _is_cdn_ip_safe(ip),
            }
            entry["role"] = _classify_hop_role(entry)
            entries.append(entry)
        branches[ttl] = entries

    # distinct_paths counts genuinely different routes THROUGH the balancer
    # points, ignoring hops that merely timed out in some flows. With no branch,
    # every flow followed the same observed routers → one effective path.
    if not branches:
        has_path = any(_path_signature(p["hops"]) for p in paths)
        summary["distinct_paths"] = 1 if has_path else 0
        summary["divergence_hop"] = None
        summary["branches"] = {}
        return summary

    branch_ttls = sorted(branches)
    sigs = set()
    for p in paths:
        ip_by_ttl = {h["hop"]: h.get("ip", "*") for h in p["hops"]}
        sig = tuple(ip_by_ttl.get(t, "?") for t in branch_ttls)
        if any(x not in ("*", "?") for x in sig):
            sigs.add(sig)

    summary["distinct_paths"] = len(sigs)
    summary["branches"] = branches
    summary["divergence_hop"] = min(branch_ttls)
    return summary


def _is_cdn_ip_safe(ip: str):
    """is_cdn_ip that never raises (returns provider name or None)."""
    try:
        from . import asn_lookup as _asn_mod
        return _asn_mod.is_cdn_ip(ip)
    except Exception:
        return None


def run_traceroute(domain: str, timeout: int = 3, max_hops: int = 30,
                   on_status=None, multipath: bool = True,
                   flows: int = 8) -> Dict[str, Any]:
    """Run traceroute at multiple layers and classify each hop by ASN.

    Runs UDP traceroute (no root) and TCP traceroute on port 443 (needs root).
    Merges results to get the most complete path.

    Returns dict with:
        hops: list of {hop, ip, rtt_ms, provider, asn, classification}
        method: which traceroute method(s) succeeded
        target_ip: resolved IP
        multipath: ECMP flow enumeration summary (see _build_multipath_summary)
    """
    import shutil
    import concurrent.futures

    _status = on_status or (lambda *a: None)
    result = {"hops": [], "methods": [], "target_ip": ""}

    # Run traceroutes in parallel across protocols
    methods = []
    needs_root = False

    # Build command list: (cmd, label, needs_root, parser)
    cmds = []
    tr_bin = shutil.which("traceroute")
    tcptr_bin = shutil.which("tcptraceroute")
    # MPLS/ICMP extensions (-e) are a GNU/Linux traceroute feature; BSD/macOS
    # traceroute rejects the flag and would fail the whole probe, so gate it.
    mpls_flag = ["-e"] if sys.platform.startswith("linux") else []

    if os.name == "nt" and not tr_bin:
        # Windows: built-in tracert (ICMP, 3 probes/hop, no admin). -w is in ms.
        tracert_bin = shutil.which("tracert") or "tracert"
        cmds.append((
            [tracert_bin, "-d", "-h", str(max_hops),
             "-w", str(timeout * 1000), domain],
            "icmp(tracert)", False, _parse_tracert
        ))
    elif tr_bin:
        # ICMP (works without root on most systems, best firewall penetration)
        cmds.append((
            [tr_bin, "-I", *mpls_flag, "-n", "-q", "3", "-m", str(max_hops),
             "-w", str(timeout), domain],
            "icmp", False, _parse_traceroute
        ))
        # UDP (default traceroute, different filtering behavior than ICMP)
        cmds.append((
            [tr_bin, *mpls_flag, "-n", "-q", "3", "-m", str(max_hops),
             "-w", str(timeout), domain],
            "udp", False, _parse_traceroute
        ))
        # TCP on port 443 (needs root or setuid — best for web targets)
        cmds.append((
            [tr_bin, "-T", "-p", "443", *mpls_flag, "-n", "-q", "3",
             "-m", str(max_hops), "-w", str(timeout), domain],
            "tcp:443", True, _parse_traceroute
        ))

    if tcptr_bin:
        cmds.append((
            [tcptr_bin, "-n", "-q", "3",
             "-m", str(max_hops), "-w", str(timeout), domain, "443"],
            "tcptraceroute", True, _parse_traceroute
        ))

    if not cmds:
        result["methods"] = []
        result["error"] = "traceroute not installed"
        return result

    _status("trace", "Network traceroute (" + " + ".join(c[1] for c in cmds) + ")")

    all_results = {}  # label -> hops

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {}
        for cmd, label, root, parser in cmds:
            futures[pool.submit(_run_tr_cmd, cmd, parser, timeout, max_hops)] = (label, root)

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
    priority = ["udp", "icmp", "tcp:443", "tcptraceroute", "icmp(tracert)"]
    ordered = priority + [l for l in all_results if l not in priority]
    for label in ordered:
        for h in all_results.get(label, []):
            hop_n = h["hop"]
            if hop_n not in merged or (h["ip"] != "*" and merged[hop_n]["ip"] == "*"):
                merged[hop_n] = h
    hops = [merged[k] for k in sorted(merged.keys())]

    # Filter trailing * hops
    while hops and hops[-1]["ip"] == "*":
        hops.pop()

    # ── Multipath / ECMP enumeration (runs before the ASN lookup so its IPs
    #    can share the same bulk queries as the primary path) ──
    mp = {"paths": [], "supported": False}
    if multipath:
        is_root = (getattr(os, "geteuid", lambda: 1)() == 0)
        mp = _enumerate_multipath(domain, max_hops, timeout, is_root,
                                  _status, flows=flows)

    # Union of every real IP seen across the primary path and all ECMP flows.
    all_real: List[str] = []
    seen = set()
    for h in hops:
        ip = h["ip"]
        if ip != "*" and ip not in seen:
            seen.add(ip); all_real.append(ip)
    for p in mp.get("paths", []):
        for h in p["hops"]:
            ip = h.get("ip", "*")
            if ip != "*" and ip not in seen:
                seen.add(ip); all_real.append(ip)

    # ASN-classify all public IPs (single bulk query for primary + flows)
    public_ips = [ip for ip in all_real if not _is_private(ip)]
    asn_map = {}
    if public_ips:
        _status("trace", f"ASN classification for {len(public_ips)} hop(s)")
        try:
            from . import asn_lookup
            asn_records = asn_lookup.lookup_asn_bulk(public_ips)
            asn_map = {r["ip"]: r for r in asn_records}
        except Exception:
            pass

    # Reverse DNS for all real IPs (parallel, fast)
    rdns_map = {}
    if all_real:
        _status("trace", f"Reverse DNS for {len(all_real)} hop(s)")
        rdns_map = _bulk_rdns(all_real)

    # Enrich primary hops with ASN data, rDNS, CDN CIDR, and role classification
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

    # ── ECMP summary (sharing the ASN/rDNS maps built above) ──
    if multipath:
        summary = _build_multipath_summary(mp.get("paths", []), asn_map, rdns_map)
        summary["supported"] = mp.get("supported", False)
        if mp.get("note"):
            summary["note"] = mp["note"]
        if mp.get("transport"):
            summary["transport"] = mp["transport"]
        result["multipath"] = summary
        result["paths"] = mp.get("paths", [])

    # ── NAT detection (Dublin-style IP-ID probing; Linux + root only) ──
    if multipath:
        try:
            from . import nat_detect
            result["nat"] = nat_detect.detect_nat(
                domain, max_hops=max_hops, timeout=min(timeout, 2),
                on_status=_status)
        except Exception:
            pass

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


# ─────────────────────────────────────────────────────────────────────────
# Trace topology graph (Mermaid / Graphviz DOT) — pure, unit-testable
# ─────────────────────────────────────────────────────────────────────────

def _graph_label(hop: Dict[str, Any]) -> str:
    """Short label for a hop: 'ttl · ip' plus provider/CDN or role."""
    sub = (hop.get("cdn_provider") or hop.get("provider") or "").split(",")[0].strip()
    sub = sub or hop.get("role", "")
    text = f"{hop['hop']} · {hop['ip']}"
    if sub:
        text += f"  {sub}"
    # Strip characters that break Mermaid/DOT label syntax.
    return re.sub(r'["\[\]{}|<>]', "", text)[:44]


def build_trace_graph(tr: Dict[str, Any], domain: str, fmt: str = "mermaid") -> str:
    """Render the traceroute as a graph: linear path + ECMP branches + NAT marks.

    fmt: "mermaid" (default) or "dot". Returns the graph as text.
    """
    hops = [h for h in tr.get("hops", []) if h.get("ip") not in (None, "*")]
    nat_ttls = {h["ttl"] for h in (tr.get("nat") or {}).get("nat_boundaries", [])}
    branches = (tr.get("multipath") or {}).get("branches", {}) or {}
    target = tr.get("target_ip", "") or domain
    dst_label = re.sub(r'["\[\]{}|<>]', "", f"{domain} {target}")[:44]

    if fmt == "dot":
        lines = ['digraph trace {', '  rankdir=TB; node [shape=box, fontname="monospace"];',
                 '  SRC [label="you", shape=oval];']
        prev = "SRC"
        for h in hops:
            nid = f"H{h['hop']}"
            lines.append(f'  {nid} [label="{_graph_label(h)}"];')
            style = ' [label="NAT", style=dashed, color=red]' if h["hop"] in nat_ttls else ''
            lines.append(f'  {prev} -> {nid}{style};')
            for i, e in enumerate(branches.get(h["hop"], [])):
                if e["ip"] == h["ip"]:
                    continue
                bid = f"H{h['hop']}b{i}"
                lbl = _graph_label({"hop": h["hop"], "ip": e["ip"],
                                    "provider": e.get("provider"),
                                    "cdn_provider": e.get("cdn_provider"),
                                    "role": e.get("role", "")})
                lines.append(f'  {bid} [label="{lbl}", color=orange];')
                lines.append(f'  {prev} -> {bid} [label="ECMP", color=orange];')
            prev = nid
        lines.append(f'  DST [label="{dst_label}", shape=oval];')
        lines.append(f'  {prev} -> DST;')
        lines.append('}')
        return "\n".join(lines)

    # Mermaid (default)
    lines = ["flowchart TD", '  SRC(["you"])']
    prev = "SRC"
    for h in hops:
        nid = f"H{h['hop']}"
        lines.append(f'  {nid}["{_graph_label(h)}"]')
        edge = "-. NAT .->" if h["hop"] in nat_ttls else "-->"
        lines.append(f"  {prev} {edge} {nid}")
        for i, e in enumerate(branches.get(h["hop"], [])):
            if e["ip"] == h["ip"]:
                continue
            bid = f"H{h['hop']}b{i}"
            lbl = _graph_label({"hop": h["hop"], "ip": e["ip"],
                                "provider": e.get("provider"),
                                "cdn_provider": e.get("cdn_provider"),
                                "role": e.get("role", "")})
            lines.append(f'  {bid}["{lbl}"]')
            lines.append(f"  {prev} -->|ECMP| {bid}")
        prev = nid
    lines.append(f'  DST(["{dst_label}"])')
    lines.append(f"  {prev} --> DST")
    return "\n".join(lines)


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
