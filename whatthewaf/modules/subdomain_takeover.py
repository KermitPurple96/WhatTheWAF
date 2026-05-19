"""Subdomain takeover detection — find dangling CNAMEs pointing to unclaimed services.

Resolves CNAME for each subdomain, checks if the target is claimable by matching
HTTP responses and DNS errors against known provider fingerprints.
"""

import concurrent.futures
import re
import socket
import httpx

# Fingerprints: (service, cname_pattern, response_fingerprint, severity)
TAKEOVER_FINGERPRINTS = [
    ("AWS S3", r"\.s3[.-].*\.amazonaws\.com$", "NoSuchBucket", "high"),
    ("AWS S3 Website", r"\.s3-website[.-].*\.amazonaws\.com$", "NoSuchBucket", "high"),
    ("GitHub Pages", r"\.github\.io$", "There isn't a GitHub Pages site here", "high"),
    ("Heroku", r"\.herokuapp\.com$", "No such app", "high"),
    ("Shopify", r"\.myshopify\.com$", "Sorry, this shop is currently unavailable", "medium"),
    ("Azure Websites", r"\.azurewebsites\.net$", "404 Web Site not found", "high"),
    ("Azure TrafficManager", r"\.trafficmanager\.net$", "NXDOMAIN", "high"),
    ("Azure CloudApp", r"\.cloudapp\.azure\.com$", "NXDOMAIN", "high"),
    ("Fastly", r"\.fastly\.net$", "Fastly error: unknown domain", "high"),
    ("Netlify", r"\.netlify\.(app|com)$", "Not Found - Request ID", "medium"),
    ("Pantheon", r"\.pantheonsite\.io$", "404 Unknown Site", "high"),
    ("Zendesk", r"\.zendesk\.com$", "Help Center Closed", "medium"),
    ("Tumblr", r"\.tumblr\.com$", "There's nothing here", "medium"),
    ("WordPress.com", r"\.wordpress\.com$", "Do you want to register", "medium"),
    ("Ghost", r"\.ghost\.io$", "404 Not Found", "medium"),
    ("Surge.sh", r"\.surge\.sh$", "project not found", "high"),
    ("Bitbucket", r"\.bitbucket\.io$", "Repository not found", "high"),
    ("Fly.io", r"\.fly\.dev$", "404 Not Found", "medium"),
    ("Vercel", r"\.vercel\.app$", "404: NOT_FOUND", "medium"),
    ("Cargo", r"\.cargocollective\.com$", "404 Not Found", "medium"),
    ("Unbounce", r"\.unbouncepages\.com$", "The requested URL was not found", "medium"),
    ("HubSpot", r"\.hubspot\.net$", "Domain not found", "medium"),
    ("Tilda", r"\.tilda\.ws$", "Please renew your subscription", "medium"),
    ("Agile CRM", r"\.agilecrm\.com$", "Sorry, this page is no longer available", "medium"),
    ("Airee.ru", r"\.airee\.ru$", "Ошибка 402", "medium"),
    ("Anima", r"\.animaapp\.io$", "404 - Page not found", "medium"),
    ("Readme.io", r"\.readme\.io$", "Project doesnt exist", "medium"),
    ("Statuspage", r"\.statuspage\.io$", "Status page pushed a DNS", "medium"),
    ("LaunchRock", r"\.launchrock\.com$", "It looks like you may have taken a wrong turn", "medium"),
    ("Ngrok", r"\.ngrok\.io$", "Tunnel .* not found", "high"),
    ("SmartJobBoard", r"\.smartjobboard\.com$", "This job board website is", "medium"),
    ("Strikingly", r"\.strikinglydns\.com$", "page not found", "medium"),
    ("Uptimerobot", r"\.uptimerobot\.com$", "page not found", "low"),
    ("Webflow", r"\.webflow\.io$", "The page you are looking for doesn't exist", "medium"),
]

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def check_takeover(subdomain, domain, timeout=5):
    """Check a single subdomain for takeover vulnerability.

    Returns dict with finding or None.
    """
    fqdn = f"{subdomain}.{domain}" if subdomain else domain

    # 1. Resolve CNAME
    import dns.resolver
    cname_target = None
    try:
        answers = dns.resolver.resolve(fqdn, "CNAME")
        for rdata in answers:
            cname_target = str(rdata.target).rstrip(".")
            break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        pass
    except Exception:
        pass

    if not cname_target:
        return None

    # 2. Check if CNAME target matches known vulnerable services
    matched_service = None
    matched_fingerprint = None
    matched_severity = None
    for service, pattern, fingerprint, severity in TAKEOVER_FINGERPRINTS:
        if re.search(pattern, cname_target, re.IGNORECASE):
            matched_service = service
            matched_fingerprint = fingerprint
            matched_severity = severity
            break

    if not matched_service:
        return None

    # 3. Check if CNAME target resolves (NXDOMAIN = dangling)
    nxdomain = False
    try:
        socket.getaddrinfo(cname_target, 443, socket.AF_INET)
    except socket.gaierror:
        nxdomain = True

    if nxdomain:
        return {
            "subdomain": fqdn,
            "cname": cname_target,
            "service": matched_service,
            "status": "VULNERABLE",
            "reason": "CNAME target does not resolve (NXDOMAIN)",
            "severity": matched_severity,
        }

    # 4. Even if it resolves, check HTTP response for provider error page
    if matched_fingerprint and matched_fingerprint != "NXDOMAIN":
        try:
            resp = httpx.get(f"https://{fqdn}", timeout=timeout, verify=False,
                             headers={"User-Agent": DEFAULT_UA}, follow_redirects=True)
            body = resp.text[:10000]
            if re.search(matched_fingerprint, body, re.IGNORECASE):
                return {
                    "subdomain": fqdn,
                    "cname": cname_target,
                    "service": matched_service,
                    "status": "VULNERABLE",
                    "reason": f"Service response matches: {matched_fingerprint[:50]}",
                    "severity": matched_severity,
                    "http_status": resp.status_code,
                }
        except Exception:
            pass

        # Try HTTP too
        try:
            resp = httpx.get(f"http://{fqdn}", timeout=timeout, verify=False,
                             headers={"User-Agent": DEFAULT_UA}, follow_redirects=True)
            body = resp.text[:10000]
            if re.search(matched_fingerprint, body, re.IGNORECASE):
                return {
                    "subdomain": fqdn,
                    "cname": cname_target,
                    "service": matched_service,
                    "status": "VULNERABLE",
                    "reason": f"Service response matches: {matched_fingerprint[:50]}",
                    "severity": matched_severity,
                    "http_status": resp.status_code,
                }
        except Exception:
            pass

    return None


# Common subdomains to check for takeover
TAKEOVER_SUBDOMAINS = [
    "blog", "help", "support", "status", "docs", "dev", "staging",
    "beta", "demo", "test", "preview", "landing", "go", "links",
    "info", "pages", "shop", "store", "app", "portal", "cdn",
    "assets", "static", "media", "img", "images", "files",
    "mail", "email", "newsletter", "feedback", "survey",
    "careers", "jobs", "events", "news", "press",
    "community", "forum", "kb", "wiki", "learn",
    "api", "gateway", "auth", "sso", "login", "id",
    "admin", "dashboard", "panel", "cms", "manage",
    "m", "mobile", "www2", "old", "legacy", "new",
]


def scan_takeover(domain, subdomains=None, timeout=5, max_workers=15, on_status=None):
    """Scan subdomains for takeover vulnerabilities.

    Returns list of vulnerability findings.
    """
    _status = on_status or (lambda *a: None)
    subs = subdomains or TAKEOVER_SUBDOMAINS
    findings = []

    _status("takeover", f"Checking {len(subs)} subdomains for takeover")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(check_takeover, sub, domain, timeout): sub
            for sub in subs
        }
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                findings.append(result)

    findings.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("severity", "low"), 9))
    return findings
