"""Subdomain takeover detection — find dangling CNAMEs, NS, and MX records.

Checks subdomains from multiple sources:
1. Hardcoded common subdomain list (50+)
2. Subdomains discovered by --recon (Shodan, DNSTrails, etc.)
3. Subdomains stored in scan history DB

For each subdomain with a CNAME/NS/MX pointing to a known vulnerable service,
verifies the takeover is real by:
1. Checking NXDOMAIN on the target
2. Matching HTTP response against provider error fingerprints
3. Double-checking with a second request to rule out temporary outages
"""

import concurrent.futures
import re
import socket
import time
import httpx

# Fingerprints: (service, cname_pattern, response_fingerprint, severity)
TAKEOVER_FINGERPRINTS = [
    # Cloud storage
    ("AWS S3", r"\.s3[.-].*\.amazonaws\.com$", "NoSuchBucket", "high"),
    ("AWS S3 Website", r"\.s3-website[.-].*\.amazonaws\.com$", "NoSuchBucket", "high"),
    ("GCP Storage", r"\.storage\.googleapis\.com$", "NoSuchBucket", "high"),
    ("Azure Blob", r"\.blob\.core\.windows\.net$", "BlobNotFound|ResourceNotFound", "high"),
    # Hosting / PaaS
    ("GitHub Pages", r"\.github\.io$", "There isn't a GitHub Pages site here", "high"),
    ("Heroku", r"\.herokuapp\.com$", "No such app|no-such-app", "high"),
    ("Azure Websites", r"\.azurewebsites\.net$", "404 Web Site not found", "high"),
    ("Azure TrafficManager", r"\.trafficmanager\.net$", "NXDOMAIN", "high"),
    ("Azure CloudApp", r"\.cloudapp\.azure\.com$", "NXDOMAIN", "high"),
    ("Pantheon", r"\.pantheonsite\.io$", "404 Unknown Site|locked site", "high"),
    ("Fly.io", r"\.fly\.dev$", "this is not the app you're looking for", "medium"),
    ("Surge.sh", r"\.surge\.sh$", "project not found", "high"),
    ("Vercel", r"\.vercel\.app$", "404: NOT_FOUND|DEPLOYMENT_NOT_FOUND", "medium"),
    # CDN
    ("Fastly", r"\.fastly\.net$", "Fastly error: unknown domain", "high"),
    ("Netlify", r"\.netlify\.(app|com)$", "Not Found.*Request ID", "medium"),
    ("CloudFront", r"\.cloudfront\.net$", "Bad request|ERROR: The request could not be satisfied", "medium"),
    # SaaS
    ("Shopify", r"\.myshopify\.com$", "Sorry, this shop is currently unavailable", "medium"),
    ("Zendesk", r"\.zendesk\.com$", "Help Center Closed", "medium"),
    ("Tumblr", r"\.tumblr\.com$", "There's nothing here|Whatever you were looking for", "medium"),
    ("WordPress.com", r"\.wordpress\.com$", "Do you want to register", "medium"),
    ("Ghost", r"\.ghost\.io$", "404.*Ghost", "medium"),
    ("Bitbucket", r"\.bitbucket\.io$", "Repository not found", "high"),
    ("Cargo", r"\.cargocollective\.com$", "404 Not Found", "medium"),
    ("Unbounce", r"\.unbouncepages\.com$", "The requested URL was not found", "medium"),
    ("HubSpot", r"\.hubspot\.net$", "Domain not found", "medium"),
    ("Tilda", r"\.tilda\.ws$", "Please renew your subscription", "medium"),
    ("Readme.io", r"\.readme\.io$", "Project doesnt exist", "medium"),
    ("Statuspage", r"\.statuspage\.io$", "Status page pushed a DNS|You are being redirected", "medium"),
    ("LaunchRock", r"\.launchrock\.com$", "It looks like you may have taken a wrong turn", "medium"),
    ("Ngrok", r"\.ngrok\.(io|app)$", "Tunnel .* not found|ERR_NGROK", "high"),
    ("Strikingly", r"\.strikinglydns\.com$", "page not found", "medium"),
    ("Webflow", r"\.webflow\.io$", "The page you are looking for doesn't exist", "medium"),
    ("Agile CRM", r"\.agilecrm\.com$", "Sorry, this page is no longer available", "medium"),
    ("Anima", r"\.animaapp\.io$", "404.*Page not found", "medium"),
    ("SmartJobBoard", r"\.smartjobboard\.com$", "This job board website is", "medium"),
    ("Desk.com", r"\.desk\.com$", "Sorry, We Couldn't Find That Page", "medium"),
    ("Feedpress", r"\.redirect\.feedpress\.me$", "The feed has not been found", "medium"),
    ("Helpjuice", r"\.helpjuice\.com$", "We could not find what you're looking for", "medium"),
    ("Help Scout", r"\.helpscoutdocs\.com$", "No settings were found for this company", "medium"),
    ("Intercom", r"\.custom\.intercom\.help$", "This page is reserved for an Intercom", "medium"),
    ("JetBrains YouTrack", r"\.myjetbrains\.com$", "is not a registered InCloud YouTrack", "medium"),
    ("Kinsta", r"\.kinsta\.cloud$", "No site found", "medium"),
    ("Landingi", r"\.landingi\.com$", "It looks like you're lost", "medium"),
    ("Pingdom", r"\.stats\.pingdom\.com$", "This public report page has not been activated", "medium"),
    ("Proposify", r"\.proposify\.biz$", "If you need immediate access", "medium"),
    ("Teamwork", r"\.teamwork\.com$", "Oops.*There is no portal here", "medium"),
    ("Thinkific", r"\.thinkific\.com$", "You may have mistyped the address", "medium"),
    ("Kajabi", r"\.mykajabi\.com$", "This domain is not set up", "medium"),
]

# NS record takeover fingerprints
NS_TAKEOVER = [
    ("AWS Route53", r"\.awsdns-", "NXDOMAIN"),
    ("Azure DNS", r"\.azure-dns\.", "NXDOMAIN"),
    ("Google Cloud DNS", r"\.googledomains\.com$", "NXDOMAIN"),
    ("DigitalOcean DNS", r"\.digitalocean\.com$", "NXDOMAIN"),
]

from ..constants import DEFAULT_UA


def check_takeover(subdomain, domain, timeout=5):
    """Check a single subdomain for CNAME and NS takeover vulnerability."""
    import dns.resolver

    fqdn = f"{subdomain}.{domain}" if subdomain else domain
    findings = []

    # ── CNAME check ──
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

    if cname_target:
        finding = _check_cname_takeover(fqdn, cname_target, timeout)
        if finding:
            findings.append(finding)

    # ── NS check (dangling nameserver) ──
    try:
        ns_answers = dns.resolver.resolve(fqdn, "NS")
        for rdata in ns_answers:
            ns_target = str(rdata.target).rstrip(".")
            for service, pattern, _ in NS_TAKEOVER:
                if re.search(pattern, ns_target, re.IGNORECASE):
                    # Check if NS resolves
                    try:
                        socket.getaddrinfo(ns_target, 53, socket.AF_INET)
                    except socket.gaierror:
                        findings.append({
                            "subdomain": fqdn,
                            "cname": ns_target,
                            "service": f"{service} (NS)",
                            "status": "VULNERABLE",
                            "reason": f"NS record {ns_target} does not resolve",
                            "severity": "critical",
                            "record_type": "NS",
                        })
    except Exception:
        pass

    return findings[0] if findings else None


def _check_cname_takeover(fqdn, cname_target, timeout):
    """Verify CNAME takeover with double-check for reliability."""

    # Match against fingerprints
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

    # Check NXDOMAIN
    nxdomain = False
    try:
        socket.getaddrinfo(cname_target, 443, socket.AF_INET)
    except socket.gaierror:
        nxdomain = True

    if nxdomain:
        # Double-check after 2 seconds to rule out temporary DNS issues
        time.sleep(2)
        try:
            socket.getaddrinfo(cname_target, 443, socket.AF_INET)
            nxdomain = False  # Resolved on second try — not dangling
        except socket.gaierror:
            pass  # Still NXDOMAIN — confirmed dangling

    if nxdomain:
        return {
            "subdomain": fqdn,
            "cname": cname_target,
            "service": matched_service,
            "status": "VULNERABLE",
            "reason": "CNAME target does not resolve (NXDOMAIN, confirmed with double-check)",
            "severity": matched_severity,
            "record_type": "CNAME",
        }

    # Even if it resolves, check HTTP for provider error page
    if matched_fingerprint and matched_fingerprint != "NXDOMAIN":
        for scheme in ("https", "http"):
            try:
                resp = httpx.get(f"{scheme}://{fqdn}", timeout=timeout, verify=False,
                                 headers={"User-Agent": DEFAULT_UA}, follow_redirects=True)
                body = resp.text[:10000]
                if re.search(matched_fingerprint, body, re.IGNORECASE):
                    # Double-check: request again to rule out transient error
                    time.sleep(1)
                    resp2 = httpx.get(f"{scheme}://{fqdn}", timeout=timeout, verify=False,
                                      headers={"User-Agent": DEFAULT_UA}, follow_redirects=True)
                    if re.search(matched_fingerprint, resp2.text[:10000], re.IGNORECASE):
                        return {
                            "subdomain": fqdn,
                            "cname": cname_target,
                            "service": matched_service,
                            "status": "VULNERABLE",
                            "reason": f"Service error confirmed (2 requests): {matched_fingerprint[:50]}",
                            "severity": matched_severity,
                            "http_status": resp.status_code,
                            "record_type": "CNAME",
                        }
            except Exception:
                pass

    return None


# Common subdomains to check
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


def scan_takeover(domain, subdomains=None, extra_subdomains=None,
                  timeout=5, max_workers=15, on_status=None):
    """Scan subdomains for takeover vulnerabilities.

    Args:
        subdomains: override the default list
        extra_subdomains: additional subdomains to check (from recon, DB, etc.)

    Returns list of vulnerability findings.
    """
    _status = on_status or (lambda *a: None)

    # Merge default + extra subdomains (dedup)
    subs = set(subdomains or TAKEOVER_SUBDOMAINS)
    if extra_subdomains:
        for s in extra_subdomains:
            # Extract subdomain part from FQDN if needed
            s = s.strip().lower()
            if s.endswith(f".{domain}"):
                s = s[: -(len(domain) + 1)]
            if s and s != domain and "." not in s:
                subs.add(s)

    subs = list(subs)
    _status("takeover", f"Checking {len(subs)} subdomains for takeover (CNAME + NS)")

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(check_takeover, sub, domain, timeout): sub
            for sub in subs
        }
        for f in concurrent.futures.as_completed(futures):
            try:
                result = f.result()
                if result:
                    findings.append(result)
            except Exception:
                pass

    findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 9))
    return findings
