"""Reverse IP lookup and shared hosting / service identification.

Identifies what service or platform is behind an IP by checking:
1. Reverse DNS (PTR records) — reveals AWS, Azure, GCP, etc.
2. Reverse IP lookup — how many domains share the IP
3. SSL certificate on the IP — shared hosting indicators
4. HTTP default vhost response — service fingerprinting
"""

import re
import socket
import ssl
import httpx


# rDNS patterns -> service identification
RDNS_SERVICES = [
    (r"awsglobalaccelerator\.com", "AWS Global Accelerator", "Anycast proxy — routes to multiple AWS backends"),
    (r"cloudfront\.net", "AWS CloudFront", "CDN / edge distribution"),
    (r"elb\.amazonaws\.com", "AWS ELB", "Elastic Load Balancer"),
    (r"compute\.amazonaws\.com", "AWS EC2", "Virtual server"),
    (r"elasticbeanstalk\.com", "AWS Elastic Beanstalk", "Managed app platform"),
    (r"s3\.amazonaws\.com", "AWS S3", "Object storage / static hosting"),
    (r"amazonaws\.com", "AWS", "Amazon Web Services"),
    (r"bc\.googleusercontent\.com", "Google Cloud", "GCE instance"),
    (r"1e100\.net", "Google", "Google infrastructure"),
    (r"googlehosted\.com", "Google Hosted", "Google hosted service"),
    (r"azurewebsites\.net", "Azure App Service", "Managed web app"),
    (r"azure\.com|azure-dns", "Azure", "Microsoft Azure"),
    (r"cloudapp\.net", "Azure Cloud", "Azure cloud service"),
    (r"vercel\.app|vercel-dns\.com", "Vercel", "Frontend hosting platform"),
    (r"netlify\.com", "Netlify", "Frontend hosting platform"),
    (r"heroku\.com|herokuapp\.com", "Heroku", "PaaS platform"),
    (r"fastly\.net", "Fastly", "CDN / edge computing"),
    (r"akamai\.net|akamaitechnologies", "Akamai", "CDN"),
    (r"cloudflare\.com", "Cloudflare", "CDN / WAF"),
    (r"digitalocean\.com", "DigitalOcean", "Cloud hosting"),
    (r"vultr\.com", "Vultr", "Cloud hosting"),
    (r"linode\.com|akamai\.com", "Linode/Akamai", "Cloud hosting"),
    (r"hetzner\.(com|de|cloud)", "Hetzner", "Hosting provider"),
    (r"ovh\.(net|com|ca)", "OVH", "Hosting provider"),
    (r"ionos\.(com|de)", "IONOS", "Hosting provider"),
    (r"contabo\.com", "Contabo", "Hosting provider"),
    (r"godaddy\.com|secureserver\.net", "GoDaddy", "Hosting / registrar"),
    (r"bluehost\.com", "Bluehost", "Shared hosting"),
    (r"hostgator\.com", "HostGator", "Shared hosting"),
    (r"siteground\.com", "SiteGround", "Managed hosting"),
    (r"dreamhost\.com", "DreamHost", "Hosting provider"),
    (r"wpengine\.com", "WP Engine", "Managed WordPress"),
    (r"kinsta\.com", "Kinsta", "Managed WordPress"),
    (r"flywheel\.com", "Flywheel", "Managed WordPress"),
    (r"pantheon\.io", "Pantheon", "WebOps platform"),
    (r"shopify\.com", "Shopify", "Ecommerce platform"),
    (r"squarespace\.com", "Squarespace", "Website builder"),
    (r"wix\.com", "Wix", "Website builder"),
    (r"github\.io", "GitHub Pages", "Static hosting"),
    (r"render\.com", "Render", "Cloud hosting"),
    (r"railway\.app", "Railway", "Cloud hosting"),
    (r"fly\.io|fly\.dev", "Fly.io", "Edge hosting"),
]


def identify_service(ip, domain=None, timeout=5):
    """Identify what service/platform is behind an IP.

    Returns dict: ip, rdns, service, description, cert_cn, cert_sans_count,
                  shared_domains_count, shared_domains_sample
    """
    result = {
        "ip": ip,
        "rdns": "",
        "service": "",
        "description": "",
        "cert_cn": "",
        "cert_sans": [],
        "cert_sans_count": 0,
        "shared_count": 0,
        "shared_sample": [],
    }

    # 1. Reverse DNS
    try:
        rev = socket.gethostbyaddr(ip)
        result["rdns"] = rev[0]
    except Exception:
        pass

    # Identify from rDNS
    if result["rdns"]:
        for pattern, service, desc in RDNS_SERVICES:
            if re.search(pattern, result["rdns"], re.IGNORECASE):
                result["service"] = service
                result["description"] = desc
                break

    # 2. SSL certificate on IP
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    cn = dict(x[0] for x in cert.get("subject", [()])).get("commonName", "")
                    result["cert_cn"] = cn
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    result["cert_sans"] = sans[:20]
                    result["cert_sans_count"] = len(sans)

                    # If cert has wildcard or many SANs, it's likely shared hosting
                    if len(sans) > 10 and not result["service"]:
                        result["service"] = "Shared hosting"
                        result["description"] = f"SSL cert covers {len(sans)} domains"

                    # Check cert CN/SANs for service identification
                    all_names = " ".join([cn] + sans[:5]).lower()
                    for pattern, service, desc in RDNS_SERVICES:
                        if re.search(pattern, all_names, re.IGNORECASE):
                            if not result["service"]:
                                result["service"] = service
                                result["description"] = desc
                            break
    except Exception:
        pass

    # 3. HTTP default vhost fingerprinting
    if not result["service"]:
        try:
            r = httpx.get(f"https://{ip}/", verify=False, timeout=timeout, follow_redirects=False)
            server = r.headers.get("server", "").lower()
            body = r.text[:3000].lower()
            result["service"] = _identify_from_http(server, body, r.headers)
        except Exception:
            try:
                r = httpx.get(f"http://{ip}/", verify=False, timeout=timeout, follow_redirects=False)
                server = r.headers.get("server", "").lower()
                body = r.text[:3000].lower()
                result["service"] = _identify_from_http(server, body, r.headers)
            except Exception:
                pass

    # 4. Reverse IP lookup (shared domains)
    shared = reverse_ip_lookup(ip, timeout=timeout)
    result["shared_count"] = shared["count"]
    result["shared_sample"] = shared["domains"]

    return result


def reverse_ip_lookup(ip, timeout=10):
    """Query HackerTarget for domains sharing the same IP.

    Returns dict: count, domains (sample list)
    """
    result = {"count": 0, "domains": []}
    try:
        r = httpx.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:50]:
            lines = [l.strip() for l in r.text.strip().split("\n") if l.strip()]
            result["count"] = len(lines)
            result["domains"] = lines[:25]  # Sample
    except Exception:
        pass
    return result


def _identify_from_http(server, body, headers):
    """Identify service from HTTP response."""
    checks = [
        (lambda: "vercel" in server or "vercel" in body, "Vercel"),
        (lambda: "netlify" in server or "netlify" in body, "Netlify"),
        (lambda: "heroku" in server or "heroku" in body, "Heroku"),
        (lambda: "github" in server or "github.io" in body, "GitHub Pages"),
        (lambda: "shopify" in body or "shopify" in server, "Shopify"),
        (lambda: "squarespace" in body, "Squarespace"),
        (lambda: "wix" in body and "wix.com" in body, "Wix"),
        (lambda: "cloudflare" in server, "Cloudflare"),
        (lambda: "amazons3" in server, "AWS S3"),
        (lambda: "awselb" in server, "AWS ELB"),
        (lambda: "cloudfront" in server, "AWS CloudFront"),
        (lambda: "gws" in server, "Google Web Server"),
        (lambda: "openresty" in server, "OpenResty (likely CDN/proxy)"),
        (lambda: headers.get("x-amz-cf-id"), "AWS CloudFront"),
        (lambda: headers.get("x-vercel-id"), "Vercel"),
        (lambda: headers.get("x-nf-request-id"), "Netlify"),
    ]
    for check_fn, name in checks:
        try:
            if check_fn():
                return name
        except Exception:
            pass
    return ""
