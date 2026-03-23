"""Deep DNS analysis — extract infrastructure intel from NS, MX, TXT records.

Parses SPF, DMARC, DKIM, and domain verification tokens to reveal
SaaS tools, mail providers, and hosting infrastructure.
"""

import re
from . import dns_resolver

# Known verification token patterns -> service name
VERIFICATION_PATTERNS = [
    (r"google-site-verification", "Google Search Console"),
    (r"facebook-domain-verification", "Facebook Business"),
    (r"MS=", "Microsoft 365"),
    (r"ms=", "Microsoft 365"),
    (r"apple-domain-verification", "Apple"),
    (r"adobe-idp-site-verification", "Adobe"),
    (r"atlassian-domain-verification", "Atlassian"),
    (r"docusign", "DocuSign"),
    (r"globalsign-domain-verification", "GlobalSign"),
    (r"stripe-verification", "Stripe"),
    (r"postman-domain-verification", "Postman"),
    (r"hubspot-developer-verification", "HubSpot"),
    (r"zoom-domain-verification", "Zoom"),
    (r"slack-domain-verification", "Slack"),
    (r"have-i-been-pwned-verification", "HIBP"),
    (r"sendinblue-code", "Sendinblue/Brevo"),
    (r"mailchimp", "Mailchimp"),
    (r"fastly-domain-delegation", "Fastly"),
    (r"ahrefs-site-verification", "Ahrefs"),
    (r"blitz=", "Blitz"),
    (r"loaderio-", "Loader.io"),
    (r"_github-challenge", "GitHub"),
    (r"yandex-verification", "Yandex"),
    (r"baidu-site-verification", "Baidu"),
    (r"pinterest-site-verification", "Pinterest"),
    (r"shopify-verification", "Shopify"),
]

# Known mail provider patterns from MX records
MAIL_PROVIDERS = [
    (r"google\.com|googlemail\.com|gmail-smtp", "Google Workspace"),
    (r"outlook\.com|microsoft\.com|office365", "Microsoft 365"),
    (r"zoho\.com|zoho\.eu", "Zoho Mail"),
    (r"protonmail\.ch|proton\.me", "ProtonMail"),
    (r"mimecast\.com", "Mimecast"),
    (r"barracuda", "Barracuda Email"),
    (r"pphosted\.com|proofpoint", "Proofpoint"),
    (r"messagelabs\.com|symantec", "Symantec/Broadcom"),
    (r"mailgun\.org", "Mailgun"),
    (r"sendgrid\.net", "SendGrid"),
    (r"amazonses\.com|amazonaws\.com", "Amazon SES"),
    (r"ovh\.(net|com)", "OVH Mail"),
    (r"gandi\.net", "Gandi Mail"),
    (r"ionos\.(com|de)", "IONOS Mail"),
    (r"fastmail\.com", "Fastmail"),
    (r"tutanota\.de|tuta\.io", "Tutanota"),
    (r"yandex\.(ru|net)", "Yandex Mail"),
    (r"secureserver\.net", "GoDaddy"),
    (r"emailsrvr\.com", "Rackspace"),
    (r"forcepoint\.com", "Forcepoint"),
]

# Known NS provider patterns
NS_PROVIDERS = [
    (r"cloudflare\.com", "Cloudflare DNS"),
    (r"awsdns", "AWS Route 53"),
    (r"azure-dns", "Azure DNS"),
    (r"googledomains\.com|google\.com", "Google Cloud DNS"),
    (r"domaincontrol\.com", "GoDaddy DNS"),
    (r"registrar-servers\.com", "Namecheap DNS"),
    (r"digitalocean\.com", "DigitalOcean DNS"),
    (r"linode\.com", "Linode DNS"),
    (r"vultr\.com", "Vultr DNS"),
    (r"ns\.ovh\.", "OVH DNS"),
    (r"hetzner\.(com|de)", "Hetzner DNS"),
    (r"gandi\.net", "Gandi DNS"),
    (r"dnsmadeeasy\.com", "DNS Made Easy"),
    (r"nsone\.net|ns1\.com", "NS1"),
    (r"dnsimple\.com", "DNSimple"),
    (r"ultradns", "UltraDNS"),
    (r"dynect\.net", "DynDNS/Oracle"),
]


def deep_dns_analysis(domain):
    """Perform deep DNS analysis on a domain.

    Returns dict with: ns_records, ns_provider, mx_records, mail_provider,
    txt_records, spf, dmarc, dkim_selector, verified_services
    """
    dns_info = dns_resolver.resolve_domain(domain)

    result = {
        "ns_records": dns_info.get("ns_records", []),
        "ns_providers": [],
        "mx_records": dns_info.get("mx_records", []),
        "mail_providers": [],
        "txt_records": dns_info.get("txt_records", []),
        "spf": None,
        "dmarc": None,
        "verified_services": [],
    }

    # Identify NS providers
    for ns in result["ns_records"]:
        for pattern, name in NS_PROVIDERS:
            if re.search(pattern, ns, re.IGNORECASE):
                if name not in result["ns_providers"]:
                    result["ns_providers"].append(name)

    # Identify mail providers from MX
    for mx in result["mx_records"]:
        for pattern, name in MAIL_PROVIDERS:
            if re.search(pattern, mx, re.IGNORECASE):
                if name not in result["mail_providers"]:
                    result["mail_providers"].append(name)

    # Parse TXT records
    for txt in result["txt_records"]:
        # SPF
        if txt.startswith("v=spf1"):
            result["spf"] = _parse_spf(txt)

        # Domain verification tokens
        for pattern, service in VERIFICATION_PATTERNS:
            if re.search(pattern, txt, re.IGNORECASE):
                if service not in result["verified_services"]:
                    result["verified_services"].append(service)

    # DMARC (check _dmarc.domain)
    try:
        import dns.resolver
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                result["dmarc"] = _parse_dmarc(txt)
    except Exception:
        pass

    return result


def _parse_spf(txt):
    """Parse SPF record into structured data."""
    info = {
        "raw": txt,
        "includes": [],
        "ips": [],
        "policy": "neutral",
    }

    for part in txt.split():
        if part.startswith("include:"):
            info["includes"].append(part.replace("include:", ""))
        elif part.startswith("ip4:") or part.startswith("ip6:"):
            info["ips"].append(part)
        elif part in ("-all", "~all", "+all", "?all"):
            policies = {"-all": "fail (strict)", "~all": "softfail", "+all": "pass (open!)", "?all": "neutral"}
            info["policy"] = policies.get(part, part)

    return info


def _parse_dmarc(txt):
    """Parse DMARC record into structured data."""
    info = {"raw": txt, "policy": "", "subdomain_policy": "", "rua": "", "ruf": "", "pct": "100"}

    for part in txt.split(";"):
        part = part.strip()
        if part.startswith("p="):
            info["policy"] = part[2:]
        elif part.startswith("sp="):
            info["subdomain_policy"] = part[3:]
        elif part.startswith("rua="):
            info["rua"] = part[4:]
        elif part.startswith("ruf="):
            info["ruf"] = part[4:]
        elif part.startswith("pct="):
            info["pct"] = part[4:]

    return info
