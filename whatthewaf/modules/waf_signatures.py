"""WAF/CDN detection signatures — 90+ vendors.

Compiled from WhatWaf, wafw00f, and manual research.
Each signature: name, category, header checks, cookie patterns, body patterns.
"""

import re

SIGNATURES = [
    # --- Cloudflare ---
    {
        "name": "Cloudflare",
        "category": "CDN/WAF",
        "headers": [("cf-ray", None), ("cf-cache-status", None), ("cf-request-id", None), ("server", "cloudflare")],
        "cookies": [r"__cfduid", r"__cf_bm", r"cf_clearance"],
        "body": [r"cloudflare.ray.id", r"attention.required!.\|.cloudflare", r"ddos.protection.by.cloudflare", r"report.uri.*cloudflare\.com"],
    },
    # --- Akamai ---
    {
        "name": "Akamai",
        "category": "CDN/WAF",
        "headers": [("x-akamai-transformed", None), ("x-akamai-request-id", None), ("server", "akamaighost")],
        "cookies": [r"ak_bmsc"],
        "body": [r"access.denied.*akamai", r"akamaighost"],
    },
    # --- AWS CloudFront ---
    {
        "name": "AWS CloudFront",
        "category": "CDN",
        "headers": [("x-amz-cf-id", None), ("x-amz-cf-pop", None), ("server", "cloudfront")],
        "cookies": [r"AWSALB", r"AWSALBCORS"],
        "body": [r"generated.by.cloudfront", r"<RequestId>[0-9a-zA-Z]{16,25}<.RequestId>", r"<Error><Code>AccessDenied"],
    },
    # --- AWS WAF ---
    {
        "name": "AWS WAF",
        "category": "WAF",
        "headers": [("x-amzn-waf-action", None)],
        "cookies": [r"aws-waf-token"],
        "body": [r"request.blocked.*aws", r"x.amz.id.\d+", r"x.amz.request.id"],
    },
    # --- Sucuri ---
    {
        "name": "Sucuri",
        "category": "WAF",
        "headers": [("x-sucuri-id", None), ("x-sucuri-block", None), ("x-sucuri-cache", None), ("server", "sucuri")],
        "cookies": [r"sucuri_cloudproxy"],
        "body": [r"access.denied.*sucuri.website.firewall", r"sucuri.webSite.firewall", r"cloudproxy@sucuri\.net"],
    },
    # --- Imperva / Incapsula ---
    {
        "name": "Imperva Incapsula",
        "category": "WAF",
        "headers": [("x-iinfo", None), ("x-cdn", "incapsula")],
        "cookies": [r"incap_ses_", r"visid_incap_", r"nlbi_"],
        "body": [r"incapsula.incident.id", r"powered.by.incapsula", r"request.unsuccessful.*incapsula"],
    },
    # --- Imperva SecureSphere ---
    {
        "name": "Imperva SecureSphere",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"the.incident.id.(is|number.is)", r"page.cannot.be.displayed.*contact.support", r"the.destination.of.your.request.has.not.been.configured"],
    },
    # --- ModSecurity ---
    {
        "name": "ModSecurity",
        "category": "WAF",
        "headers": [("server", "mod_security")],
        "cookies": [],
        "body": [r"mod.?security", r"this.error.was.generated.by.mod.security", r"blocked.by.mod.security", r"NYOB"],
    },
    # --- ModSecurity OWASP ---
    {
        "name": "ModSecurity OWASP CRS",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"not.acceptable.*additionally.*406.not.acceptable"],
    },
    # --- F5 BIG-IP ---
    {
        "name": "F5 BIG-IP",
        "category": "WAF",
        "headers": [("server", "bigip"), ("server", "big-ip"), ("x-wa-info", None)],
        "cookies": [r"^TS[a-zA-Z0-9]{3,8}=", r"BIGipServer", r"^F5="],
        "body": [r"the.requested.url.was.rejected"],
    },
    # --- F5 ASM ---
    {
        "name": "F5 ASM",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"the.requested.url.was.rejected..please.consult.with.your.administrator"],
    },
    # --- Fastly ---
    {
        "name": "Fastly",
        "category": "CDN",
        "headers": [("x-fastly-request-id", None), ("fastly-debug-digest", None), ("x-served-by", "cache-")],
        "cookies": [],
        "body": [r"fastly.error"],
    },
    # --- Azure CDN / Front Door ---
    {
        "name": "Azure CDN",
        "category": "CDN",
        "headers": [("x-azure-ref", None), ("x-msedge-ref", None), ("x-fd-healthprobe", None)],
        "cookies": [],
        "body": [],
    },
    # --- Barracuda ---
    {
        "name": "Barracuda WAF",
        "category": "WAF",
        "headers": [],
        "cookies": [r"barra.counter.session"],
        "body": [r"barracuda", r"barracuda.networks.*inc"],
    },
    # --- Radware AppWall ---
    {
        "name": "Radware AppWall",
        "category": "WAF",
        "headers": [("x-sl-compstate", None)],
        "cookies": [],
        "body": [r"cloudwebsec.radware.com", r"unauthorized.activity.has.been.detected", r"with.the.following.case.number.in.its.subject"],
    },
    # --- FortiWeb / FortiGate ---
    {
        "name": "FortiWeb",
        "category": "WAF",
        "headers": [],
        "cookies": [r"FORTIWAFSID"],
        "body": [r"powered.by.fortinet", r"fortigate.ips.sensor", r"fortigate", r"\.fgd_icon", r"fortiGate.application.control"],
    },
    # --- Citrix NetScaler ---
    {
        "name": "Citrix NetScaler",
        "category": "WAF",
        "headers": [("cneonction", None), ("x-ns-id", None)],
        "cookies": [r"citrix_ns_id", r"NSC_"],
        "body": [],
    },
    # --- Wordfence ---
    {
        "name": "Wordfence",
        "category": "WAF",
        "headers": [],
        "cookies": [r"wfvt_"],
        "body": [r"generated.by.wordfence", r"your.access.to.this.site.has.been.limited", r">wordfence<"],
    },
    # --- StackPath ---
    {
        "name": "StackPath",
        "category": "CDN/WAF",
        "headers": [("x-hw", None), ("x-sp-url", None)],
        "cookies": [],
        "body": [r"action.that.triggered.the.service.and.blocked", r"sorry,.you.have.been.blocked"],
    },
    # --- DDoS-Guard ---
    {
        "name": "DDoS-Guard",
        "category": "WAF",
        "headers": [("server", "ddos-guard"), ("x-ddos-protection", None)],
        "cookies": [r"__ddg"],
        "body": [r"ddos.guard"],
    },
    # --- Varnish ---
    {
        "name": "Varnish",
        "category": "CDN",
        "headers": [("x-varnish", None), ("via", "varnish")],
        "cookies": [],
        "body": [r"xid.\d+", r"security.by.cachewall", r"access.is.blocked.according.to.our.site.security.policy"],
    },
    # --- Vercel ---
    {
        "name": "Vercel",
        "category": "Hosting",
        "headers": [("x-vercel-id", None), ("x-vercel-cache", None), ("server", "vercel")],
        "cookies": [],
        "body": [],
    },
    # --- Netlify ---
    {
        "name": "Netlify",
        "category": "Hosting",
        "headers": [("x-nf-request-id", None), ("server", "netlify")],
        "cookies": [],
        "body": [],
    },
    # --- 360 WAF ---
    {
        "name": "360 WAF",
        "category": "WAF",
        "headers": [("x-powered-by-360wzb", None)],
        "cookies": [],
        "body": [r"wzws.waf.cgi", r"wangzhan\.360\.cn", r"qianxin.waf", r"360wzws", r"transfer.is.blocked"],
    },
    # --- aeSecure ---
    {
        "name": "aeSecure",
        "category": "WAF",
        "headers": [("aesecure-code", None)],
        "cookies": [],
        "body": [r"aesecure.denied"],
    },
    # --- Airlock ---
    {
        "name": "Airlock",
        "category": "WAF",
        "headers": [],
        "cookies": [r"al[.\-]?(sess|lb)"],
        "body": [],
    },
    # --- Alert Logic ---
    {
        "name": "Alert Logic",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"requested.url.cannot.be.found.*proceed.to.homepage", r"sorry.but.the.page.you.are.looking.for.cannot"],
    },
    # --- AliYunDun ---
    {
        "name": "Alibaba Cloud WAF",
        "category": "WAF",
        "headers": [],
        "cookies": [r"aliyungf_tc"],
        "body": [r"errors?\.aliyun(dun)?\.(com|net)", r"aliyundun"],
    },
    # --- Anquanbao ---
    {
        "name": "Anquanbao",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"aqb_cc.error"],
    },
    # --- AnYu ---
    {
        "name": "AnYu WAF",
        "category": "WAF",
        "headers": [("wzws-ray", None)],
        "cookies": [],
        "body": [r"access.has.been.intercept.*anyu", r"anyu.*green.channel"],
    },
    # --- Armor ---
    {
        "name": "Armor Defense",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"\barmor\b", r"blocked.by.website.protection.from.armour"],
    },
    # --- Apache Generic ---
    {
        "name": "Apache Generic",
        "category": "Web Server",
        "headers": [("server", "apache")],
        "cookies": [],
        "body": [r"you.don.t.have.permission.to.access", r"<address>apache"],
    },
    # --- ASP.NET Generic ---
    {
        "name": "ASP.NET Generic",
        "category": "WAF",
        "headers": [("x-aspnet-version", None)],
        "cookies": [r"asp\.net.sessionid"],
        "body": [r"a.potentially.dangerous.request", r"runtime.error", r"server.error.in.'/'"],
    },
    # --- Apache Traffic Server ---
    {
        "name": "Apache Traffic Server",
        "category": "CDN",
        "headers": [("server", "ats"), ("via", "apachetrafficserver")],
        "cookies": [],
        "body": [],
    },
    # --- Baidu Yunjiasu ---
    {
        "name": "Baidu Yunjiasu",
        "category": "CDN/WAF",
        "headers": [("server", "yunjiasu")],
        "cookies": [],
        "body": [r"yunjiasu"],
    },
    # --- Barikode ---
    {
        "name": "Barikode",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r">barikode<", r"forbidden.access"],
    },
    # --- Bekchy ---
    {
        "name": "Bekchy",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"bekchy.*access.denied", r"bekchy\.com"],
    },
    # --- BinarySEC ---
    {
        "name": "BinarySEC",
        "category": "WAF",
        "headers": [("x-binarysec-via", None), ("x-binarysec-nocache", None)],
        "cookies": [],
        "body": [r"binarysec"],
    },
    # --- BitNinja ---
    {
        "name": "BitNinja",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"bitninja", r"security.check.by.bitninja", r"visitor.anti.*robot.validation"],
    },
    # --- BlockDos ---
    {
        "name": "BlockDos",
        "category": "WAF",
        "headers": [("server", "blockdos")],
        "cookies": [],
        "body": [r"blockdos\.net"],
    },
    # --- Chuangyu ---
    {
        "name": "Chuangyu",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"365cyd\.(com|net)"],
    },
    # --- Cisco ACE XML ---
    {
        "name": "Cisco ACE XML",
        "category": "WAF",
        "headers": [("server", "ace xml gateway")],
        "cookies": [],
        "body": [],
    },
    # --- CodeIgniter ---
    {
        "name": "CodeIgniter",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"the.uri.you.submitted.has.disallowed.characters"],
    },
    # --- Comodo ---
    {
        "name": "Comodo WAF",
        "category": "WAF",
        "headers": [("server", "protected by comodo")],
        "cookies": [],
        "body": [r"protected.by.comodo.waf"],
    },
    # --- ConfigServer CSF ---
    {
        "name": "ConfigServer CSF",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"the.firewall.on.this.server.is.blocking.your.connection"],
    },
    # --- IBM DataPower ---
    {
        "name": "IBM DataPower",
        "category": "WAF",
        "headers": [("x-backside-transport", None)],
        "cookies": [],
        "body": [],
    },
    # --- DenyAll ---
    {
        "name": "DenyAll",
        "category": "WAF",
        "headers": [],
        "cookies": [r"sessioncookie=", r"conditionintercepted"],
        "body": [r"condition.intercepted"],
    },
    # --- DiDiYun ---
    {
        "name": "DiDiYun WAF",
        "category": "WAF",
        "headers": [("server", "didi-slb")],
        "cookies": [],
        "body": [r"didiyun", r"didi(static|yun)?\.com"],
    },
    # --- DoD Enterprise ---
    {
        "name": "DoD Enterprise Protection",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"dod.enterprise.level.protection.system"],
    },
    # --- DOSarrest ---
    {
        "name": "DOSarrest",
        "category": "WAF",
        "headers": [("server", "dosarrest"), ("x-dis-request-id", None)],
        "cookies": [],
        "body": [r"dosarrest"],
    },
    # --- dotDefender ---
    {
        "name": "dotDefender",
        "category": "WAF",
        "headers": [("x-dotdefender-denied", None)],
        "cookies": [],
        "body": [r"dotdefender.blocked.your.request"],
    },
    # --- DynamicWeb ---
    {
        "name": "DynamicWeb",
        "category": "WAF",
        "headers": [("x-403-status-by", "dw")],
        "cookies": [],
        "body": [],
    },
    # --- Edgecast ---
    {
        "name": "Edgecast",
        "category": "CDN",
        "headers": [("server", "ecacc"), ("server", "ecs"), ("x-ec-custom-error", None)],
        "cookies": [],
        "body": [],
    },
    # --- ExpressionEngine ---
    {
        "name": "ExpressionEngine",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"error.-.expressionengine", r"the.uri.you.submitted.has.disallowed.characters.*expressionengine"],
    },
    # --- Gladius ---
    {
        "name": "Gladius",
        "category": "WAF",
        "headers": [],
        "cookies": [r"gladius_blockchain"],
        "body": [],
    },
    # --- Google Cloud Armor ---
    {
        "name": "Google Cloud Armor",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"your.client.has.issued.a.malformed.or.illegal.request", r"systems.have.detected.unusual.traffic", r"blocked.by.g.cloud.security.policy"],
    },
    # --- GreyWizard ---
    {
        "name": "GreyWizard",
        "category": "WAF",
        "headers": [("server", "greywizard")],
        "cookies": [],
        "body": [r"greywizard", r"grey.wizard.block"],
    },
    # --- InfoSafe ---
    {
        "name": "InfoSafe",
        "category": "WAF",
        "headers": [("server", "infosafe")],
        "cookies": [],
        "body": [r"infosafe", r"7i24\.(com|net)"],
    },
    # --- Instart Logic ---
    {
        "name": "Instart Logic",
        "category": "CDN",
        "headers": [("x-instart-request-id", None), ("x-instart-cachekeymod", None)],
        "cookies": [],
        "body": [],
    },
    # --- Janusec ---
    {
        "name": "Janusec",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"janusec", r"janusec\.(com|net|org)"],
    },
    # --- Jiasule ---
    {
        "name": "Jiasule",
        "category": "WAF",
        "headers": [("server", "jiasule")],
        "cookies": [r"jsl_?tracking", r"__?jsluid"],
        "body": [r"notice.jiasule", r"jiasule\.(com|net)"],
    },
    # --- Malcare ---
    {
        "name": "Malcare",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"malcare", r"powered.by.*malcare", r"firewall.*powered.by.*blogvault"],
    },
    # --- NexusGuard ---
    {
        "name": "NexusGuard",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"nexus.?guard", r"nexusguard\.com.wafpage"],
    },
    # --- Palo Alto ---
    {
        "name": "Palo Alto",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"blocked.in.accordance.with.company.policy", r"Virus.Spyware.Download.Blocked", r"paloaltonetworks"],
    },
    # --- PerimeterX ---
    {
        "name": "PerimeterX",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"access.*denied.*automation.tool", r"perimeterx.*whywasiblocked", r"perimeterx", r"client\.perimeterx"],
    },
    # --- pkSecurity ---
    {
        "name": "pkSecurityModule",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"pkSecurityModule.*Security.Alert", r"safety.critical.request.was.discovered.and.blocked"],
    },
    # --- Powerful Firewall ---
    {
        "name": "Powerful Firewall",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"Powerful Firewall", r"tiny\.cc.powerful.firewall"],
    },
    # --- RSFirewall ---
    {
        "name": "RSFirewall",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"com.rsfirewall", r"rsfirewall"],
    },
    # --- Sabre ---
    {
        "name": "Sabre",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"dxsupport@sabre\.com"],
    },
    # --- SafeDog ---
    {
        "name": "SafeDog",
        "category": "WAF",
        "headers": [("server", "safedog")],
        "cookies": [r"safedog"],
        "body": [r"safedog", r"waf.\d+.\d+"],
    },
    # --- SecuPress ---
    {
        "name": "SecuPress",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"secupress", r"block.id.*bad.url.contents"],
    },
    # --- Shadow Daemon ---
    {
        "name": "Shadow Daemon",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"request.forbidden.by.administrative.rules"],
    },
    # --- Shield Security ---
    {
        "name": "Shield Security",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"blocked.by.the.shield", r"transgression.*against.this", r"url.*form.or.cookie.data.wasn.t.appropriate"],
    },
    # --- SiteGuard ---
    {
        "name": "SiteGuard",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"Powered.by.SiteGuard", r"refuse.to.browse"],
    },
    # --- SonicWall ---
    {
        "name": "SonicWall",
        "category": "WAF",
        "headers": [("server", "sonicwall")],
        "cookies": [],
        "body": [r"blocked.by.the.SonicWALL", r"Dell.SonicWALL", r"nsa.banner", r"policy.this.site.is.blocked"],
    },
    # --- Squid ---
    {
        "name": "Squid Proxy",
        "category": "CDN",
        "headers": [("server", "squid"), ("x-squid-error", None)],
        "cookies": [],
        "body": [r"Access.control.configuration.prevents", r"X.Squid.Error"],
    },
    # --- Stingray ---
    {
        "name": "Stingray",
        "category": "WAF",
        "headers": [],
        "cookies": [r"X-Mapping-"],
        "body": [],
    },
    # --- StrictHttpFirewall ---
    {
        "name": "StrictHttpFirewall",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"the.request.was.rejected.because.the.url.contained.a.potentially.malicious.string"],
    },
    # --- Teros ---
    {
        "name": "Teros",
        "category": "WAF",
        "headers": [],
        "cookies": [r"st8(id|.wa|.wf)"],
        "body": [],
    },
    # --- UEWaf ---
    {
        "name": "UEWaf",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"ucloud", r"uewaf.deny.pages"],
    },
    # --- UrlScan ---
    {
        "name": "UrlScan",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"rejected.by.url.scan"],
    },
    # --- Viettel ---
    {
        "name": "Viettel WAF",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"access.denied.*viettel.waf", r"viettel.waf.system", r"cloudrity\.com"],
    },
    # --- Wallarm ---
    {
        "name": "Wallarm",
        "category": "WAF",
        "headers": [("x-wallarm-waf-check", None), ("server", "wallarm")],
        "cookies": [],
        "body": [r"wallarm"],
    },
    # --- WatchGuard ---
    {
        "name": "WatchGuard",
        "category": "WAF",
        "headers": [("server", "watchguard")],
        "cookies": [],
        "body": [r"watchguard.firewall", r"watchguard.technologies"],
    },
    # --- WebKnight ---
    {
        "name": "WebKnight",
        "category": "WAF",
        "headers": [("server", "webknight")],
        "cookies": [],
        "body": [r"webknight"],
    },
    # --- WebSEAL ---
    {
        "name": "IBM WebSEAL",
        "category": "WAF",
        "headers": [("server", "webseal")],
        "cookies": [],
        "body": [r"webseal.error.message.template", r"webseal.server.received.an.invalid"],
    },
    # --- West263 ---
    {
        "name": "West263",
        "category": "CDN",
        "headers": [("x-cache", "wt")],
        "cookies": [],
        "body": [],
    },
    # --- WTS-WAF ---
    {
        "name": "WTS-WAF",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"wts.wa(f)?"],
    },
    # --- Xuanwudun ---
    {
        "name": "Xuanwudun",
        "category": "WAF",
        "headers": [],
        "cookies": [],
        "body": [r"class=.db?waf"],
    },
    # --- Yundun ---
    {
        "name": "Yundun",
        "category": "WAF",
        "headers": [("server", "yundun"), ("x-cache", "yundun")],
        "cookies": [r"yd.cookie"],
        "body": [r"YUNDUN", r"yundun\.com"],
    },
    # --- Yunsuo ---
    {
        "name": "Yunsuo",
        "category": "WAF",
        "headers": [],
        "cookies": [r"yunsuo.session"],
        "body": [r"yunsuologo", r"yunsuo.session"],
    },
    # --- Zscaler ---
    {
        "name": "Zscaler",
        "category": "WAF",
        "headers": [("server", "zscaler")],
        "cookies": [],
        "body": [r"zscaler"],
    },
    # --- Reblaze ---
    {
        "name": "Reblaze",
        "category": "WAF",
        "headers": [("server", "reblaze")],
        "cookies": [r"rbzid"],
        "body": [r"reblaze"],
    },
    # --- KeyCDN ---
    {
        "name": "KeyCDN",
        "category": "CDN",
        "headers": [("server", "keycdn"), ("x-pull", None)],
        "cookies": [],
        "body": [],
    },
    # --- MaxCDN ---
    {
        "name": "MaxCDN",
        "category": "CDN",
        "headers": [("server", "netdna"), ("x-cdn", "maxcdn")],
        "cookies": [],
        "body": [],
    },
    # --- LiteSpeed ---
    {
        "name": "LiteSpeed",
        "category": "Web Server",
        "headers": [("server", "litespeed")],
        "cookies": [],
        "body": [r"litespeed.web.server"],
    },
    # --- Nginx Generic ---
    {
        "name": "Nginx Generic",
        "category": "Web Server",
        "headers": [("server", "nginx")],
        "cookies": [],
        "body": [],
    },
]


def detect_waf(headers, cookies, body, status_code):
    """Run all WAF signatures against a response.

    Returns list of dicts: name, category, confidence, evidence
    """
    detections = []
    body_lower = body.lower() if body else ""
    cookie_str = "\n".join(cookies).lower()

    for sig in SIGNATURES:
        evidence = []
        score = 0.0

        for hdr_name, hdr_pattern in sig["headers"]:
            val = _get_header(headers, hdr_name)
            if val is not None:
                if hdr_pattern is None:
                    evidence.append(f"header:{hdr_name}")
                    score += 0.5
                elif hdr_pattern.lower() in val.lower():
                    evidence.append(f"header:{hdr_name}={val}")
                    score += 0.5

        for cpat in sig["cookies"]:
            try:
                if re.search(cpat, cookie_str, re.IGNORECASE):
                    evidence.append(f"cookie:{cpat}")
                    score += 0.4
            except re.error:
                pass

        for bpat in sig["body"]:
            try:
                if re.search(bpat, body_lower, re.IGNORECASE):
                    evidence.append(f"body:{bpat}")
                    score += 0.3
            except re.error:
                pass

        if evidence:
            confidence = min(score, 1.0)
            detections.append({
                "name": sig["name"],
                "category": sig["category"],
                "confidence": round(confidence, 2),
                "evidence": evidence,
            })

    detections.sort(key=lambda d: d["confidence"], reverse=True)
    return detections


def _get_header(headers, name):
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None
