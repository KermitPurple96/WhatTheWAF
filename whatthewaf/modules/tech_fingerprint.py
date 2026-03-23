"""Technology fingerprinting — web servers, frameworks, CMS, JS libs, analytics.

Comprehensive signatures inspired by Wappalyzer and WhatWeb.
"""

import re

# (header_name_lower, value_pattern, tech_name, category)
HEADER_TECHS = [
    # Web Servers
    ("server", "nginx", "Nginx", "Web Server"),
    ("server", "apache", "Apache", "Web Server"),
    ("server", "litespeed", "LiteSpeed", "Web Server"),
    ("server", "iis", "Microsoft IIS", "Web Server"),
    ("server", "openresty", "OpenResty", "Web Server"),
    ("server", "caddy", "Caddy", "Web Server"),
    ("server", "envoy", "Envoy", "Web Server"),
    ("server", "gunicorn", "Gunicorn", "Web Server"),
    ("server", "uvicorn", "Uvicorn", "Web Server"),
    ("server", "tengine", "Tengine", "Web Server"),
    ("server", "cowboy", "Erlang Cowboy", "Web Server"),
    ("server", "lighttpd", "Lighttpd", "Web Server"),
    ("server", "cherokee", "Cherokee", "Web Server"),
    ("server", "hiawatha", "Hiawatha", "Web Server"),
    ("server", "traefik", "Traefik", "Web Server"),
    ("server", "kestrel", "Kestrel", "Web Server"),
    ("server", "jetty", "Jetty", "Web Server"),
    ("server", "tomcat", "Apache Tomcat", "Web Server"),
    ("server", "wildfly", "WildFly", "Web Server"),
    ("server", "weblogic", "Oracle WebLogic", "Web Server"),
    ("server", "websphere", "IBM WebSphere", "Web Server"),
    ("server", "yaws", "Yaws", "Web Server"),
    ("server", "h2o", "H2O", "Web Server"),
    ("server", "phusion", "Phusion Passenger", "Web Server"),
    ("server", "thin", "Thin", "Web Server"),
    ("server", "puma", "Puma", "Web Server"),
    ("server", "unicorn", "Unicorn", "Web Server"),
    ("server", "werkzeug", "Werkzeug", "Web Server"),
    ("server", "daphne", "Daphne", "Web Server"),
    ("server", "hypercorn", "Hypercorn", "Web Server"),
    # Hosting providers via Server header
    ("server", "ovhcloud", "OVHcloud", "Hosting"),
    ("server", "ovh-", "OVH", "Hosting"),
    ("server", "hetzner", "Hetzner", "Hosting"),
    ("server", "digitalocean", "DigitalOcean", "Hosting"),
    ("server", "linode", "Linode", "Hosting"),
    ("server", "vultr", "Vultr", "Hosting"),
    ("server", "heroku", "Heroku", "Hosting"),
    ("server", "github.com", "GitHub Pages", "Hosting"),
    ("server", "awselb", "AWS ELB", "Hosting"),
    ("server", "amazons3", "Amazon S3", "Hosting"),
    ("server", "gws", "Google Web Server", "Hosting"),
    ("server", "gse", "Google Servlet Engine", "Hosting"),
    ("server", "fly", "Fly.io", "Hosting"),
    ("server", "deno", "Deno Deploy", "Hosting"),
    ("server", "bunny", "BunnyCDN", "CDN"),
    ("server", "surge", "Surge.sh", "Hosting"),
    # Frameworks
    ("x-powered-by", "php", "PHP", "Framework"),
    ("x-powered-by", "asp.net", "ASP.NET", "Framework"),
    ("x-powered-by", "express", "Express.js", "Framework"),
    ("x-powered-by", "next.js", "Next.js", "Framework"),
    ("x-powered-by", "nuxt", "Nuxt.js", "Framework"),
    ("x-powered-by", "django", "Django", "Framework"),
    ("x-powered-by", "flask", "Flask", "Framework"),
    ("x-powered-by", "rails", "Ruby on Rails", "Framework"),
    ("x-powered-by", "laravel", "Laravel", "Framework"),
    ("x-powered-by", "symfony", "Symfony", "Framework"),
    ("x-powered-by", "cake", "CakePHP", "Framework"),
    ("x-powered-by", "perl", "Perl", "Framework"),
    ("x-powered-by", "servlet", "Java Servlet", "Framework"),
    ("x-powered-by", "spring", "Spring", "Framework"),
    ("x-powered-by", "jsf", "JavaServer Faces", "Framework"),
    ("x-powered-by", "plone", "Plone", "CMS"),
    ("x-powered-by", "craft", "Craft CMS", "CMS"),
    ("x-powered-by", "w3 total cache", "W3 Total Cache", "Plugin"),
    # CMS Generators
    ("x-generator", "wordpress", "WordPress", "CMS"),
    ("x-generator", "drupal", "Drupal", "CMS"),
    ("x-generator", "joomla", "Joomla", "CMS"),
    ("x-generator", "typo3", "TYPO3", "CMS"),
    ("x-generator", "hugo", "Hugo", "CMS"),
    ("x-generator", "gatsby", "Gatsby", "CMS"),
    ("x-generator", "hexo", "Hexo", "CMS"),
    ("x-generator", "ghost", "Ghost", "CMS"),
    ("x-generator", "jekyll", "Jekyll", "CMS"),
    ("x-generator", "pelican", "Pelican", "CMS"),
    ("x-generator", "nikola", "Nikola", "CMS"),
    ("x-generator", "mkdocs", "MkDocs", "CMS"),
    ("x-generator", "docusaurus", "Docusaurus", "CMS"),
    ("x-generator", "eleventy", "Eleventy", "CMS"),
    ("x-generator", "astro", "Astro", "CMS"),
    ("x-generator", "statamic", "Statamic", "CMS"),
    ("x-generator", "contentful", "Contentful", "CMS"),
    ("x-generator", "sitecore", "Sitecore", "CMS"),
    ("x-generator", "umbraco", "Umbraco", "CMS"),
    ("x-generator", "kentico", "Kentico", "CMS"),
    ("x-generator", "sitefinity", "Sitefinity", "CMS"),
    ("x-generator", "episerver", "Episerver", "CMS"),
    ("x-generator", "concrete5", "Concrete5", "CMS"),
    ("x-generator", "silverstripe", "SilverStripe", "CMS"),
    ("x-generator", "textpattern", "Textpattern", "CMS"),
    ("x-generator", "modx", "MODX", "CMS"),
    ("x-generator", "grav", "Grav", "CMS"),
    ("x-generator", "october", "October CMS", "CMS"),
    ("x-generator", "bolt", "Bolt CMS", "CMS"),
    # Hosting / Platform
    ("x-shopify-stage", "", "Shopify", "Hosting"),
    ("x-github-request-id", "", "GitHub Pages", "Hosting"),
    ("x-pantheon-styx-hostname", "", "Pantheon", "Hosting"),
    ("x-kinsta-cache", "", "Kinsta", "Hosting"),
    ("x-wpe-backend", "", "WP Engine", "Hosting"),
    ("x-ah-environment", "", "Acquia", "Hosting"),
    ("x-hacker", "automattic", "WordPress.com", "Hosting"),
    ("x-flywheel-cache", "", "Flywheel", "Hosting"),
    ("x-squarespace-did", "", "Squarespace", "Hosting"),
    ("x-wix-request-id", "", "Wix", "Hosting"),
    ("x-webflow-info", "", "Webflow", "Hosting"),
    ("x-bubble-perf", "", "Bubble", "Hosting"),
    ("x-render-origin-server", "", "Render", "Hosting"),
    ("x-railway-request-id", "", "Railway", "Hosting"),
    # Caching
    ("x-cache", "hit from", "CDN Cache", "Cache"),
    ("x-drupal-cache", "", "Drupal Cache", "Cache"),
    ("x-litespeed-cache", "", "LiteSpeed Cache", "Cache"),
    ("x-proxy-cache", "", "Proxy Cache", "Cache"),
]

# (cookie_pattern, tech_name, category)
COOKIE_TECHS = [
    (r"PHPSESSID", "PHP", "Framework"),
    (r"JSESSIONID", "Java", "Framework"),
    (r"ASP\.NET_SessionId", "ASP.NET", "Framework"),
    (r"laravel_session", "Laravel", "Framework"),
    (r"rack\.session", "Ruby/Rack", "Framework"),
    (r"connect\.sid", "Node.js/Express", "Framework"),
    (r"_rails_session", "Ruby on Rails", "Framework"),
    (r"ci_session", "CodeIgniter", "Framework"),
    (r"symfony", "Symfony", "Framework"),
    (r"cakephp", "CakePHP", "Framework"),
    (r"yii_csrf_token", "Yii", "Framework"),
    (r"zend_session", "Zend", "Framework"),
    (r"slim_session", "Slim", "Framework"),
    (r"mojolicious", "Mojolicious", "Framework"),
    (r"play_session", "Play Framework", "Framework"),
    (r"flask_session", "Flask", "Framework"),
    # CMS cookies
    (r"wp-settings", "WordPress", "CMS"),
    (r"wordpress_logged_in", "WordPress", "CMS"),
    (r"wordpress_test_cookie", "WordPress", "CMS"),
    (r"wp_woocommerce_session", "WooCommerce", "CMS"),
    (r"Drupal\.", "Drupal", "CMS"),
    (r"joomla", "Joomla", "CMS"),
    (r"PrestaShop", "PrestaShop", "CMS"),
    (r"MAGENTO", "Magento", "CMS"),
    (r"frontend=", "Magento", "CMS"),
    (r"typo3", "TYPO3", "CMS"),
    (r"october_session", "October CMS", "CMS"),
    (r"craft_csrf_token", "Craft CMS", "CMS"),
    (r"ghost-admin", "Ghost", "CMS"),
    (r"umbraco", "Umbraco", "CMS"),
    (r"sitecore", "Sitecore", "CMS"),
    (r"ep-user", "Episerver", "CMS"),
    (r"concrete5", "Concrete5", "CMS"),
    (r"silverstripe", "SilverStripe", "CMS"),
    (r"plone", "Plone", "CMS"),
    (r"kentico", "Kentico", "CMS"),
    (r"sitefinity", "Sitefinity", "CMS"),
    (r"textpattern", "Textpattern", "CMS"),
    (r"modx_session", "MODX", "CMS"),
    (r"grav-site", "Grav", "CMS"),
    (r"statamic_session", "Statamic", "CMS"),
    (r"_discourse_session", "Discourse", "CMS"),
    (r"_xf_session", "XenForo", "CMS"),
    (r"mybb", "MyBB", "CMS"),
    (r"vbulletin", "vBulletin", "CMS"),
    (r"ipb_session", "Invision Community", "CMS"),
    (r"moodle", "Moodle", "CMS"),
    (r"mediawiki", "MediaWiki", "CMS"),
    (r"DokuWiki", "DokuWiki", "CMS"),
    # Ecommerce
    (r"_shopify_s", "Shopify", "Ecommerce"),
    (r"cart_id", "Shopify", "Ecommerce"),
    (r"wc_session", "WooCommerce", "Ecommerce"),
    (r"bigcommerce", "BigCommerce", "Ecommerce"),
    (r"oscsid", "osCommerce", "Ecommerce"),
    (r"OpenCart", "OpenCart", "Ecommerce"),
    (r"zen_cart", "Zen Cart", "Ecommerce"),
    # Misc
    (r"SERVERID", "HAProxy", "Load Balancer"),
    (r"BNI_persistence", "F5 BIG-IP", "Load Balancer"),
    (r"_ga=", "Google Analytics", "Analytics"),
    (r"_fbp=", "Facebook Pixel", "Analytics"),
]

# (body_pattern, tech_name, category)
BODY_TECHS = [
    # CMS
    (r"wp-content/", "WordPress", "CMS"),
    (r"wp-includes/", "WordPress", "CMS"),
    (r'wp-json/', "WordPress", "CMS"),
    (r'<meta name="generator" content="WordPress', "WordPress", "CMS"),
    (r"drupal\.settings", "Drupal", "CMS"),
    (r"/sites/default/files", "Drupal", "CMS"),
    (r"/misc/drupal\.js", "Drupal", "CMS"),
    (r'Drupal\.behaviors', "Drupal", "CMS"),
    (r"com_content", "Joomla", "CMS"),
    (r"/media/jui/", "Joomla", "CMS"),
    (r'<meta name="generator" content="Joomla', "Joomla", "CMS"),
    (r'Mage\.Cookies', "Magento", "CMS"),
    (r"/skin/frontend/", "Magento", "CMS"),
    (r"/static/version", "Magento 2", "CMS"),
    (r'<meta name="generator" content="TYPO3', "TYPO3", "CMS"),
    (r"typo3conf/", "TYPO3", "CMS"),
    (r"typo3temp/", "TYPO3", "CMS"),
    (r'content="Ghost', "Ghost", "CMS"),
    (r"ghost\.io", "Ghost", "CMS"),
    (r'content="Hugo', "Hugo", "CMS"),
    (r'content="Jekyll', "Jekyll", "CMS"),
    (r'content="Gatsby', "Gatsby", "CMS"),
    (r'content="Hexo', "Hexo", "CMS"),
    (r"__gatsby", "Gatsby", "CMS"),
    (r'content="Docusaurus', "Docusaurus", "CMS"),
    (r"_astro/", "Astro", "CMS"),
    (r'content="Eleventy', "Eleventy", "CMS"),
    (r"/umbraco/", "Umbraco", "CMS"),
    (r"sitecore", "Sitecore", "CMS"),
    (r'content="Contentful', "Contentful", "CMS"),
    (r"kentico", "Kentico", "CMS"),
    (r"concrete5", "Concrete5", "CMS"),
    (r"silverstripe", "SilverStripe", "CMS"),
    (r"textpattern", "Textpattern", "CMS"),
    (r"/assets/components/", "MODX", "CMS"),
    (r'content="MODX', "MODX", "CMS"),
    (r'content="Craft CMS', "Craft CMS", "CMS"),
    (r'content="October CMS', "October CMS", "CMS"),
    (r'content="Grav', "Grav", "CMS"),
    (r'content="Statamic', "Statamic", "CMS"),
    (r'content="Bolt', "Bolt CMS", "CMS"),
    (r"PrestaShop", "PrestaShop", "CMS"),
    (r"prestashop", "PrestaShop", "CMS"),
    (r'content="Squarespace', "Squarespace", "Hosting"),
    (r"squarespace\.com", "Squarespace", "Hosting"),
    (r"static\.squarespace", "Squarespace", "Hosting"),
    (r"wix\.com", "Wix", "Hosting"),
    (r"wixstatic\.com", "Wix", "Hosting"),
    (r"webflow\.com", "Webflow", "Hosting"),
    (r"cdn\.shopify\.com", "Shopify", "Ecommerce"),
    (r"shopify\.com/s/files", "Shopify", "Ecommerce"),
    (r"myshopify\.com", "Shopify", "Ecommerce"),
    (r"bigcommerce\.com", "BigCommerce", "Ecommerce"),
    (r"osCommerce", "osCommerce", "Ecommerce"),
    (r"opencart", "OpenCart", "Ecommerce"),
    (r"zencart", "Zen Cart", "Ecommerce"),
    # Forums
    (r"/discourse/", "Discourse", "CMS"),
    (r"xenforo", "XenForo", "CMS"),
    (r"vbulletin", "vBulletin", "CMS"),
    (r"phpbb", "phpBB", "CMS"),
    (r"Invision Community", "Invision Community", "CMS"),
    (r"mybb", "MyBB", "CMS"),
    (r"smf_images", "SMF", "CMS"),
    # Wiki/LMS
    (r"mediawiki", "MediaWiki", "CMS"),
    (r"DokuWiki", "DokuWiki", "CMS"),
    (r"confluence", "Confluence", "CMS"),
    (r"moodle", "Moodle", "CMS"),
    # JS Frameworks
    (r"_next/static", "Next.js", "Framework"),
    (r"/_next/data/", "Next.js", "Framework"),
    (r"__next", "Next.js", "Framework"),
    (r"__nuxt", "Nuxt.js", "Framework"),
    (r"/_nuxt/", "Nuxt.js", "Framework"),
    (r"ng-version=", "Angular", "Framework"),
    (r"ng-app=", "AngularJS", "Framework"),
    (r'<div id="app".*vue', "Vue.js", "Framework"),
    (r"__vue_ssr_context__", "Vue.js", "Framework"),
    (r"react-root", "React", "Framework"),
    (r'data-reactroot', "React", "Framework"),
    (r"__REACT", "React", "Framework"),
    (r"svelte", "Svelte", "Framework"),
    (r"__sveltekit", "SvelteKit", "Framework"),
    (r"ember-view", "Ember.js", "Framework"),
    (r"backbone\.js", "Backbone.js", "Framework"),
    (r"remix\.run", "Remix", "Framework"),
    (r"/_remix/", "Remix", "Framework"),
    # JS Libraries & UI
    (r"jquery[/\.\-]", "jQuery", "Library"),
    (r"jquery\.min\.js", "jQuery", "Library"),
    (r"jquery-ui", "jQuery UI", "Library"),
    (r"jquery-migrate", "jQuery Migrate", "Library"),
    (r"bootstrap[/\.\-]", "Bootstrap", "Library"),
    (r"bootstrap\.min\.(css|js)", "Bootstrap", "Library"),
    (r"tailwindcss", "Tailwind CSS", "Library"),
    (r"tailwind\.min\.css", "Tailwind CSS", "Library"),
    (r"font-?awesome", "Font Awesome", "Library"),
    (r"fontawesome", "Font Awesome", "Library"),
    (r"material-?icons", "Material Icons", "Library"),
    (r"ionicons", "Ionicons", "Library"),
    (r"animate\.css", "Animate.css", "Library"),
    (r"aos\.js|data-aos=", "AOS (Animate On Scroll)", "Library"),
    (r"wow\.js|class=\"wow ", "WOW.js", "Library"),
    (r"gsap|greensock", "GSAP", "Library"),
    (r"three\.js|three\.min\.js", "Three.js", "Library"),
    (r"d3\.js|d3\.min\.js|d3\.v\d", "D3.js", "Library"),
    (r"chart\.js|chartjs", "Chart.js", "Library"),
    (r"highcharts", "Highcharts", "Library"),
    (r"moment\.js|moment\.min\.js", "Moment.js", "Library"),
    (r"lodash|_\.min\.js", "Lodash", "Library"),
    (r"underscore\.js", "Underscore.js", "Library"),
    (r"axios", "Axios", "Library"),
    (r"socket\.io", "Socket.io", "Library"),
    (r"modernizr", "Modernizr", "Library"),
    (r"polyfill\.io", "Polyfill.io", "Library"),
    (r"lazysizes|lazyload|loading=\"lazy\"", "Lazy Loading", "Library"),
    (r"lottie", "Lottie", "Library"),
    (r"swiper", "Swiper", "Library"),
    (r"slick[/\.\-]|slick\.min", "Slick Slider", "Library"),
    (r"owl\.carousel|owlcarousel", "Owl Carousel", "Library"),
    (r"lightbox", "Lightbox", "Library"),
    (r"fancybox", "Fancybox", "Library"),
    (r"magnific-popup", "Magnific Popup", "Library"),
    (r"photoswipe", "PhotoSwipe", "Library"),
    (r"isotope", "Isotope", "Library"),
    (r"masonry", "Masonry", "Library"),
    (r"select2", "Select2", "Library"),
    (r"chosen\.js|chosen\.min", "Chosen", "Library"),
    (r"datatables", "DataTables", "Library"),
    (r"tinymce", "TinyMCE", "Library"),
    (r"ckeditor", "CKEditor", "Library"),
    (r"quill\.js|quilljs", "Quill", "Library"),
    (r"alpinejs|x-data=", "Alpine.js", "Framework"),
    (r"htmx\.org|hx-get=|hx-post=", "htmx", "Framework"),
    (r"stimulus", "Stimulus", "Framework"),
    (r"turbo\.js|turbolinks", "Turbo/Turbolinks", "Framework"),
    (r"livewire", "Laravel Livewire", "Framework"),
    (r"inertia", "Inertia.js", "Framework"),
    (r"webpack", "Webpack", "Build Tool"),
    (r"vite", "Vite", "Build Tool"),
    (r"parcel", "Parcel", "Build Tool"),
    # Fonts
    (r"fonts\.googleapis\.com", "Google Fonts", "Font"),
    (r"fonts\.gstatic\.com", "Google Fonts", "Font"),
    (r"use\.typekit\.net", "Adobe Fonts (Typekit)", "Font"),
    (r"fast\.fonts\.net", "Fonts.com", "Font"),
    (r"cloud\.typography", "Cloud.typography (Hoefler)", "Font"),
    (r"webfont\.js|WebFont\.load", "WebFont Loader", "Font"),
    (r"font-display:\s*swap", "Font Display Swap", "Font"),
    # Analytics & Marketing
    (r"google-analytics\.com|analytics\.js|ga\.js", "Google Analytics", "Analytics"),
    (r"gtag/js\?id=", "Google Tag Manager", "Analytics"),
    (r"googletagmanager\.com", "Google Tag Manager", "Analytics"),
    (r"connect\.facebook\.net|fbevents\.js", "Facebook Pixel", "Analytics"),
    (r"snap\.licdn\.com|linkedin\.com/insight", "LinkedIn Insight Tag", "Analytics"),
    (r"static\.ads-twitter\.com|t\.co/i/adsct", "Twitter Pixel", "Analytics"),
    (r"bat\.bing\.com|clarity\.ms", "Microsoft Clarity/UET", "Analytics"),
    (r"hotjar\.com|hj\(", "Hotjar", "Analytics"),
    (r"cdn\.segment\.com|analytics\.js", "Segment", "Analytics"),
    (r"plausible\.io", "Plausible", "Analytics"),
    (r"matomo\.js|piwik\.js", "Matomo", "Analytics"),
    (r"fathom", "Fathom Analytics", "Analytics"),
    (r"mixpanel", "Mixpanel", "Analytics"),
    (r"amplitude", "Amplitude", "Analytics"),
    (r"heap-\d+\.js|heap\.load", "Heap", "Analytics"),
    (r"intercom", "Intercom", "Marketing"),
    (r"crisp\.chat", "Crisp", "Marketing"),
    (r"tawk\.to", "Tawk.to", "Marketing"),
    (r"livechatinc\.com|livechat", "LiveChat", "Marketing"),
    (r"zendesk", "Zendesk", "Marketing"),
    (r"freshdesk|freshchat", "Freshworks", "Marketing"),
    (r"drift\.com", "Drift", "Marketing"),
    (r"hubspot", "HubSpot", "Marketing"),
    (r"mailchimp", "Mailchimp", "Marketing"),
    (r"optimizely", "Optimizely", "Marketing"),
    (r"abtasty", "AB Tasty", "Marketing"),
    (r"cookiebot", "Cookiebot", "Security"),
    (r"onetrust", "OneTrust", "Security"),
    (r"cookie-?consent|cookie-?banner|cookie-?notice", "Cookie Consent", "Security"),
    (r"gdpr", "GDPR Notice", "Security"),
    (r"recaptcha", "reCAPTCHA", "Security"),
    (r"hcaptcha\.com", "hCaptcha", "Security"),
    (r"turnstile.*cloudflare", "Cloudflare Turnstile", "Security"),
    # Payment
    (r"stripe\.com|stripe\.js", "Stripe", "Payment"),
    (r"paypal\.com|paypalobjects", "PayPal", "Payment"),
    (r"braintree", "Braintree", "Payment"),
    (r"adyen", "Adyen", "Payment"),
    (r"klarna", "Klarna", "Payment"),
    # Meta/HTML features
    (r'<meta.*charset.*utf-8', "UTF-8", "Encoding"),
    (r'<meta.*viewport', "Responsive (viewport)", "Design"),
    (r'<meta.*og:title', "Open Graph", "SEO"),
    (r'<meta.*twitter:card', "Twitter Cards", "SEO"),
    (r"schema\.org|application/ld\+json", "Schema.org / JSON-LD", "SEO"),
    (r"sitemap\.xml", "XML Sitemap", "SEO"),
    (r"service-?worker|sw\.js", "Service Worker", "PWA"),
    (r"manifest\.json|web-?app-?manifest", "Web App Manifest", "PWA"),
]


def fingerprint_tech(headers, cookies, body):
    """Detect technologies from HTTP response.

    Returns list of dicts: name, category, version, source_type, line, matched, evidence
    """
    results = []
    seen = set()

    # Pre-compute line index for body
    body_text = body or ""
    _line_breaks = _build_line_index(body_text)

    def _body_line(pos):
        """Get 1-based line number from character position."""
        lo, hi = 0, len(_line_breaks)
        while lo < hi:
            mid = (lo + hi) // 2
            if _line_breaks[mid] <= pos:
                lo = mid + 1
            else:
                hi = mid
        return lo

    # Header-based
    for hdr_name, pattern, tech, category in HEADER_TECHS:
        val = _get_header(headers, hdr_name)
        if val is not None:
            if not pattern or pattern.lower() in val.lower():
                if tech not in seen:
                    seen.add(tech)
                    version = _extract_version_from_header(hdr_name, val, tech)
                    results.append({"name": tech, "category": category, "version": version,
                                    "source_type": "header", "line": 0,
                                    "matched": f"{hdr_name}: {val}",
                                    "evidence": f"header:{hdr_name}"})

    # x-powered-by
    xpb = _get_header(headers, "x-powered-by")
    if xpb and xpb not in seen:
        already = any(r["name"].lower() in xpb.lower() for r in results)
        if not already:
            seen.add(xpb)
            version = _extract_version(xpb)
            results.append({"name": xpb, "category": "Framework", "version": version,
                            "source_type": "header", "line": 0,
                            "matched": f"X-Powered-By: {xpb}",
                            "evidence": f"header:x-powered-by"})

    # Cookie-based
    cookie_str = "\n".join(cookies)
    for pattern, tech, category in COOKIE_TECHS:
        if tech not in seen:
            try:
                m = re.search(pattern, cookie_str, re.IGNORECASE)
                if m:
                    seen.add(tech)
                    matched = m.group(0)[:80]
                    results.append({"name": tech, "category": category, "version": "",
                                    "source_type": "cookie", "line": 0,
                                    "matched": matched,
                                    "evidence": f"cookie"})
            except re.error:
                pass

    # Meta generator tags
    for m in re.finditer(
        r'<meta[^>]*name=["\x27]generator["\x27][^>]*content=["\x27]([^"\x27>]+)',
        body_text, re.IGNORECASE
    ):
        gen_value = m.group(1).strip()
        if not gen_value:
            continue
        gen_match = re.match(r'^(.+?)[/ ]+(\d+[\d.]+\S*)', gen_value)
        if gen_match:
            gen_name = gen_match.group(1).strip()
            gen_ver = gen_match.group(2).strip()
        else:
            gen_name = gen_value
            gen_ver = ""
        if gen_name not in seen:
            seen.add(gen_name)
            cat = _guess_generator_category(gen_name)
            line = _body_line(m.start())
            tag_text = m.group(0).strip()
            if len(tag_text) > 100:
                tag_text = tag_text[:97] + "..."
            results.append({"name": gen_name, "category": cat, "version": gen_ver,
                            "source_type": "html", "line": line,
                            "matched": tag_text,
                            "evidence": f"meta:generator"})

    # Script/link src version extraction
    for m in re.finditer(r'(?:src|href)=["\x27]([^"\x27]+)["\x27]', body_text):
        url = m.group(1)
        line = _body_line(m.start())
        _extract_tech_from_url(url, seen, results, line)

    # Body pattern-based
    body_lower = body_text.lower()
    for pattern, tech, category in BODY_TECHS:
        if tech not in seen:
            try:
                m = re.search(pattern, body_lower, re.IGNORECASE)
                if m:
                    seen.add(tech)
                    version = _extract_version_from_body(body_text, tech)
                    line = _body_line(m.start())
                    # Get the full line of source where match was found
                    line_start = body_text.rfind("\n", 0, m.start()) + 1
                    line_end = body_text.find("\n", m.end())
                    if line_end == -1:
                        line_end = min(m.end() + 80, len(body_text))
                    raw_line = body_text[line_start:line_end].strip()
                    # Trim to reasonable length centered on match
                    match_in_line = m.start() - line_start
                    trim_start = max(0, match_in_line - 10)
                    trim_end = min(len(raw_line), match_in_line + len(m.group(0)) + 40)
                    snippet = raw_line[trim_start:trim_end]
                    if trim_start > 0:
                        snippet = "..." + snippet
                    if trim_end < len(raw_line):
                        snippet = snippet + "..."
                    results.append({"name": tech, "category": category, "version": version,
                                    "source_type": "html", "line": line,
                                    "matched": snippet[:120],
                                    "evidence": f"body"})
            except re.error:
                pass

    return results


def _build_line_index(text):
    """Build list of line-start positions for fast line number lookup."""
    breaks = [0]
    for i, ch in enumerate(text):
        if ch == '\n':
            breaks.append(i + 1)
    return breaks


def _guess_generator_category(name):
    """Guess category for a meta generator value."""
    lower = name.lower()
    cms_kw = ["wordpress", "drupal", "joomla", "typo3", "ghost", "hugo", "jekyll",
              "gatsby", "hexo", "magento", "prestashop", "shopify", "squarespace",
              "wix", "craft", "october", "grav", "statamic", "umbraco", "sitecore",
              "contentful", "kentico", "concrete5", "silverstripe", "modx", "bolt",
              "textpattern", "eleventy", "astro", "docusaurus"]
    for kw in cms_kw:
        if kw in lower:
            return "CMS"
    plugin_kw = ["rocket", "yoast", "elementor", "cache", "seo", "plugin", "addon"]
    for kw in plugin_kw:
        if kw in lower:
            return "Plugin"
    return "CMS"


# URL patterns: (regex_on_url, tech_name, category)
_URL_TECH_PATTERNS = [
    (r"jquery[.\-/](\d+\.\d+(?:\.\d+)?)", "jQuery", "Library"),
    (r"jquery\.min\.js", "jQuery", "Library"),
    (r"jquery-migrate[.\-/](\d+\.\d+(?:\.\d+)?)", "jQuery Migrate", "Library"),
    (r"bootstrap[.\-/](\d+\.\d+(?:\.\d+)?)", "Bootstrap", "Library"),
    (r"font-?awesome[.\-/](\d+\.\d+(?:\.\d+)?)", "Font Awesome", "Library"),
    (r"swiper[.\-/](\d+\.\d+(?:\.\d+)?)", "Swiper", "Library"),
    (r"slick[.\-/](\d+\.\d+(?:\.\d+)?)", "Slick Slider", "Library"),
    (r"aos[.\-/](\d+\.\d+(?:\.\d+)?)", "AOS", "Library"),
    (r"gsap[.\-/](\d+\.\d+(?:\.\d+)?)", "GSAP", "Library"),
    (r"three[.\-/](\d+\.\d+(?:\.\d+)?)", "Three.js", "Library"),
    (r"chart[.\-/](\d+\.\d+(?:\.\d+)?)", "Chart.js", "Library"),
    (r"d3[.\-/]v?(\d+\.\d+(?:\.\d+)?)", "D3.js", "Library"),
    (r"lodash[.\-/](\d+\.\d+(?:\.\d+)?)", "Lodash", "Library"),
    (r"moment[.\-/](\d+\.\d+(?:\.\d+)?)", "Moment.js", "Library"),
    (r"elementor[.\-/]?(?:pro)?.*?(\d+\.\d+(?:\.\d+)?)?", "Elementor", "Plugin"),
    (r"wp-rocket", "WP Rocket", "Plugin"),
    (r"yoast", "Yoast SEO", "Plugin"),
    (r"contact-form-7", "Contact Form 7", "Plugin"),
    (r"woocommerce[.\-/]?(\d+\.\d+(?:\.\d+)?)?", "WooCommerce", "Ecommerce"),
    (r"gravityforms", "Gravity Forms", "Plugin"),
    (r"wpml", "WPML", "Plugin"),
    (r"wordfence", "Wordfence", "Plugin"),
    (r"w3-total-cache|w3tc", "W3 Total Cache", "Plugin"),
    (r"wp-super-cache", "WP Super Cache", "Plugin"),
    (r"jetpack", "Jetpack", "Plugin"),
    (r"akismet", "Akismet", "Plugin"),
    (r"all-in-one-seo|aioseo", "All in One SEO", "Plugin"),
    (r"rank-math", "Rank Math SEO", "Plugin"),
    (r"advanced-custom-fields|acf", "ACF", "Plugin"),
    (r"google-site-kit", "Google Site Kit", "Plugin"),
]


def _extract_tech_from_url(url, seen, results, line=0):
    """Try to identify technologies and versions from a script/link URL."""
    for pattern, tech, category in _URL_TECH_PATTERNS:
        if tech in seen:
            continue
        m = re.search(pattern, url, re.IGNORECASE)
        if m:
            seen.add(tech)
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            if not version:
                vm = re.search(r'[/\-.]v?(\d+\.\d+(?:\.\d+)?)', url)
                if vm:
                    version = vm.group(1)
            results.append({"name": tech, "category": category, "version": version,
                            "source_type": "url", "line": line,
                            "matched": url[:150],
                            "evidence": f"url"})


# --- Version extraction ---

# Version patterns for specific technologies in headers
# (tech_name_lower, header_regex_to_extract_version)
_HEADER_VERSION_PATTERNS = {
    "server": [
        (r"apache[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"nginx[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"openresty[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"litespeed[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"iis[/ ]+(\d+\.\d+)", None),
        (r"tomcat[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"jetty[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"caddy[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"envoy[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"tengine[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"cloudflare", None),  # no version in server header
    ],
    "x-powered-by": [
        (r"php[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"asp\.net[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
        (r"express[/ ]*(\d+\.\d+(?:\.\d+)?)?", None),
        (r"next\.js[/ ]+(\d+\.\d+(?:\.\d+)?)", None),
    ],
    "x-aspnet-version": [
        (r"(\d+\.\d+(?:\.\d+(?:\.\d+)?)?)", None),
    ],
}

# Version extraction patterns from body for specific technologies
# (tech_name, [list of regex patterns where group(1) is the version])
_BODY_VERSION_PATTERNS = [
    ("jQuery", [
        r"jquery[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
        r"jquery\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("jQuery UI", [
        r"jquery-ui[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Bootstrap", [
        r"bootstrap[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
        r"bootstrap\.min\.(css|js)\?ver=(\d+\.\d+(?:\.\d+)?)",
        r"Bootstrap v(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("React", [
        r"react[/\-.]v?(\d+\.\d+(?:\.\d+)?)",
        r"React v(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Angular", [
        r"ng-version=\"(\d+\.\d+(?:\.\d+)?)",
        r"angular[/\-.]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("AngularJS", [
        r"angular\.js/(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Vue.js", [
        r"vue[/\-.]v?(\d+\.\d+(?:\.\d+)?)",
        r"Vue\.js v(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Next.js", [
        r"next[/\-.]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Nuxt.js", [
        r"nuxt[/\-.]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("WordPress", [
        r"wordpress[/ ]+(\d+\.\d+(?:\.\d+)?)",
        r'content="WordPress (\d+\.\d+(?:\.\d+)?)',
        r"ver=(\d+\.\d+(?:\.\d+)?).*wp-",
    ]),
    ("Drupal", [
        r"Drupal (\d+\.\d+(?:\.\d+)?)",
        r'content="Drupal (\d+)',
    ]),
    ("Joomla", [
        r"Joomla!?\s*(\d+\.\d+(?:\.\d+)?)",
        r'content="Joomla! (\d+\.\d+)',
    ]),
    ("Magento", [
        r"Magento[/ ]+(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("TYPO3", [
        r"TYPO3 CMS[/ ]+(\d+\.\d+(?:\.\d+)?)",
        r'content="TYPO3 (\d+\.\d+)',
    ]),
    ("Ghost", [
        r"Ghost (\d+\.\d+(?:\.\d+)?)",
        r'content="Ghost (\d+\.\d+)',
    ]),
    ("Font Awesome", [
        r"font-?awesome[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("WebFont Loader", [
        r"webfont[/\-. ]+(\d+\.\d+(?:\.\d+)?)",
        r"webfont\.js\?v=(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Google Tag Manager", [
        r"GTM-([A-Z0-9]+)",
    ]),
    ("D3.js", [
        r"d3\.v(\d+)",
        r"d3[/\-.]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Three.js", [
        r"three\.js r(\d+)",
        r"three[/\-.]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Chart.js", [
        r"chart\.js[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Swiper", [
        r"swiper[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Tailwind CSS", [
        r"tailwindcss[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Modernizr", [
        r"modernizr[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("GSAP", [
        r"gsap[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Lodash", [
        r"lodash[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Moment.js", [
        r"moment[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("Shopify", [
        r"Shopify\.theme.*(\d+\.\d+)",
    ]),
    ("WooCommerce", [
        r"woocommerce[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
    ("PrestaShop", [
        r"prestashop[/\-. ]v?(\d+\.\d+(?:\.\d+)?)",
    ]),
]


def _extract_version(text):
    """Generic version extraction from a string."""
    m = re.search(r"[/\s]v?(\d+\.\d+(?:\.\d+(?:\.\d+)?)?)", text)
    return m.group(1) if m else ""


def _extract_version_from_header(hdr_name, hdr_value, tech):
    """Extract version from a specific header value."""
    hdr_lower = hdr_name.lower()
    patterns = _HEADER_VERSION_PATTERNS.get(hdr_lower, [])
    for pat, _ in patterns:
        m = re.search(pat, hdr_value, re.IGNORECASE)
        if m and m.lastindex:
            return m.group(1)

    # Generic fallback: extract version from header value
    return _extract_version(hdr_value)


def _extract_version_from_body(body, tech):
    """Extract version for a specific technology from page body."""
    for name, patterns in _BODY_VERSION_PATTERNS:
        if name.lower() == tech.lower():
            for pat in patterns:
                m = re.search(pat, body, re.IGNORECASE)
                if m and m.lastindex:
                    return m.group(1)
            break

    # For scripts/links with version in URL path
    # e.g. /libs/webfont/1.6.26/webfont.js
    tech_clean = re.escape(tech.lower().replace(" ", "").replace(".", ""))
    short_names = [tech.lower().split()[0], tech.lower().replace(" ", ""), tech.lower().replace(".", "")]
    for name in short_names:
        name_escaped = re.escape(name)
        m = re.search(
            rf'{name_escaped}[/\-]v?(\d+\.\d+(?:\.\d+)?)',
            body, re.IGNORECASE
        )
        if m:
            return m.group(1)

    return ""


def _get_header(headers, name):
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None
