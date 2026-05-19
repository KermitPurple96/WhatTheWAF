"""Shared constants used across WhatTheWAF modules."""

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)

CDN_WAF_KEYWORDS = frozenset({
    "cloudflare", "akamai", "fastly", "cloudfront", "edgecast",
    "incapsula", "imperva", "sucuri", "ddos-guard", "qrator",
    "stackpath", "cdn77", "bunny", "gcore", "limelight",
    "stormwall", "radware", "barracuda", "f5 ", "fortinet",
    "datadome", "perimeterx", "reblaze", "wallarm",
    "azure front door", "aws shield", "google cloud armor",
    "netlify", "vercel",
})
