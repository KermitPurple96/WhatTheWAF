# WhatTheWAF v3.2.0

WAF/CDN Detection | Infrastructure Tracing | WAF Bypass | TLS/SSL Audit | Origin Discovery

## Install

```bash
git clone https://github.com/KermitPurple96/WhatTheWAF.git
cd WhatTheWAF
pip install -e .

# Optional: HTTP/3, favicon hash, TLS impersonation
pip install -e ".[full]"
```

API keys config: `~/.config/whatthewaf/api_keys.conf` (auto-created on install, permissions 600). Run `wtw --api-init` to create, `wtw --api-status` to check.

## Quick Start

```bash
wtw example.com                        # Full scan
wtw example.com --only waf             # WAF detection only
wtw example.com --trace                # Infrastructure chain + traceroute
wtw example.com --tls                  # TLS/SSL audit (sslscan-like)
wtw example.com --ip auto              # Auto-discover + test bypass
wtw example.com --ip history           # Re-test stored IPs (no APIs)
wtw example.com --evasion              # Quick WAF evasion recon
wtw example.com --waf-scan --proton    # Deep WAF audit (use VPN)
wtw example.com --scan-history         # View stored intelligence
wtw example.com --origins              # Quick DNS + ASN classification
wtw example.com --json -o report.json  # JSON output
```

## Features

### `--only waf` — WAF/CDN Detection

90+ WAF/CDN signatures matched against HTTP headers, cookies, body, and error pages. When ASN identifies a CDN/WAF that headers don't reveal (e.g. Cloudflare with `server: nginx`), it's auto-detected. Error page probing (15 probes including SQLi, XSS, path traversal triggers) is included automatically.

### `--trace` — Infrastructure Trace

Maps every layer of the traffic path and runs network traceroute:

```
AWS CloudFront [CDN]  →  Akamai [CDN/WAF]  →  nginx [PROXY]  →  Next.js [FRAMEWORK]
```

Fingerprints 11 layers: CDN/WAF, cache (Varnish, Squid), load balancers (HAProxy, F5, ALB), proxies (nginx, Envoy), hosting (SiteGround, WP Engine, Heroku), web servers (Apache, IIS), runtimes (PHP, Java, Node.js, Python), frameworks (Django, Laravel, Rails, Next.js), and CMS (WordPress, Drupal, Magento).

Network traceroute (ICMP + TCP:443) with ASN classification shows the physical path with `◄` markers at network boundaries. TCP traceroute needs root — fix with `sudo chmod u+s $(readlink -f $(which traceroute))`.

Combinable with other flags:

```bash
wtw example.com --trace --ip 203.0.113.50   # Compare CDN vs direct route
wtw example.com --trace --ip auto            # Discover + trace to origins
wtw example.com --trace --evasion            # Trace + evasion analysis
```

### `--tls` — TLS/SSL Audit

Protocol enumeration (TLS 1.0–1.3), 35+ cipher suite testing (strong/acceptable/weak/insecure + PFS), certificate analysis (subject, issuer, key, SANs, validity, HSTS), vulnerability assessment, browser fingerprint comparison, and WAF TLS acceptance tests.

### `--ip` — WAF Bypass Testing

Connects directly to an IP with `Host: target.com`, bypassing CDN/WAF. Compares body hashes to confirm bypass.

| Mode | What it does |
|------|-------------|
| `--ip 1.2.3.4` | Test specific IP(s) |
| `--ip auto` | Discover origin IPs via OSINT (subdomains, historical DNS, favicon hash, Censys, Shodan, GitHub, VirusTotal) and test all |
| `--ip history` | Re-test stored IPs from previous scans — no API calls |

### `--evasion` — Quick WAF Recon (~30 requests)

Tests what the WAF inspects: User-Agent filtering, HTTP method restrictions, encoding bypasses, rate limiting. Safe from your own IP.

### `--waf-scan` — Deep WAF Vulnerability Audit

10-layer analysis with real attack payloads (SQLi, XSS, RCE, LFI). Tests network, rule engine, rate limiting, evasion, behavioral, header spoofing, TLS, HTTP methods, session manipulation, and misconfigurations. False positive verification with `[FP-clean]` tags.

> **Use VPN.** Sends hundreds of malicious-looking requests: `wtw example.com --waf-scan --proton`

### Scan Persistence

All scans auto-store WAF detections, IPs, and findings in SQLite (`~/.local/share/whatthewaf/scan_history.db`). View with `--scan-history`, re-test IPs with `--ip history`, clear with `--purge-history`.

### `--recon` — Full OSINT

Runs all discovery sources (DNS, subdomains, historical DNS, SSL cert, favicon hash, GitHub leaks, Censys, Shodan, VirusTotal, Whoxy, DNSTrails), correlates IPs, ranks by confidence.

## Flags

```
# Targets
targets                  Domain(s), IP(s), or @file.txt
--stdin                  Read from stdin
-l, --list FILE          Read from file
--origins                Quick DNS + ASN classification

# Analysis
--only MODULES           Specific modules: waf, errors, tls, evasion, bypass, cert, subs, history, proxy
--trace                  Infrastructure chain + network traceroute
--tls                    TLS/SSL audit
--evasion                WAF evasion analysis
--waf-scan               Deep 10-layer WAF audit
--waf-scan-layers L      Specific layers only

# Bypass
--ip IP                  Test IP(s), 'auto', or 'history'
--path PATH              Path for --ip (default: /)
--recon                  Full OSINT recon

# OSINT (individual)
--favicon [URL|HASH]     Favicon hash search
--github-leaks           GitHub leak search
--censys [QUERY]         Censys cert search
--shodan [QUERY]         Shodan search
--virustotal             VT passive DNS
--securitytrails         SecurityTrails historical DNS
--whoxy                  Reverse WHOIS
--dnstrails              DNSTrails

# History
--scan-history           View stored intelligence
--purge-history          Clear stored data
--no-persist             Skip storing results

# Stealth
--proton                 Route through ProtonVPN SOCKS
--proton-check           Check VPN status
--proton-rotate          Rotate VPN IP
--proxy URL              HTTP/SOCKS proxy
--proxy-chain LIST       Test proxy chain against WAF
--tor                    Tor IP rotation
--tls-rotate             Rotate JA3/JA4 per request
--h2-rotate              Rotate HTTP/2 fingerprint
--header-profile BROWSER Header order (chrome/firefox/safari/edge)
--dot [PROVIDER]         DNS-over-TLS
--doh [PROVIDER]         DNS-over-HTTPS
--auto-retry             Auto-retry on WAF blocks
--cf-inject              Test Cloudflare header spoofing

# Protocol
--h3                     HTTP/3 QUIC probe
--proto-probe            H1 vs H2 vs H3 comparison

# TCP (needs sudo)
--tcp-profile PROFILE    TCP fingerprint: windows | macos
--tcp-revert             Revert to Linux defaults
--tcp-options PROFILE    TCP SYN options

# Proxy mode
--proxy-mode             Start stealth proxy
--mitm                   Start MITM proxy

# Output
--json                   JSON output
-o, --output FILE        Write to file
-q, --quiet              Suppress banner
-v, --version            Version

# Tuning
--user-agent UA          Custom UA
--timeout SECS           Timeout (default: 10)
--delay SECS             Delay between targets
--workers N              Concurrent workers
```

## API Keys

Optional — the tool works without them. More keys = more origin discovery sources.

```bash
wtw --api-init       # Create config template
wtw --api-status     # Check configured keys
```

Keys in `~/.config/whatthewaf/api_keys.conf` or environment variables (env vars override config):

| Service | Used For | Env Var |
|---------|----------|---------|
| Shodan | Favicon hash, DNS records | `SHODAN_API_KEY` |
| Censys | Certificate-based origin discovery | `CENSYS_API_ID` + `CENSYS_API_SECRET` |
| FOFA | Favicon hash (Asia-Pacific) | `FOFA_EMAIL` + `FOFA_KEY` |
| SecurityTrails | Historical DNS | `SECURITYTRAILS_KEY` |
| VirusTotal | Passive DNS | `VIRUSTOTAL_KEY` |
| Whoxy | Reverse WHOIS → sibling domains | `WHOXY_API_KEY` |
| DNSTrails | Historical DNS + subdomains | `DNSTRAILS_API_KEY` |

## ProtonVPN Setup

```bash
# Install (Kali/Debian) — do NOT use pip install protonvpn-cli
sudo apt install -y proton-vpn-cli

# Setup
protonvpn signin <username>
protonvpn connect

# Use
wtw --proton-check
wtw example.com --proton --waf-scan
wtw --proton-rotate
```

For GUI: enable SOCKS5 proxy on port 1080 in ProtonVPN settings, then use `--proton`.
