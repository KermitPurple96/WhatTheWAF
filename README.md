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
wtw example.com --ip 1.2.3.0/24       # Test CIDR range
wtw example.com --ip history           # Re-test stored IPs (no APIs)
wtw example.com --evasion              # Quick WAF evasion recon
wtw example.com --waf-scan --proton    # Deep WAF audit (use VPN)
wtw example.com --scan-history         # View stored intelligence
wtw example.com --origins              # Quick DNS + ASN classification
wtw --whoami                           # Your current fingerprint
wtw example.com --profile stealth      # Use a saved profile
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

Connects directly to an IP with `Host: target.com`, bypassing CDN/WAF. Compares body hashes to confirm bypass. Supports CIDR ranges.

| Mode | What it does |
|------|-------------|
| `--ip 1.2.3.4` | Test specific IP(s) |
| `--ip 1.2.3.0/24` | Test all 254 IPs in a /24 range |
| `--ip auto` | Discover origin IPs via OSINT and test all |
| `--ip history` | Re-test stored IPs from previous scans — no API calls |

### `--evasion` — Quick WAF Recon (~30 requests)

Tests what the WAF inspects: User-Agent filtering, HTTP method restrictions, encoding bypasses, rate limiting. Safe from your own IP.

### `--waf-scan` — Deep WAF Vulnerability Audit

10-layer analysis with real attack payloads (SQLi, XSS, RCE, LFI). Tests network, rule engine, rate limiting, evasion, behavioral, header spoofing, TLS, HTTP methods, session manipulation, and misconfigurations. False positive verification with `[FP-clean]` tags.

> **Use VPN.** Sends hundreds of malicious-looking requests: `wtw example.com --waf-scan --proton`

### Scan Persistence

All scans auto-store WAF detections, IPs, and findings in SQLite (`~/.local/share/whatthewaf/scan_history.db`). View with `--scan-history`, re-test IPs with `--ip history`, clear with `--purge-history`.

### `--recon` — Full OSINT

Runs all discovery sources (DNS, subdomains, historical DNS, SSL cert, favicon hash, GitHub leaks, Censys, Shodan, VirusTotal, Whoxy, DNSTrails), correlates IPs, ranks by confidence. IPs with matching SSL certificates get `[SSL ✓]` verification.

### `--whoami` — Your Fingerprint

Shows what servers see when you connect: public IP, ISP, geolocation, VPN/Tor/proxy detection, TLS version, cipher suite count, User-Agent, TCP TTL. Supports `--proxy` to verify your fingerprint through the MITM proxy.

```bash
wtw --whoami                                   # Direct fingerprint
wtw --whoami --proxy http://127.0.0.1:8888     # Through MITM proxy
```

## API Keys

Optional — the tool works without them. More keys = more origin discovery sources. Multiple keys per service for auto-rotation if one gets banned:

```bash
wtw --api-init       # Create config template
wtw --api-status     # Check configured keys
```

Keys in `~/.config/whatthewaf/api_keys.conf` or environment variables (env vars override config):

```ini
[keys]
# Single key:
shodan_api_key = YOUR_KEY

# Multiple keys (auto-rotates on 401/403/429):
shodan_api_key = key1, key2, key3
```

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
# Install (Kali/Debian)
sudo apt install -y protonvpn-cli

# Sign in
protonvpn signin <username>

# Connect
protonvpn connect                      # Fastest server
protonvpn connect --country NL         # Netherlands
protonvpn connect --city "Amsterdam"   # Specific city
protonvpn connect --random             # Random server

# Status
protonvpn status
wtw --proton-check                     # Verify wtw can use it

# Rotate IP
wtw --proton-rotate

# Disconnect
protonvpn disconnect
```

## Stealth Setup (full walkthrough)

WAFs fingerprint you at every layer: IP, TCP, TLS, HTTP headers. The MITM proxy intercepts HTTPS traffic, rewrites headers and User-Agent to look like Chrome, and applies stealth TLS. Combined with VPN and TCP fingerprinting, you're invisible.

**Step 1 — Check your current fingerprint:**

```bash
wtw --whoami
# IP: 83.48.x.x | ISP: Telefonica | TTL: 64 → Linux | UA: python-httpx
# Everything screams "automated tool from Spain"
```

**Step 2 — Connect ProtonVPN (change IP + country):**

```bash
protonvpn connect --country NL
wtw --proton-check
```

**Step 3 — TCP fingerprint (look like Windows, not Linux):**

```bash
sudo wtw --tcp-profile windows         # TTL=128, Windows TCP stack
```

**Step 4 — Start MITM proxy (intercepts HTTPS, rewrites everything):**

```bash
wtw --mitm --proton --proxy-verbose --random-delay 1 --listen-port 8888
```

The MITM proxy:
- Generates per-host TLS certificates signed by a local CA
- Decrypts HTTPS → rewrites User-Agent, headers, order → re-encrypts with Chrome-like TLS
- Spoofs `curl/`, `python-httpx`, `sqlmap`, `nuclei`, etc. to Chrome UA
- Adds Chrome headers: `Sec-Ch-Ua`, `Sec-Fetch-*`, `Accept-Language`, etc.

**Step 5 — Configure Burp Suite:**

In Burp: `Settings → Network → Connections → Upstream Proxy Servers → Add`:
- Destination host: `*`
- Proxy host: `127.0.0.1`
- Proxy port: `8888`

```
Browser  →  Burp (8080)  →  MITM proxy (8888)  →  ProtonVPN  →  Internet
             you see &       rewrites headers,       different
             modify here     spoofs UA/TLS            IP/country
```

**Step 6 — Verify:**

```bash
wtw --whoami --proxy http://127.0.0.1:8888

# Or with curl:
curl -k -x http://127.0.0.1:8888 https://httpbin.org/headers
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0
# Sec-Ch-Ua, Sec-Fetch-*, Accept-Language — all injected automatically
```

**Step 7 — Run scans through the chain:**

```bash
wtw target.com --proxy http://127.0.0.1:8888 --evasion
wtw target.com --proxy http://127.0.0.1:8888 --waf-scan
```

**Step 8 — Rotate IP if blocked:**

```bash
wtw --proton-rotate
wtw --whoami --proxy http://127.0.0.1:8888
```

**Step 9 — Clean up:**

```bash
sudo wtw --tcp-revert                  # Restore Linux TCP defaults
protonvpn disconnect
# Ctrl+C the MITM proxy
```

**Layer summary:**

| Layer | What changes | How |
|-------|-------------|-----|
| IP | Different IP/country | `--proton` on MITM proxy |
| TCP | TTL=128, Windows TCP stack | `sudo --tcp-profile windows` |
| TLS | Chrome cipher suites, HTTP/1.1 ALPN | MITM proxy auto |
| HTTP | Chrome UA, Sec-Ch-Ua, Sec-Fetch-*, header order | MITM proxy auto |
| Timing | Random delays between requests | `--random-delay 1` |

Without Burp, use a profile to apply all stealth layers at once:

```bash
wtw target.com --profile chrome-vpn --evasion
wtw target.com --profile chrome-vpn --waf-scan
wtw target.com --profile paranoid --trace
```

> **CA trust:** The MITM proxy generates a CA at `/tmp/whatthewaf_ca/ca.crt`. For curl use `-k` (skip verify) or `--cacert /tmp/whatthewaf_ca/ca.crt`. For Burp, import the CA in `Settings → Network → TLS`.

## Profiles

Profiles define your identity/fingerprint — not what to scan. Save them in `~/.config/whatthewaf/profiles.conf`:

```ini
[chrome-vpn]
proton = true
header_profile = chrome
tls_rotate = true
h2_rotate = true
doh = cloudflare
random_delay = 1

[low-profile]
doh = cloudflare
random_delay = 2
timeout = 15

[paranoid]
proton = true
tls_rotate = true
h2_rotate = true
header_profile = chrome
doh = cloudflare
random_delay = 3
auto_retry = true
```

Combine a profile with any action:

```bash
wtw example.com --profile chrome-vpn --only waf        # WAF detection as Chrome via VPN
wtw example.com --profile chrome-vpn --waf-scan        # Deep audit as Chrome via VPN
wtw example.com --profile chrome-vpn --trace            # Trace as Chrome via VPN
wtw example.com --profile paranoid --evasion            # Evasion with max stealth
wtw --profile ?                                         # List available profiles
```

CLI flags always override profile values. You can also pass a file path: `--profile /path/to/custom.conf`

## Flags

```
# Targets
targets                  Domain(s), IP(s), or @file.txt
--stdin                  Read from stdin
-l, --list FILE          Read from file
--profile NAME           Load settings from saved profile
--origins                Quick DNS + ASN classification

# Analysis
--only MODULES           Specific modules: waf, errors, tls, evasion, bypass, cert, subs, history, proxy
--trace                  Infrastructure chain + network traceroute
--tls                    TLS/SSL audit
--evasion                WAF evasion analysis
--waf-scan               Deep 10-layer WAF audit
--waf-scan-layers L      Specific layers only

# Bypass
--ip IP                  IP(s), CIDR range (1.2.3.0/24), 'auto', or 'history'
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

# Fingerprint
--whoami                 Your current fingerprint (IP, TLS, headers, TCP)
--stealth-status         Status of all evasion capabilities

# MITM Proxy (full HTTPS interception + header/UA/TLS spoofing)
--mitm                   Start MITM proxy
--listen-port PORT       Port (default: 8888)
--no-spoof-ua            Don't replace User-Agent
--no-spoof-tls           Don't modify TLS fingerprint
--proxy-verbose          Log all requests
--random-delay SECS      Random delay between requests

# Stealth (combine with any scan or MITM proxy)
--proton                 Route through ProtonVPN SOCKS
--proxy URL              HTTP/SOCKS proxy
--tor                    Tor IP rotation
--tls-rotate             Rotate JA3/JA4 per request
--h2-rotate              Rotate HTTP/2 fingerprint
--header-profile BROWSER Header order (chrome/firefox/safari/edge)
--dot [PROVIDER]         DNS-over-TLS (cloudflare/google/quad9/adguard)
--doh [PROVIDER]         DNS-over-HTTPS (cloudflare/google/quad9/adguard)
--auto-retry             Auto-retry on WAF blocks

# Stealth (standalone)
--proton-check           Check VPN status
--proton-rotate          Rotate VPN IP
--proxy-chain LIST       Test proxy chain against WAF
--cf-inject              Test Cloudflare header spoofing

# Protocol probing
--h3                     HTTP/3 QUIC probe
--proto-probe            H1 vs H2 vs H3 comparison

# TCP (needs sudo)
--tcp-profile PROFILE    TCP fingerprint: windows | macos
--tcp-revert             Revert to Linux defaults
--tcp-options PROFILE    TCP SYN options

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
