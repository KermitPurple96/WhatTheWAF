# WhatTheWAF v3.1.0

WAF/CDN Detection | WAF Bypass | Origin Discovery | TLS Fingerprint Evasion

## Install

```bash
git clone https://github.com/KermitPurple96/WhatTheWAF.git
cd WhatTheWAF
pip install -e .

# Optional: favicon hash matching + all extras
pip install -e ".[full]"
```

On install, a template API key config is created at `~/.config/whatthewaf/api_keys.conf` (permissions 600, outside the repo — never uploaded to git). Edit it to add your keys — **remove the `#` to uncomment lines** — or set environment variables instead.

Both `whatthewaf` and `wtw` commands are available after install.

## Quick Start

```bash
# Full WAF scan
wtw example.com

# Only WAF detection
wtw example.com --only waf

# Only IPs + WAF + error pages
wtw example.com --only ips,waf,errors

# Direct IP bypass PoC
wtw example.com --direct-ip 1.2.3.4
wtw example.com --direct-ip 1.2.3.4,5.6.7.8 --path /login
wtw example.com --direct-ip auto

# Deep WAF vulnerability scan (10 layers)
wtw example.com --waf-scan

# WAF evasion analysis
wtw example.com --evasion

# Origin IP classification
wtw example.com -m origins

# Scan through ProtonVPN
wtw example.com --proton --evasion

# JSON output
wtw example.com --json -o report.json
```

## How It Works

WhatTheWAF is a modular WAF/CDN reconnaissance and bypass toolkit. Here's what happens when you run a scan:

### Detection Pipeline

1. **DNS Resolution** -- Resolves the target domain and extracts A records + CNAME chains. CNAMEs often reveal the CDN (e.g. `example.com.cdn.cloudflare.net`).

2. **ASN Classification** -- Each resolved IP is looked up against a database of 50+ WAF/CDN providers and 30+ hosting providers. This tells you whether traffic goes through a proxy (Cloudflare, Akamai) or directly to an origin server (AWS, Hetzner).

3. **WAF Signature Matching** -- HTTP response headers, cookies, and body content are matched against 90+ WAF/CDN signatures. For example, a `cf-ray` header means Cloudflare, a `__cfduid` cookie means Cloudflare, an `X-Sucuri-ID` header means Sucuri.

4. **Error Page Probing** -- Requests 404, 403, 500, and WAF-trigger paths (like `/../../etc/passwd`). WAFs often reveal themselves on error pages even when the homepage looks clean.

### Origin Discovery (finding the real IP)

When a CDN/WAF is detected, the tool tries to find the origin server IP through multiple techniques:

| Technique | How It Works | API Key Needed |
|-----------|-------------|----------------|
| **Subdomain leakage** | Resolves 35+ subdomains (mail, dev, staging, api, ftp, etc.) that are often not behind the CDN | No |
| **SSL certificate inspection** | Connects to candidate IPs on port 443 and checks if the cert matches the target domain | No |
| **Historical DNS** (ViewDNS) | Looks up old A records -- the IP before CDN migration is often still the origin | No |
| **Historical DNS** (SecurityTrails) | Same concept, different data source with better coverage | Yes |
| **Favicon hash matching** | Fetches the site's favicon, computes its MMH3 hash, then searches Shodan/FOFA/ZoomEye for other servers with the same favicon -- these are often the origin | Yes |
| **GitHub leak search** | Searches GitHub code for the domain in config files, .env files, nginx/Apache configs that may contain hardcoded origin IPs | No (rate-limited) |
| **Censys certificate search** | Finds all hosts that have a TLS certificate with the target domain name -- origin servers often have the same cert | Yes |
| **Shodan DNS records** | Queries Shodan's passive DNS for subdomain A records | Yes |
| **VirusTotal resolutions** | Historical domain-to-IP mappings from VirusTotal's passive DNS | Yes |
| **Whoxy reverse WHOIS** | WHOIS lookup → registrant email → reverse WHOIS to find sibling domains → resolve for shared origin IPs | Yes |
| **DNSTrails** | Historical DNS A records + subdomain enumeration (SecurityTrails-compatible API) | Yes |

With `--direct-ip auto` or `--recon`, all available techniques run in sequence, collect candidate IPs, deduplicate them, and correlate across sources. `--recon` ranks IPs by how many sources found them.

### WAF Bypass Verification

Once candidate origin IPs are found, the tool verifies bypass by:

1. Fetching the page normally through the CDN → gets a body hash
2. Connecting directly to the candidate IP with `Host: target.com` header → gets another body hash
3. Comparing the two hashes:
   - **Same hash** + DNS goes through WAF → **WAF BYPASS CONFIRMED**
   - **Same hash** + DNS goes to hosting → **DIRECT ACCESS CONFIRMED**
   - **Different hash** + default/parking page detected → **DEFAULT VHOST** (false positive)
   - **Different hash** + real content (200/301/302) → **WAF BYPASS LIKELY**

Default vhost detection prevents false positives from shared hosting servers that respond to any Host header with a parking page.

### WAF Evasion Analysis (`--evasion`)

Tests what the WAF actually inspects:
- **User-Agent sensitivity** -- sends requests with Chrome, Firefox, curl, sqlmap, Nikto UAs to see which get blocked
- **HTTP method restrictions** -- tests GET, POST, PUT, DELETE, TRACE, OPTIONS, PATCH, etc.
- **Encoding bypasses** -- tries URL-encoded, double URL-encoded, Unicode, null-byte, and mixed-case variants
- **Rate limiting** -- measures how many requests before the WAF starts blocking
- **HTTP version** -- tests HTTP/1.0 vs 1.1 acceptance

### Deep WAF Vulnerability Scanner (`--waf-scan`)

A 10-layer analysis framework that tests the WAF itself for weaknesses:

| Layer | What It Tests |
|-------|--------------|
| Network | Virtual host bypass, sensitive path probing, Host header manipulation |
| Rule Engine | SQLi, XSS, RCE, LFI payloads to find detection gaps |
| Rate Limiting | Burst and sustained request enforcement thresholds |
| Evasion | 10 encoding variants per payload to find bypasses |
| Behavioral | Tarpit detection, JavaScript challenge analysis, back-off timing |
| Header | IP spoofing via X-Forwarded-For, X-Real-IP, CF-Connecting-IP |
| TLS | Version probing, SNI bypass, certificate fingerprinting |
| HTTP Method | Verb-based bypass including WebDAV methods |
| Session | Cookie manipulation, authentication bypass, session fixation |
| Misconfiguration | Version leakage, information disclosure, config errors |

**False Positive Verification:** Every finding in the rule engine and evasion layers is automatically validated against a clean baseline. If the attack response is identical to the homepage (and the payload isn't reflected), it's still flagged as a WAF gap — but findings that pass FP verification get a `[FP-clean]` tag and higher confidence score.

**Statistical Persistence:** Results are stored in a local SQLite database (`~/.local/share/whatthewaf/scan_history.db`) across sessions. On repeat scans, you get:
- **Stability classification** — is a finding `stable` (80%+ scans), `intermittent`, or `rare`?
- **Statistical confidence** — weighted by hit rate, consistency, and verification status
- **Diff tracking** — what's new this scan, what disappeared (patched or intermittent?)
- **Recon IP tracking** — IPs from `--recon` and `--direct-ip` accumulate confidence over time

### Stealth & Evasion Stack

Multiple layers can be combined for maximum stealth:

| Layer | Module | What It Does |
|-------|--------|-------------|
| IP | `proxy_manager` / `tor_rotator` | Rotate exit IP via ProtonVPN, Tor, or proxy pool |
| TCP | `tcp_fingerprint` / `tcp_options` | Change TTL, window size, SACK to look like Windows/macOS |
| TLS | `tls_rotator` | Rotate JA3/JA4 fingerprint per request (Chrome, Firefox, Safari, Edge profiles) |
| HTTP/2 | `h2_fingerprint` / `http2_fingerprint` | Rotate SETTINGS frames, header order, priority weights |
| HTTP/3 | `http3_probe` / `socks5_udp` | QUIC probing, protocol-level bypass detection, SOCKS5 UDP relay |
| HTTP | `proxy_mode` | Rewrite headers, strip tool signatures, add browser-like patterns |
| Headers | `header_order` | Browser-accurate header ordering (Chrome, Firefox, Safari, Edge) |
| DNS | `dns_encrypted` | DNS-over-TLS/DoH to prevent DNS leakage and bypass DNS-level blocks |
| Source Port | `source_port` | Use trusted ports (80, 443, 53) or browser-range ports to evade tracking |
| JS Challenges | `headless_browser` | Solve Cloudflare Turnstile, DataDome, PerimeterX with stealth Playwright |
| MITM | `mitm_proxy` | Full HTTPS interception with dynamic per-host certificate generation |
| CF Headers | `cf_header_inject` | Test if WAF trusts spoofed Cloudflare internal headers |
| Auto-retry | `response_advisor` | Escalating retry strategies when WAF blocks (UA swap, delay, header spoof) |

```bash
# Full stealth: all layers combined
sudo wtw --tcp-profile windows                                          # Terminal 1
wtw --proxy-mode --proton --tls-rotate --h2-rotate --random-delay 2     # Terminal 2
wtw target.com --proxy http://127.0.0.1:8888 --evasion                  # Terminal 3

# Protocol-level analysis
wtw target.com --proto-probe                    # Test H1 vs H2 vs H3
wtw target.com --h3                             # Quick HTTP/3 QUIC probe

# Encrypted DNS (prevent DNS leakage)
wtw target.com --dot google                     # DNS-over-TLS via Google
wtw target.com --doh cloudflare                 # DNS-over-HTTPS via Cloudflare

# Browser-accurate header ordering
wtw target.com --header-profile chrome --evasion
wtw target.com --header-profile firefox --waf-scan
```

## Flags

### Target Selection

```
targets                  Domain(s), IP(s), or @file.txt
--stdin                  Read targets from stdin
-l, --list FILE          Read targets from file
-m, --mode               origins | full (default: full)
```

### Output

```
--json                   JSON output
-o, --output FILE        Write results to file
-q, --quiet              Suppress banner
--no-banner              Suppress banner (alias)
-v, --version            Show version
```

### Module Selection

```
--only MODULES           Run only specific modules (comma-separated)
```

Available modules for `--only`:

| Module | What it does |
|--------|-------------|
| `ips` | DNS resolution + ASN classification (always included) |
| `waf` | WAF/CDN signature detection from headers, cookies, body |
| `errors` | Error page probing (404, 403, 500, WAF trigger paths) |
| `tls` | TLS fingerprint analysis and config testing |
| `evasion` | WAF evasion analysis (User-Agent, encoding, methods) |
| `bypass` | WAF bypass testing via direct IP access |
| `cert` | SSL certificate inspection (CDN-issued detection) |
| `subs` | Subdomain origin leakage + favicon hash + Censys + GitHub leaks |
| `history` | Historical DNS record lookup (ViewDNS + SecurityTrails) |
| `proxy` | Proxy effectiveness testing against WAF |

Examples:

```bash
# Only detect WAF
wtw example.com --only waf

# IPs and WAF detection
wtw example.com --only ips,waf

# Full recon minus TLS
wtw example.com --only ips,waf,errors,bypass,cert,subs

# Evasion analysis only
wtw example.com --only evasion
```

### Skip Modules (full scan minus specific modules)

```
--no-tls                 Skip TLS fingerprint analysis
--no-subs                Skip subdomain leakage scan
--no-cert                Skip SSL certificate check
```

### Enable Optional Modules

```
--evasion                Run WAF evasion analysis (UA, encoding, methods)
--history                Check historical DNS records
```

### Full OSINT Recon (`--recon`)

```
--recon                  Run ALL OSINT sources, correlate IPs, classify CDN vs origin
```

Runs every available source in sequence (DNS, subdomains, historical DNS, SSL cert, favicon hash, GitHub leaks, Censys, Shodan, VirusTotal, Whoxy, DNSTrails), then:
- ASN-classifies every IP (CDN vs origin vs hosting)
- Cross-references which sources found each IP
- Ranks by confidence (more sources = higher confidence)
- Gives a ready `--direct-ip` command for the best candidates

```bash
wtw example.com --recon
wtw example.com --recon --json -o recon.json
```

Output:

```
  Sources Queried
    ✓ dns                  2 result(s)
    · subdomains           0 result(s)
    ✓ shodan               4 result(s)
    ✓ virustotal           24 result(s)
    ...

  Correlated IPs (24 unique)
  ─────────────────────────────────────────────────────────
  IP                ASN        Provider           Type     #Src  Sources
  104.20.23.154     AS13335    CLOUDFLARENET       CDN      3    dns, shodan, virustotal
  93.184.216.34     ?          NA                  ORIGIN?  1    virustotal
  ...

  Analysis
    CDN/WAF IPs: 104.20.23.154, 172.66.147.243
    High confidence origins (2+ sources):
      93.184.216.34     (2 sources: shodan, virustotal)
    Low confidence (1 source):
      1.2.3.4           (virustotal)

  Next Steps
    wtw example.com --direct-ip 93.184.216.34,1.2.3.4
```

### Individual OSINT Tools

Run each discovery source individually. Each flag accepts an optional argument for direct queries without needing a target domain.

```
--favicon [URL|HASH]     No arg: hash target's favicon. URL: fetch & hash. Number: search by hash.
--github-leaks           Search GitHub for leaked origin IPs in configs/.env
--censys [QUERY]         No arg: cert search for target. String: raw Censys query.
--shodan [QUERY]         No arg: domain DNS records. String: raw Shodan host search.
--virustotal             VirusTotal domain resolution history
--securitytrails         SecurityTrails historical DNS A records
--whoxy                  WHOIS + reverse WHOIS → sibling domains → shared origin IPs
--dnstrails              DNSTrails historical DNS + subdomain enumeration
```

```bash
# With a target domain (auto-detect favicon, search domain records)
wtw example.com --favicon
wtw example.com --shodan
wtw example.com --censys

# Favicon: fetch from a specific URL and search by its hash
wtw --favicon https://target.com/assets/icon.png

# Favicon: search by a known MMH3 hash directly
wtw --favicon 708578229

# Shodan/Censys: raw queries (no target needed)
wtw --shodan 'http.title:"Login" port:443 country:US'
wtw --shodan 'ssl.cert.subject.cn:example.com'
wtw --censys 'services.tls.certificates.leaf.names: example.com'

# Combine multiple sources against a target
wtw example.com --favicon --shodan --virustotal --censys

# All sources at once
wtw example.com --favicon --github-leaks --censys --shodan --virustotal --securitytrails

# JSON output
wtw example.com --shodan --virustotal --json -o osint.json
```

When run with a target, results include a combined summary with all unique IPs and a ready-to-paste `--direct-ip` command:

```
  Summary: 24 unique IP(s) for example.com
  =======================================================
    93.184.216.34     via virustotal
    104.18.26.120     via shodan, virustotal
    ...

  Test for bypass:
    wtw example.com --direct-ip 93.184.216.34,104.18.26.120,...
```

### Direct IP Bypass PoC

```
--direct-ip IP           Single IP, comma-separated IPs, or 'auto'
--path PATH              Path to test (default: /)
```

Connects to the specified IP with the `Host` header set to the target domain, bypassing DNS resolution and any CDN/WAF in front. Compares body hashes between CDN and direct response to confirm bypass.

With `--direct-ip auto`, the tool runs all available origin discovery techniques (subdomain leakage, historical DNS, favicon hash matching, Censys, Shodan, GitHub leaks, VirusTotal) and tests every candidate IP it finds.

```bash
# Single IP
wtw example.com --direct-ip 203.0.113.50

# Multiple IPs (comma-separated)
wtw example.com --direct-ip 203.0.113.50,203.0.113.51,10.0.0.5

# Auto-discover origin IPs from all sources and test all
wtw example.com --direct-ip auto

# Test specific path
wtw example.com --direct-ip 203.0.113.50 --path /login

# Combine: auto-discover + specific path
wtw example.com --direct-ip auto --path /api/v1/health

# Save PoC as JSON
wtw example.com --direct-ip 203.0.113.50 --json -o bypass-poc.json
```

### Deep WAF Vulnerability Scanner

```
--waf-scan               Run 10-layer WAF vulnerability scanner
--waf-scan-layers LAYERS Scan specific layers (comma-separated)
--no-persist             Don't store results in history database
--scan-history           Show scan history + statistical analysis for domain
--purge-history          Delete stored scan history for domain
```

```bash
# Full 10-layer scan (results auto-stored for cross-session analysis)
wtw example.com --waf-scan

# Only test rule engine and evasion layers
wtw example.com --waf-scan --waf-scan-layers ruleengine,evasion

# Combine with stealth
wtw example.com --waf-scan --tor --tls-rotate

# View statistical analysis across previous scans
wtw example.com --scan-history

# Scan without storing results
wtw example.com --waf-scan --no-persist

# Clear history for a domain
wtw example.com --purge-history
```

### API Key Management

```
--api-status             Show which API keys are configured
--api-init               Create template API key config file
```

### Proxy & VPN

```
--proxy URL              Proxy for all requests (http/socks5)
--proxy-chain LIST       Comma-separated proxies to test against WAF
--proton                 Route traffic through ProtonVPN SOCKS (127.0.0.1:1080)
--proton-check           Check ProtonVPN status (no target needed)
--proton-rotate          Rotate ProtonVPN IP (no target needed)
```

### Stealth & Evasion Tools

```
--proxy-mode             Start as stealth proxy (JA3 evasion + browser headers)
--listen-port PORT       Port for proxy mode (default: 8888)
--no-spoof-ua            Proxy mode: don't replace User-Agent
--no-spoof-tls           Proxy mode: don't modify TLS fingerprint
--proxy-verbose          Proxy mode: log all requests
--random-delay SECS      Proxy mode: max random delay between requests
--tor                    Use Tor for IP rotation
--tor-password PASS      Tor control port password
--cf-inject              Test Cloudflare header injection bypass
--source-port PROFILE    Manipulate TCP source port (trusted/browser_linux/browser_windows/scanner_evasion/rotating)
--tls-rotate             Rotate TLS fingerprint per request
--h2-rotate              Rotate HTTP/2 SETTINGS fingerprint per request
--h3                     Probe HTTP/3 (QUIC) support and compare with HTTP/2
--proto-probe            Test H1 vs H2 vs H3 and report WAF differences per protocol
--header-profile BROWSER Header ordering profile (chrome/firefox/safari/edge)
--dot [PROVIDER]         DNS-over-TLS (cloudflare/google/quad9/adguard)
--doh [PROVIDER]         DNS-over-HTTPS (cloudflare/google/quad9/adguard)
--tcp-options PROFILE    Set TCP SYN options (chrome/firefox/safari/edge/windows10/linux/random)
--auto-retry             Auto-retry with different techniques when WAF blocks
--proxy-pool FILE        File with proxy URLs for IP rotation pool
--mitm                   Start MITM proxy with dynamic cert generation
--tui                    Show real-time TUI dashboard
```

### TCP Fingerprint (p0f evasion)

```
--tcp-profile PROFILE    Apply TCP fingerprint: windows | macos (needs sudo)
--tcp-revert             Revert TCP fingerprint to Linux defaults
--tcp-status             Show current TCP fingerprint
```

### JS Challenge Solving

```
--solve-challenge URL    Solve JS challenge with headless browser, export cookies
--screenshot FILE        Save screenshot when solving challenge
--install-playwright     Install Playwright + Chromium
```

### HTTP/2 Fingerprint

```
--install-curl-impersonate   Install curl-impersonate (Chrome/Firefox emulation)
```

### Stealth Status

```
--stealth-status         Show status of all evasion capabilities + API keys
```

### Request Tuning

```
--user-agent UA          Custom User-Agent
--timeout SECS           Request timeout (default: 10)
--delay SECS             Delay between targets
--workers N              Concurrent workers for batch scanning
```

## API Keys

Optional API keys unlock additional origin discovery sources. Keys are loaded from environment variables or a config file. **No keys are required** -- the tool works without them, but more keys = more origin discovery sources.

```bash
# Create template config
wtw --api-init

# Check which keys are configured
wtw --api-status
```

### Config File

Keys are stored in `~/.config/whatthewaf/api_keys.conf` (permissions 600, outside the git repo — never uploaded). Lines starting with `#` are comments and ignored. **Remove the `#` to activate a key.**

```bash
# Create template (auto-runs on install)
wtw --api-init

# Edit it
nano ~/.config/whatthewaf/api_keys.conf

# Verify
wtw --api-status
```

```ini
[keys]
# Remove the # prefix to activate a key:
shodan_api_key = YOUR_KEY
censys_api_id = YOUR_ID
censys_api_secret = YOUR_SECRET
fofa_email = you@example.com
fofa_key = YOUR_KEY
zoomeye_key = YOUR_KEY
securitytrails_key = YOUR_KEY
virustotal_api_key = YOUR_KEY
chinaz_api_key = YOUR_KEY
passivetotal_username = you@example.com
passivetotal_key = YOUR_KEY
whoxy_api_key = YOUR_KEY
dnstrails_api_key = YOUR_KEY
```

### Environment Variables

Environment variables always override the config file:

```bash
export SHODAN_API_KEY=xxx
export CENSYS_API_ID=xxx
export CENSYS_API_SECRET=xxx
export FOFA_EMAIL=xxx
export FOFA_KEY=xxx
export ZOOMEYE_KEY=xxx
export SECURITYTRAILS_KEY=xxx
export VIRUSTOTAL_KEY=xxx
export CHINAZ_KEY=xxx
export PASSIVETOTAL_USER=xxx
export PASSIVETOTAL_KEY=xxx
export WHOXY_API_KEY=xxx
export DNSTRAILS_API_KEY=xxx
```

### What Each Key Enables

| Service | Used For | Free Tier |
|---------|----------|-----------|
| Shodan | Favicon hash search, domain DNS records, host lookup | Yes (limited) |
| Censys | Certificate-based origin IP discovery | Yes (250 queries/month) |
| FOFA | Favicon hash search (strong in Asia-Pacific) | Yes (limited) |
| ZoomEye | Favicon hash search | Yes (limited) |
| SecurityTrails | Historical DNS A records (better coverage than ViewDNS) | Yes (50 queries/month) |
| VirusTotal | Domain resolution history (passive DNS) | Yes (500 queries/day) |
| Whoxy | WHOIS + reverse WHOIS to find sibling domains sharing origin IPs | Yes (limited) |
| DNSTrails | Historical DNS A records + subdomain enumeration | Yes (limited) |
| Chinaz | Chinese domain/IP intelligence | Varies |
| PassiveTotal | Passive DNS data | Yes (limited) |

### Key Loading Priority

1. **Environment variables** (highest priority -- always win)
2. **Config file** (`~/.config/whatthewaf/api_keys.conf`)
3. **Project-local file** (`.whatthewaf_keys` in the project directory)

This means you can set keys in your shell profile for persistent use, or in CI/CD environment variables, and they'll override any config file.

## Usage Examples

### Basic Recon

```bash
# Full scan
wtw example.com

# Multiple targets
wtw example.com target.com another.com

# From file
wtw -l domains.txt --workers 5

# From stdin
cat subs.txt | wtw --stdin -m origins
```

### WAF Bypass Testing

```bash
# Auto-discover and test all origin IPs (uses all available API sources)
wtw example.com --direct-ip auto

# Test specific IPs
wtw example.com --direct-ip 203.0.113.50,10.0.0.5

# Test specific path (login page, API, etc.)
wtw example.com --direct-ip auto --path /login

# Manual: find origin IPs first, then test
wtw example.com --only ips,subs,history
wtw example.com --direct-ip 203.0.113.50
```

### Pentest Workflow with ProtonVPN

```bash
# 1. Check VPN status
wtw --proton-check

# 2. Scan target through VPN
wtw target.com --proton --evasion

# 3. If blocked, rotate IP and retry
wtw --proton-rotate
wtw target.com --proton --evasion

# 4. Compare with/without VPN
wtw target.com --json -o direct.json
wtw target.com --proton --json -o vpn.json
```

### Full Stealth Mode

```bash
# Terminal 1: TCP fingerprint
sudo wtw --tcp-profile windows

# Terminal 2: Stealth proxy
wtw --proxy-mode --proton --random-delay 2

# Terminal 3: Scan through stealth proxy
wtw target.com --proxy http://127.0.0.1:8888 --evasion

# Check all evasion capabilities
wtw --stealth-status
```

## ProtonVPN Setup

WhatTheWAF can route traffic through ProtonVPN to change your exit IP and bypass IP-based WAF blocks. ProtonVPN is **optional**.

### Option A: ProtonVPN official CLI (recommended)

```bash
# 1. Install (Kali/Debian)
wget -qO- https://repo.protonvpn.com/debian/public_key.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/protonvpn.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/protonvpn.gpg] https://repo.protonvpn.com/debian stable main" | sudo tee /etc/apt/sources.list.d/protonvpn.list
sudo apt update
sudo apt install -y proton-vpn-cli
```

The package is `proton-vpn-cli` and installs the binary as `/usr/bin/protonvpn`.

> **Do NOT use** `pip install protonvpn-cli` -- that's the old v2 CLI which no longer works (API returns 422).

```bash
# 2. Sign in
protonvpn signin <username>

# 3. Connect
protonvpn connect

# 4. Verify with WhatTheWAF
wtw --proton-check

# 5. Use in scans
wtw example.com --proton --evasion

# 6. Rotate IP if blocked
wtw --proton-rotate

# 7. Disconnect when done
protonvpn disconnect
```

**ProtonVPN CLI quick reference:**

```
protonvpn signin <user>          Sign in (one-time)
protonvpn connect                Connect to fastest server
protonvpn connect --cc NL        Connect to Netherlands
protonvpn connect --random       Connect to random server
protonvpn status                 Show connection status
protonvpn disconnect             Disconnect
protonvpn reconnect              Reconnect to last server
```

### Option B: ProtonVPN GUI (no rotation, simpler)

1. Open ProtonVPN app and connect to any server
2. Go to **Settings > Advanced > SOCKS5 Proxy** and enable it on port **1080**
3. Verify: `wtw --proton-check`
4. Use: `wtw example.com --proton`

With the GUI you cannot use `--proton-rotate` (rotation requires the CLI).

## Modules

| Module | Description |
|--------|-------------|
| waf_signatures | 90+ WAF/CDN vendor detection from headers, cookies, body |
| waf_bypass | Direct IP bypass, alt ports, header spoofing, HTTP downgrade |
| waf_evasion | Detect what WAF checks: UA, encoding, methods, rate limiting |
| waf_vuln_scanner | 10-layer deep WAF vulnerability analysis |
| tls_fingerprint | TLS config analysis, browser difference detection |
| tls_rotator | Per-request JA3/JA4 TLS fingerprint rotation |
| h2_fingerprint | HTTP/2 SETTINGS frame rotation across browser profiles |
| http2_fingerprint | curl-impersonate integration for protocol-level browser emulation |
| tcp_fingerprint | OS-level TCP stack modification (TTL, window, SACK) |
| tcp_options | Scapy-based TCP SYN option manipulation |
| source_port | Per-request source port manipulation |
| proxy_manager | ProtonVPN integration, proxy chains, IP rotation |
| proxy_mode | Stealth proxy with header rewriting and TLS spoofing |
| proxy_pool | External proxy pool management with liveness probing |
| tor_rotator | Multi-instance Tor IP rotation via NEWNYM |
| mitm_proxy | Full HTTPS MITM with dynamic per-host cert generation |
| headless_browser | Playwright-based JS challenge solving (Cloudflare, DataDome, PerimeterX) |
| cf_header_inject | Cloudflare header trust testing (CF-Connecting-IP, CF-Ray, etc.) |
| response_advisor | Escalating auto-retry strategies on WAF blocks |
| tui_dashboard | Real-time terminal UI with live traffic and technique tracking |
| origin_finder | Subdomain leakage, historical DNS, SSL cert, favicon hash, GitHub leaks, Censys, Shodan, VirusTotal, Whoxy, DNSTrails |
| api_keys | API key management (config file + env vars) for 13 services |
| error_pages | Probe 404/403/500/WAF trigger pages for signature leakage |
| asn_lookup | ASN classification: 50+ WAF/CDN providers, 30+ hosting providers |
| dns_resolver | DNS resolution with CNAME chain extraction |
| dns_encrypted | DNS-over-TLS and DNS-over-HTTPS (Cloudflare, Google, Quad9, AdGuard) |
| header_order | Browser-accurate header ordering profiles (Chrome, Firefox, Safari, Edge) |
| http3_probe | HTTP/3 QUIC probing, protocol comparison, and WAF bypass detection |
| socks5_udp | SOCKS5 UDP ASSOCIATE relay for routing QUIC through proxies |
| proto_probe | Multi-protocol probing (H1/H2/H3) with WAF behavior diff analysis |
| scan_persistence | Cross-session SQLite storage with statistical confidence scoring and FP verification |

## WAF/CDN Provider Detection

The tool distinguishes between WAF/CDN proxies and plain hosting to accurately classify bypass results:

**WAF/CDN (bypass if DNS resolves here):** Cloudflare, Akamai, Fastly, CloudFront, Imperva/Incapsula, Sucuri, Radware, F5, Barracuda, Fortinet, DDoS-Guard, Qrator, StormWall, StackPath, CDN77, Edgecast, Limelight, BunnyCDN, Gcore, Wallarm, Reblaze, DataDome, PerimeterX, Azure Front Door, AWS Shield, Google Cloud Armor, Netlify, Vercel, and more.

**Hosting (direct access, not bypass):** AWS, Google Cloud, Azure, DigitalOcean, Linode, Vultr, Hetzner, OVH, Scaleway, Oracle Cloud, Rackspace, Contabo, Leaseweb, GoDaddy, Hostinger, and more.

**Default vhost detection:** SiteGround, nginx default, Apache default, cPanel, Plesk, parking/propagation pages -- automatically rejected as false positives.
