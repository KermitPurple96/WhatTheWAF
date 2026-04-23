# WhatTheWAF v2.0

WAF/CDN Detection | WAF Bypass | TLS Fingerprint Evasion

## Install

```bash
git clone https://github.com/KermitPurple96/WhatTheWAF.git
cd WhatTheWAF
pip install -e .
```

Both `whatthewaf` and `wtw` commands are available after install.

## Quick Start

```bash
# Full WAF scan
wtw example.com

# Only WAF detection
wtw example.com --only waf

# Only IPs + WAF + error pages
wtw example.com --only ips,waf,errors

# Direct IP bypass PoC (connect to IP bypassing DNS/CDN)
wtw example.com --direct-ip 1.2.3.4

# WAF evasion analysis
wtw example.com --evasion

# Origin IP classification
wtw example.com -m origins

# Scan through ProtonVPN
wtw example.com --proton --evasion

# JSON output
wtw example.com --json -o report.json
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
| `subs` | Subdomain origin leakage scan |
| `history` | Historical DNS record lookup |
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

### Direct IP Bypass PoC

```
--direct-ip IP           Single IP, comma-separated IPs, or 'auto'
--path PATH              Path to test (default: /)
```

Connects to the specified IP with the `Host` header set to the target domain, bypassing DNS resolution and any CDN/WAF in front. Compares body hashes between CDN and direct response to confirm bypass.

Determination logic:
- **Same hash** + DNS via WAF → `WAF BYPASS CONFIRMED`
- **Same hash** + DNS without WAF → `DIRECT ACCESS CONFIRMED`
- **Different hash** + default vhost detected → `DEFAULT VHOST` (not a bypass)
- **Different hash** + real content → `WAF BYPASS LIKELY` / `DIRECT ACCESS`

```bash
# Single IP
wtw example.com --direct-ip 203.0.113.50

# Multiple IPs (comma-separated)
wtw example.com --direct-ip 203.0.113.50,203.0.113.51,10.0.0.5

# Auto-discover origin IPs (subdomain leakage + historical DNS) and test all
wtw example.com --direct-ip auto

# Test specific path
wtw example.com --direct-ip 203.0.113.50 --path /login

# Combine: auto-discover + specific path
wtw example.com --direct-ip auto --path /api/v1/health

# Save PoC as JSON
wtw example.com --direct-ip 203.0.113.50 --json -o bypass-poc.json
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
--stealth-status         Show status of all evasion capabilities
```

### Request Tuning

```
--user-agent UA          Custom User-Agent
--timeout SECS           Request timeout (default: 10)
--delay SECS             Delay between targets
--workers N              Concurrent workers for batch scanning
```

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
# Auto-discover and test all origin IPs
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

> **Do NOT use** `pip install protonvpn-cli` — that's the old v2 CLI which no longer works (API returns 422).

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
| waf_signatures | 90+ WAF/CDN vendor detection |
| waf_bypass | Direct IP, alt ports, header spoofing, HTTP downgrade |
| waf_evasion | Detect what WAF checks: UA, encoding, methods, rate limiting |
| tls_fingerprint | TLS config analysis, test which configs WAF accepts/rejects |
| proxy_manager | ProtonVPN integration, proxy chains, IP rotation |
| error_pages | Probe 404/403/500/WAF trigger pages |
| origin_finder | Subdomain leakage, historical DNS, SSL cert analysis |
| asn_lookup | ASN classification (CDN vs origin) |
| dns_resolver | DNS resolution |
