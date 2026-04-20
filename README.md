# WhatTheWAF v2.0

WAF/CDN Detection | WAF Bypass | TLS Fingerprint Evasion

## Install

```bash
git clone https://github.com/KermitPurple96/WhatTheWAF.git
cd WhatTheWAF
pip install -e .
```

## Usage

```bash
# Basic WAF scan
whatthewaf example.com

# WAF evasion analysis (test what the WAF detects about you)
whatthewaf example.com --evasion

# Quick origin IP classification
whatthewaf example.com -m origins

# Scan through a proxy
whatthewaf example.com --proxy socks5://127.0.0.1:9050

# Scan through ProtonVPN
whatthewaf example.com --proton --evasion

# Test multiple proxies against WAF
whatthewaf example.com --proxy-chain "socks5://proxy1:1080,http://proxy2:8080"

# Batch scan from file
whatthewaf -l domains.txt --workers 5

# JSON output
whatthewaf example.com --json -o report.json

# Historical DNS + subdomain origin leakage
whatthewaf example.com --history
```

## Flags

```
targets              Domain(s), IP(s), or @file.txt
--stdin              Read targets from stdin
-l, --list FILE      Read targets from file
-m, --mode           origins | full (default: full)
--json               JSON output
-o, --output FILE    Write results to file
--evasion            Run WAF evasion analysis (UA, encoding, methods)
--no-tls             Skip TLS fingerprint analysis
--no-subs            Skip subdomain leakage scan
--no-cert            Skip SSL certificate check
--history            Check historical DNS records
--proxy URL          Proxy for all requests (http/socks5)
--proxy-chain LIST   Comma-separated proxies to test against WAF
--proton             Route traffic through ProtonVPN SOCKS (127.0.0.1:1080)
--proton-check       Check ProtonVPN status (no target needed)
--proton-rotate      Rotate ProtonVPN IP (no target needed)
--user-agent UA      Custom User-Agent
--timeout SECS       Request timeout (default: 10)
--delay SECS         Delay between targets
--workers N          Concurrent workers for batch
-q, --quiet          Suppress banner
-v, --version        Show version
```

## ProtonVPN Setup

WhatTheWAF can route traffic through ProtonVPN to change your exit IP and bypass IP-based WAF blocks. ProtonVPN is **optional** — the tool works without it.

### Option A: ProtonVPN CLI (recommended for IP rotation)

```bash
# 1. Install
pip install protonvpn-cli
```

The binary is called `protonvpn` (not `protonvpn-cli`). If your shell can't find it, it's in `~/.local/bin/`:

```bash
# Check where it is
which protonvpn || ls ~/.local/bin/protonvpn

# If not in PATH, add it
export PATH="$HOME/.local/bin:$PATH"
```

```bash
# 2. First-time setup (interactive — asks username, password, plan, protocol)
protonvpn init
```

This asks for:
- **OpenVPN username/password** — NOT your Proton account password. Get these from: https://account.protonvpn.com/account#openvpn-ike2 (look for "OpenVPN / IKEv2 username" and "OpenVPN / IKEv2 password")
- **ProtonVPN plan** (Free, Basic, Plus, Visionary)
- **Default protocol** (UDP recommended)

```bash
# 3. Connect
protonvpn connect --fastest

# 4. Check status
protonvpn status

# 5. Verify it works with WhatTheWAF
whatthewaf --proton-check

# 6. Use in scans
whatthewaf example.com --proton --evasion

# 7. Rotate IP if blocked
whatthewaf --proton-rotate
whatthewaf example.com --proton

# 8. Disconnect when done
protonvpn disconnect
```

**ProtonVPN CLI quick reference:**

```
protonvpn init                   # First-time setup
protonvpn connect --fastest      # Connect to fastest server
protonvpn connect --cc NL        # Connect to Netherlands
protonvpn connect --random       # Connect to random server
protonvpn status                 # Show connection status
protonvpn disconnect             # Disconnect
protonvpn reconnect              # Reconnect to last server
```

**Important:** You need a Proton account (free tier works but limited servers). The CLI uses **OpenVPN credentials**, not your regular Proton login. Get them at https://account.protonvpn.com/account#openvpn-ike2

### Option B: ProtonVPN GUI (no rotation, simpler)

If you use the ProtonVPN desktop app instead of the CLI:

1. Open ProtonVPN app and connect to any server
2. Go to **Settings > Advanced > SOCKS5 Proxy** and enable it on port **1080**
3. Verify: `whatthewaf --proton-check`
4. Use: `whatthewaf example.com --proton`

With the GUI you cannot use `--proton-rotate` (rotation requires the CLI).

### What --proton-check shows

```
ProtonVPN Status Check
--------------------------------------------------
  Your IP (direct):  203.0.113.10
  CLI installed:     Yes (protonvpn-cli)
  Logged in:         Yes
  Connected:         Yes
  Server:            NL#42
  SOCKS proxy:       Active (127.0.0.1:1080)
  Exit IP:           185.107.56.78
  Location:          Amsterdam, Netherlands
  ISP:               Proton AG

  [+] IP successfully changed: 203.0.113.10 -> 185.107.56.78
  [+] IP rotation available — use --proton-rotate to change IP
```

### Pentest workflow with ProtonVPN

```bash
# Check you're connected
whatthewaf --proton-check

# Scan target through ProtonVPN
whatthewaf target.com --proton --evasion

# If WAF blocks your ProtonVPN IP, rotate and retry
whatthewaf --proton-rotate
whatthewaf target.com --proton --evasion

# Compare results with and without VPN
whatthewaf target.com --json -o direct.json
whatthewaf target.com --proton --json -o proton.json
```

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
