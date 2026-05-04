"""WhatTheWAF CLI — WAF/CDN Detection, Bypass Testing, TLS Fingerprint Evasion."""

import argparse
import json
import sys
import os

from . import __version__
from .scanner import origins_scan, full_scan, full_scan_batch, direct_ip_scan

RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"
CYAN = "\033[36m"; MAGENTA = "\033[35m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"


def _load_banner():
    for path in [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ascii"),
                 os.path.join(os.path.dirname(os.path.abspath(__file__)), "ascii")]:
        try:
            with open(path) as f:
                art = f.read().rstrip()
            return (f"{CYAN}{BOLD}{art}{RESET}\n"
                    f"  {YELLOW}v{__version__}{RESET}  "
                    f"{MAGENTA}WAF/CDN Detection | WAF Bypass | TLS Fingerprint Evasion{RESET}\n")
        except FileNotFoundError:
            continue
    return f"{CYAN}{BOLD}WhatTheWAF{RESET} {YELLOW}v{__version__}{RESET}\n"


def main():
    parser = argparse.ArgumentParser(
        description="WhatTheWAF - WAF/CDN Detection, Bypass, TLS Fingerprint Evasion & WAF Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  whatthewaf example.com
  whatthewaf example.com --only waf
  whatthewaf example.com --direct-ip auto
  whatthewaf example.com --evasion
  whatthewaf example.com --waf-scan

  # individual OSINT tools
  whatthewaf example.com --favicon
  whatthewaf example.com --github-leaks
  whatthewaf example.com --censys --shodan --virustotal
  whatthewaf example.com --favicon --censys --shodan --github-leaks --securitytrails --virustotal

  # stealth
  whatthewaf example.com --tor --tls-rotate --source-port rotating
  whatthewaf --proxy-mode --proton --tls-rotate --h2-rotate
  cat subs.txt | whatthewaf --stdin -m origins""",
    )
    parser.add_argument("targets", nargs="*", help="Domain(s), IP(s), or @file.txt")
    parser.add_argument("--stdin", action="store_true", help="Read targets from stdin")
    parser.add_argument("-l", "--list", metavar="FILE", help="Read targets from file")
    parser.add_argument("-m", "--mode", choices=["origins", "full"], default="full")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-o", "--output", metavar="FILE")
    parser.add_argument("--only", metavar="MODULES",
                        help="Run only specific modules (comma-separated): ips, waf, errors, tls, evasion, bypass, cert, subs, history, proxy")
    parser.add_argument("--direct-ip", metavar="IP",
                        help="IP(s) to connect directly (comma-separated), or 'auto' to discover and test origin IPs")
    parser.add_argument("--path", metavar="PATH", default="/",
                        help="Path to test in direct-ip mode (default: /)")
    parser.add_argument("--no-subs", action="store_true", help="Skip subdomain leakage scan")
    parser.add_argument("--no-cert", action="store_true", help="Skip SSL certificate check")
    parser.add_argument("--no-tls", action="store_true", help="Skip TLS fingerprint analysis")
    parser.add_argument("--history", action="store_true", help="Check historical DNS records")
    parser.add_argument("--evasion", action="store_true", help="Run WAF evasion analysis (UA, encoding, methods)")
    parser.add_argument("--proxy-chain", metavar="PROXIES", help="Comma-separated proxy URLs to test")
    parser.add_argument("--proton", action="store_true", help="Use ProtonVPN SOCKS proxy (socks5://127.0.0.1:1080)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--proxy", metavar="URL", help="HTTP/SOCKS proxy for all requests")
    parser.add_argument("--user-agent", metavar="UA")
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--proxy-mode", action="store_true",
                        help="Start as stealth proxy (JA3 evasion + browser headers + ProtonVPN)")
    parser.add_argument("--listen-port", type=int, default=8888,
                        help="Port for proxy mode (default: 8888)")
    parser.add_argument("--no-spoof-ua", action="store_true",
                        help="Proxy mode: don't replace User-Agent")
    parser.add_argument("--no-spoof-tls", action="store_true",
                        help="Proxy mode: don't modify TLS fingerprint")
    parser.add_argument("--proxy-verbose", action="store_true",
                        help="Proxy mode: log all requests")
    parser.add_argument("--random-delay", type=float, default=0,
                        help="Proxy mode: max random delay (secs) between requests to mimic human")
    parser.add_argument("--install-curl-impersonate", action="store_true",
                        help="Download and install curl-impersonate (Chrome/Firefox HTTP/2 emulation)")
    parser.add_argument("--tcp-profile", choices=["windows", "macos"],
                        help="Apply TCP fingerprint profile (changes TTL, window size — needs sudo)")
    parser.add_argument("--tcp-revert", action="store_true",
                        help="Revert TCP fingerprint to Linux defaults")
    parser.add_argument("--tcp-status", action="store_true",
                        help="Show current TCP fingerprint (what OS you look like)")
    parser.add_argument("--solve-challenge", metavar="URL",
                        help="Solve JS challenge with headless browser and export cookies")
    parser.add_argument("--install-playwright", action="store_true",
                        help="Install Playwright + Chromium for JS challenge solving")
    parser.add_argument("--screenshot", metavar="FILE",
                        help="Save screenshot when solving challenge")
    parser.add_argument("--stealth-status", action="store_true",
                        help="Show status of all evasion capabilities")
    parser.add_argument("--proton-check", action="store_true",
                        help="Check ProtonVPN status, connectivity, and IP rotation capability")
    parser.add_argument("--proton-rotate", action="store_true",
                        help="Rotate ProtonVPN IP (disconnect + reconnect to new server)")
    # New evasion modules
    parser.add_argument("--tor", action="store_true",
                        help="Use Tor for IP rotation (auto-detects running instances)")
    parser.add_argument("--tor-password", metavar="PASS", default="",
                        help="Tor control port password for IP rotation")
    parser.add_argument("--cf-inject", action="store_true",
                        help="Test Cloudflare header injection bypass (CF-Connecting-IP, CF-Ray, etc.)")
    parser.add_argument("--source-port", metavar="PROFILE",
                        choices=["trusted", "browser_linux", "browser_windows", "scanner_evasion", "rotating"],
                        help="Manipulate TCP source port per request")
    parser.add_argument("--tls-rotate", action="store_true",
                        help="Rotate TLS fingerprint per request (requires tls-client)")
    parser.add_argument("--h2-rotate", action="store_true",
                        help="Rotate HTTP/2 SETTINGS fingerprint per request")
    parser.add_argument("--tcp-options", metavar="PROFILE",
                        choices=["chrome", "firefox", "safari", "edge", "windows10", "linux", "random"],
                        help="Set TCP SYN options to match browser profile (requires scapy + root)")
    parser.add_argument("--waf-scan", action="store_true",
                        help="Run deep WAF vulnerability scanner (10 layers)")
    parser.add_argument("--waf-scan-layers", metavar="LAYERS",
                        help="Scan specific layers (comma-separated): network,ruleengine,ratelimit,evasion,behavioural,header,tls,method,session,misconfig")
    parser.add_argument("--mitm", action="store_true",
                        help="Start MITM proxy with dynamic cert generation (full HTTPS interception)")
    parser.add_argument("--auto-retry", action="store_true",
                        help="Auto-retry with different techniques when WAF blocks (403/429/503)")
    parser.add_argument("--proxy-pool", metavar="FILE",
                        help="File with proxy URLs (one per line) for IP rotation pool")
    parser.add_argument("--tui", action="store_true",
                        help="Show real-time TUI dashboard (requires urwid)")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--api-status", action="store_true",
                        help="Show which API keys are configured")
    parser.add_argument("--api-init", action="store_true",
                        help="Create template API key config file")
    # Individual OSINT tools
    parser.add_argument("--favicon", nargs="?", const="auto", default=None, metavar="URL_OR_HASH",
                        help="Favicon hash search. No arg: fetch from target. URL: fetch from URL. Number: use as MMH3 hash directly.")
    parser.add_argument("--github-leaks", action="store_true",
                        help="Search GitHub for leaked origin IPs in configs/.env files")
    parser.add_argument("--censys", nargs="?", const="auto", default=None, metavar="QUERY",
                        help="Censys search. No arg: cert search for target. String: raw Censys query.")
    parser.add_argument("--shodan", nargs="?", const="auto", default=None, metavar="QUERY",
                        help="Shodan search. No arg: domain DNS records. String: raw Shodan query.")
    parser.add_argument("--virustotal", action="store_true",
                        help="Query VirusTotal for domain resolution history")
    parser.add_argument("--securitytrails", action="store_true",
                        help="Query SecurityTrails for historical DNS A records")
    parser.add_argument("--whoxy", action="store_true",
                        help="Whoxy WHOIS + reverse WHOIS to find sibling domains and shared IPs")
    parser.add_argument("--dnstrails", action="store_true",
                        help="DNSTrails historical DNS records and subdomain enumeration")
    parser.add_argument("--recon", action="store_true",
                        help="Run all OSINT sources, correlate results, and classify IPs")
    parser.add_argument("-v", "--version", action="version", version=f"WhatTheWAF {__version__}")

    args = parser.parse_args()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not args.quiet and not args.no_banner:
        print(_load_banner(), file=sys.stderr)

    # Handle proton-check / proton-rotate / proxy-mode (no target needed)
    if args.proton_check:
        _run_proton_check()
        return
    if args.proton_rotate:
        _run_proton_rotate()
        return
    if args.proxy_mode:
        _run_proxy_mode(args)
        return
    if args.stealth_status:
        _run_stealth_status()
        return
    if args.install_curl_impersonate:
        _run_install_curl_impersonate()
        return
    if args.install_playwright:
        _run_install_playwright()
        return
    if args.tcp_status:
        _run_tcp_status()
        return
    if args.tcp_profile:
        _run_tcp_profile(args.tcp_profile)
        return
    if args.tcp_revert:
        _run_tcp_revert()
        return
    if args.solve_challenge:
        _run_solve_challenge(args)
        return
    if args.mitm:
        _run_mitm_proxy(args)
        return
    if args.api_status:
        _run_api_status()
        return
    if args.api_init:
        _run_api_init()
        return

    targets = _collect_targets(args)

    # Individual OSINT tools (some can run without a target)
    osint_mode = any([args.favicon is not None, args.github_leaks,
                      args.censys is not None, args.shodan is not None,
                      args.virustotal, args.securitytrails, args.whoxy,
                      args.dnstrails])
    if osint_mode:
        _run_osint(targets, args)
        return

    if args.recon:
        if not targets:
            parser.error("--recon requires at least one target domain.")
        _run_recon(targets, args)
        return

    if not targets:
        parser.error("No targets specified.")

    if args.waf_scan:
        _run_waf_scan(targets, args)
    elif args.cf_inject:
        _run_cf_inject(targets, args)
    elif args.direct_ip:
        _run_direct_ip(targets, args)
    elif args.mode == "origins":
        _run_origins(targets, args)
    else:
        _run_full(targets, args)


def _run_stealth_status():
    """Show status of all evasion capabilities."""
    from .modules import http2_fingerprint, tcp_fingerprint, headless_browser, proxy_manager

    print(f"\n{BOLD}Stealth Evasion Status{RESET}")
    print("=" * 60)

    # ProtonVPN
    proton = proxy_manager.proton_status()
    proton_ok = proton.get("socks_available") or proton.get("connected")
    print(f"\n  {BOLD}IP Rotation (ProtonVPN):{RESET}")
    print(f"    Status: {GREEN + 'Ready' + RESET if proton_ok else RED + 'Not available' + RESET}")
    if proton.get("exit_ip"):
        print(f"    Exit IP: {proton['exit_ip']} ({proton.get('country', '?')})")

    # Tor
    try:
        from .modules.tor_rotator import TorRotator
        tr = TorRotator()
        tor_count = len(tr._alive_proxies)
        print(f"\n  {BOLD}IP Rotation (Tor):{RESET}")
        if tor_count > 0:
            print(f"    Status: {GREEN}{tor_count} instance(s) detected{RESET}")
        else:
            print(f"    Status: {RED}No Tor instances found{RESET}")
        print(f"    Use: {CYAN}whatthewaf --tor{RESET}")
    except Exception:
        print(f"\n  {BOLD}IP Rotation (Tor):{RESET}")
        print(f"    Status: {RED}Not available{RESET}")

    # TLS Rotation (tls-client)
    try:
        from .modules.tls_rotator import TLSRotator
        tls_ok = TLSRotator.is_available()
        print(f"\n  {BOLD}TLS Fingerprint Rotation (tls-client):{RESET}")
        print(f"    Status: {GREEN + 'Ready' + RESET if tls_ok else YELLOW + 'Fallback mode (pip install tls-client)' + RESET}")
        print(f"    Use: {CYAN}whatthewaf --tls-rotate{RESET}")
    except Exception:
        pass

    # TCP Options (Scapy)
    try:
        from .modules.tcp_options import TCPOptionsManipulator
        tcp_opt = TCPOptionsManipulator()
        print(f"\n  {BOLD}TCP SYN Options (Scapy):{RESET}")
        print(f"    Scapy: {GREEN + 'Available' + RESET if tcp_opt.is_available() else RED + 'Not available (pip install scapy)' + RESET}")
        print(f"    Use: {CYAN}whatthewaf --tcp-options chrome{RESET}")
    except Exception:
        pass

    # Source Port
    print(f"\n  {BOLD}Source Port Manipulation:{RESET}")
    print(f"    Status: {GREEN}Available{RESET}")
    print(f"    Use: {CYAN}whatthewaf --source-port rotating{RESET}")

    # curl-impersonate
    print(f"\n  {BOLD}HTTP/2 Fingerprint (curl-impersonate):{RESET}")
    ci_installed = http2_fingerprint.is_installed()
    print(f"    Status: {GREEN + 'Installed' + RESET if ci_installed else RED + 'Not installed' + RESET}")
    if not ci_installed:
        print(f"    Install: {CYAN}whatthewaf --install-curl-impersonate{RESET}")

    # TCP fingerprint
    print(f"\n  {BOLD}TCP Fingerprint (p0f evasion):{RESET}")
    tcp = tcp_fingerprint.get_status()
    print(f"    Current TTL: {tcp['current_ttl']} → looks like: {YELLOW}{tcp['looks_like']}{RESET}")
    if tcp.get("iptables_ttl_rules"):
        print(f"    Active rules: {tcp['iptables_ttl_rules']}")
    print(f"    Has sudo: {'Yes' if tcp['has_sudo'] else 'No'}")
    if tcp["looks_like"] != "Windows":
        print(f"    Apply: {CYAN}whatthewaf --tcp-profile windows{RESET}")

    # Headless browser
    print(f"\n  {BOLD}JS Challenge Solver (Playwright):{RESET}")
    pw_installed = headless_browser.is_installed()
    print(f"    Status: {GREEN + 'Ready' + RESET if pw_installed else RED + 'Not installed' + RESET}")
    if not pw_installed:
        print(f"    Install: {CYAN}whatthewaf --install-playwright{RESET}")

    # MITM Proxy
    print(f"\n  {BOLD}MITM Proxy (HTTPS interception):{RESET}")
    print(f"    Status: {GREEN}Available{RESET}")
    print(f"    Use: {CYAN}whatthewaf --mitm --listen-port 8888{RESET}")

    # WAF Scanner
    print(f"\n  {BOLD}WAF Vulnerability Scanner:{RESET}")
    print(f"    Status: {GREEN}Available (10 layers){RESET}")
    print(f"    Use: {CYAN}whatthewaf example.com --waf-scan{RESET}")

    # TUI
    try:
        from .modules.tui_dashboard import WAFDashboard
        tui_ok = WAFDashboard.is_available()
        print(f"\n  {BOLD}TUI Dashboard:{RESET}")
        print(f"    Status: {GREEN + 'Available' + RESET if tui_ok else YELLOW + 'Fallback (pip install urwid)' + RESET}")
    except Exception:
        pass

    # API Keys
    try:
        from .modules import api_keys
        key_status = api_keys.status()
        configured = [k for k, v in key_status.items() if v]
        print(f"\n  {BOLD}API Keys:{RESET}")
        if configured:
            print(f"    Configured: {GREEN}{len(configured)}/{len(key_status)}{RESET}")
            for k in configured:
                print(f"      {GREEN}✓{RESET} {k}")
        else:
            print(f"    Status: {YELLOW}No API keys configured{RESET}")
        print(f"    Setup: {CYAN}wtw --api-init && wtw --api-status{RESET}")
    except Exception:
        pass

    print(f"\n{'=' * 60}")
    print(f"  {BOLD}Full stealth command:{RESET}")
    print(f"    {CYAN}whatthewaf --proxy-mode --proton --tls-rotate --source-port rotating --random-delay 2{RESET}")
    print(f"    or {CYAN}whatthewaf --mitm --tor --tls-rotate --h2-rotate{RESET}")
    print(f"    + {CYAN}whatthewaf --tcp-profile windows{RESET} (in another terminal)")
    print()


def _run_install_curl_impersonate():
    """Install curl-impersonate."""
    from .modules.http2_fingerprint import install, is_installed

    if is_installed():
        print(f"{GREEN}[+] curl-impersonate already installed{RESET}")
        return

    print(f"{CYAN}[*] Installing curl-impersonate...{RESET}")
    result = install(verbose=True)
    if result["success"]:
        print(f"{GREEN}[+] Installed: {result['path']}{RESET}")
    else:
        print(f"{RED}[!] Failed: {result['error']}{RESET}")


def _run_install_playwright():
    """Install Playwright + Chromium."""
    from .modules.headless_browser import install

    print(f"{CYAN}[*] Installing Playwright + Chromium...{RESET}")
    result = install(verbose=True)
    if result["success"]:
        print(f"{GREEN}[+] Playwright + Chromium installed{RESET}")
    else:
        print(f"{RED}[!] Failed: {result['error']}{RESET}")


def _run_tcp_status():
    """Show TCP fingerprint status."""
    from .modules.tcp_fingerprint import get_status

    status = get_status()
    print(f"\n{BOLD}TCP Fingerprint Status{RESET}")
    print(f"  TTL:              {status['current_ttl']}")
    print(f"  Looks like:       {YELLOW}{status['looks_like']}{RESET}")
    print(f"  Window scaling:   {status.get('tcp_window_scaling', '?')}")
    print(f"  SACK:             {status.get('tcp_sack', '?')}")
    print(f"  Timestamps:       {status.get('tcp_timestamps', '?')}")
    print(f"  Has sudo:         {'Yes' if status['has_sudo'] else 'No'}")
    if status.get("iptables_ttl_rules"):
        print(f"  Active TTL rules: {status['iptables_ttl_rules']}")
    print()


def _run_tcp_profile(profile_name):
    """Apply TCP fingerprint profile."""
    from .modules.tcp_fingerprint import apply_profile

    print(f"{CYAN}[*] Applying {profile_name} TCP profile...{RESET}")
    result = apply_profile(profile_name)

    if result["changes_made"]:
        for change in result["changes_made"]:
            print(f"  {GREEN}[+]{RESET} {change}")
    if result["errors"]:
        for err in result["errors"]:
            print(f"  {RED}[!]{RESET} {err}")

    if result["revert_commands"]:
        print(f"\n  {BOLD}To revert:{RESET} {CYAN}whatthewaf --tcp-revert{RESET}")

    print()


def _run_tcp_revert():
    """Revert TCP fingerprint."""
    from .modules.tcp_fingerprint import revert_profile

    print(f"{CYAN}[*] Reverting TCP fingerprint to Linux defaults...{RESET}")
    result = revert_profile()
    for change in result["changes_reverted"]:
        print(f"  {GREEN}[+]{RESET} {change}")
    print()


def _run_solve_challenge(args):
    """Solve JS challenge with headless browser."""
    from .modules.headless_browser import solve_challenge, export_cookies_for_curl

    url = args.solve_challenge
    proxy = None
    if args.proton:
        from .modules.proxy_manager import PROTON_SOCKS
        proxy = PROTON_SOCKS
    elif args.proxy:
        proxy = args.proxy

    print(f"{CYAN}[*] Solving challenge at {url}...{RESET}")
    result = solve_challenge(
        url, timeout=args.timeout or 30, proxy=proxy,
        screenshot_path=args.screenshot, verbose=True,
    )

    if result["success"]:
        print(f"\n  {BOLD}Result:{RESET}")
        print(f"    Status: {result['status_code']}")
        print(f"    Title:  {result['title']}")
        print(f"    Challenge detected: {'Yes' if result['challenge_detected'] else 'No'}")
        if result["challenge_detected"]:
            solved_str = f"{GREEN}SOLVED{RESET}" if result["challenge_solved"] else f"{RED}NOT SOLVED{RESET}"
            print(f"    Challenge solved:   {solved_str}")

        if result["cookies"]:
            cookie_str = export_cookies_for_curl(result["cookies"])
            print(f"\n  {BOLD}Cookies (use in curl):{RESET}")
            print(f"    {CYAN}curl -sk -b '{cookie_str}' {url}{RESET}")
            print(f"\n  {BOLD}Or export for other tools:{RESET}")
            for c in result["cookies"][:10]:
                print(f"    {c['name']}={c['value'][:50]}")

        if result.get("screenshot_path"):
            print(f"\n  Screenshot: {result['screenshot_path']}")
    else:
        print(f"  {RED}[!] Failed: {result['error']}{RESET}")
    print()


def _run_proxy_mode(args):
    """Start stealth proxy mode."""
    from .modules.proxy_mode import run_proxy

    run_proxy(
        listen_host="127.0.0.1",
        listen_port=args.listen_port,
        upstream_proxy=args.proxy,
        use_proton=args.proton,
        spoof_ua=not args.no_spoof_ua,
        spoof_tls=not args.no_spoof_tls,
        strip_tool_headers=True,
        add_referer=True,
        random_delay=args.random_delay,
        verbose=args.proxy_verbose,
    )


def _run_mitm_proxy(args):
    """Start MITM proxy with dynamic cert generation."""
    from .modules.mitm_proxy import MITMProxy

    proxy = MITMProxy(
        listen_host="127.0.0.1",
        listen_port=args.listen_port,
        upstream_proxy=args.proxy,
        use_proton=args.proton,
        spoof_ua=not args.no_spoof_ua,
        spoof_tls=not args.no_spoof_tls,
        verbose=args.proxy_verbose,
    )
    proxy.start()


def _run_recon(targets, args):
    """Run all OSINT sources, correlate results, classify every IP."""
    from .modules import origin_finder, api_keys, dns_resolver, asn_lookup

    is_json = args.json
    all_reports = []

    for target in targets:
        domain = dns_resolver._clean_domain(target)
        if not is_json:
            W = max(len(domain) + 20, 60)
            print(f"\n{BOLD}{CYAN}{'=' * W}{RESET}")
            print(f"{BOLD}{CYAN}  OSINT Recon: {domain}{RESET}")
            print(f"{BOLD}{CYAN}{'=' * W}{RESET}")

        # ip -> {sources: set, ports: set, hostnames: set, org: str, ...}
        ip_intel = {}

        def _add(ip, source, **extra):
            if not ip:
                return
            if ip not in ip_intel:
                ip_intel[ip] = {"sources": set(), "ports": set(), "hostnames": set(), "extra": {}}
            ip_intel[ip]["sources"].add(source)
            for k, v in extra.items():
                if k == "port" and v:
                    ip_intel[ip]["ports"].add(v)
                elif k == "hostnames" and v:
                    ip_intel[ip]["hostnames"].update(v)
                elif v:
                    ip_intel[ip]["extra"][k] = v

        source_status = {}  # source -> count or error

        # 1. DNS A records
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [~] DNS resolution{RESET}"); sys.stderr.flush()
        dns_info = dns_resolver.resolve_domain(domain)
        a_records = dns_info.get("a_records", [])
        for ip in a_records:
            _add(ip, "dns")
        source_status["dns"] = len(a_records)

        # 2. Subdomain leakage
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [*] Subdomain leakage scan{RESET}"); sys.stderr.flush()
        cdn_ips = set()
        if a_records:
            asn_records = asn_lookup.lookup_asn_bulk(a_records)
            cdn_ips = {r["ip"] for r in asn_records if r["classification"] == "CDN"}
        subs = origin_finder.find_origins(domain, cdn_ips=cdn_ips, timeout=args.timeout)
        for c in subs:
            if not c.get("is_cdn"):
                _add(c["ip"], f"subdomain:{c.get('subdomain', '?')}")
        source_status["subdomains"] = len([c for c in subs if not c.get("is_cdn")])

        # 3. Historical DNS (ViewDNS + SecurityTrails)
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [<] Historical DNS{RESET}"); sys.stderr.flush()
        historical = origin_finder.fetch_historical_ips(domain, timeout=args.timeout)
        for h in historical:
            _add(h["ip"], f"history:{h.get('source', 'viewdns')}", last_seen=h.get("last_seen", ""))
        source_status["historical_dns"] = len(historical)

        # 4. SSL certificate
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [@] SSL certificate inspection{RESET}"); sys.stderr.flush()
        cert_info = None
        if a_records:
            cert_info = origin_finder.check_ssl_cert(a_records[0], domain, timeout=args.timeout)

        # 5. Favicon hash
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [#] Favicon hash matching{RESET}"); sys.stderr.flush()
        fav = origin_finder.fetch_favicon_hash(domain, timeout=args.timeout)
        fav_results = []
        if fav:
            fav_results = origin_finder.search_by_favicon_hash(fav["hash"], domain=domain, timeout=args.timeout)
            for r in fav_results:
                _add(r["ip"], f"favicon:{r['source']}", port=r.get("port"), hostnames=r.get("hostnames"),
                     org=r.get("org", ""))
        source_status["favicon"] = len(fav_results) if fav else "no favicon"

        # 6. GitHub leaks
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [G] GitHub leak search{RESET}"); sys.stderr.flush()
        github = origin_finder.search_github_leaks(domain, timeout=args.timeout)
        for r in github:
            _add(r["ip"], "github", repo=r.get("repo", ""), context=r.get("context", "")[:100])
        source_status["github"] = len(github)

        # 7. Censys
        if api_keys.get("censys_api_id") and api_keys.get("censys_api_secret"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [C] Censys certificate search{RESET}"); sys.stderr.flush()
            censys = origin_finder.search_censys(domain, timeout=args.timeout)
            for r in censys:
                _add(r["ip"], "censys", org=r.get("autonomous_system", ""))
            source_status["censys"] = len(censys)
        else:
            source_status["censys"] = "no key"

        # 8. Shodan
        if api_keys.get("shodan_api_key"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [S] Shodan domain search{RESET}"); sys.stderr.flush()
            shodan = origin_finder.search_shodan_domain(domain, timeout=args.timeout)
            for r in shodan:
                sub = r.get("subdomain", "")
                _add(r["ip"], f"shodan" + (f":{sub}" if sub else ""), last_seen=r.get("last_seen", ""))
            source_status["shodan"] = len(shodan)
        else:
            source_status["shodan"] = "no key"

        # 9. VirusTotal
        if api_keys.get("virustotal_api_key"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [V] VirusTotal resolutions{RESET}"); sys.stderr.flush()
            vt = origin_finder.search_virustotal(domain, timeout=args.timeout)
            for r in vt:
                _add(r["ip"], "virustotal", last_seen=r.get("last_seen", ""))
            source_status["virustotal"] = len(vt)
        else:
            source_status["virustotal"] = "no key"

        # 10. Whoxy (WHOIS + reverse WHOIS → sibling domains → IPs)
        if api_keys.get("whoxy_api_key"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [W] Whoxy reverse WHOIS{RESET}"); sys.stderr.flush()
            whoxy = origin_finder.search_whoxy(domain, timeout=args.timeout)
            for r in whoxy.get("ips", []):
                _add(r["ip"], f"whoxy:{r.get('sibling_domain', '?')}")
            source_status["whoxy"] = len(whoxy.get("ips", []))
            if whoxy.get("sibling_domains"):
                source_status["whoxy_siblings"] = len(whoxy["sibling_domains"])
        else:
            source_status["whoxy"] = "no key"

        # 11. DNSTrails
        if api_keys.get("dnstrails_api_key"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [D] DNSTrails{RESET}"); sys.stderr.flush()
            dt = origin_finder.search_dnstrails(domain, timeout=args.timeout)
            for r in dt:
                label = r.get("subdomain", "") if r.get("type") == "subdomain" else "history"
                _add(r["ip"], f"dnstrails:{label}")
            source_status["dnstrails"] = len(dt)
        else:
            source_status["dnstrails"] = "no key"

        sys.stderr.write("\r\033[K"); sys.stderr.flush()

        # === CORRELATION: ASN classify all collected IPs ===
        all_ips = list(ip_intel.keys())
        asn_map = {}
        if all_ips:
            asn_results = asn_lookup.lookup_asn_bulk(all_ips)
            for rec in asn_results:
                asn_map[rec["ip"]] = rec

        # Classify each IP
        for ip, intel in ip_intel.items():
            asn = asn_map.get(ip, {})
            intel["asn"] = asn.get("asn", "")
            intel["provider"] = asn.get("provider", "")
            intel["classification"] = asn.get("classification", "UNKNOWN")
            intel["country"] = asn.get("country", "")
            intel["source_count"] = len(intel["sources"])

        # Sort: most sources first, then non-CDN first
        ranked = sorted(ip_intel.items(), key=lambda x: (
            -x[1]["source_count"],
            x[1]["classification"] == "CDN",
            x[0],
        ))

        # === PRINT RESULTS ===
        if not is_json:
            # Sources summary
            print(f"\n  {BOLD}Sources Queried{RESET}")
            for src, count in source_status.items():
                if isinstance(count, int):
                    icon = f"{GREEN}✓{RESET}" if count > 0 else f"{DIM}·{RESET}"
                    print(f"    {icon} {src:<20} {count} result(s)")
                else:
                    print(f"    {YELLOW}·{RESET} {src:<20} {DIM}{count}{RESET}")

            # Favicon hash
            if fav:
                print(f"\n  {BOLD}Favicon{RESET}")
                print(f"    Hash: {BOLD}{fav['hash']}{RESET}  ({fav.get('favicon_url', '?')})")
                print(f"    {DIM}Shodan: http.favicon.hash:{fav['hash']}{RESET}")

            # SSL cert
            if cert_info:
                print(f"\n  {BOLD}SSL Certificate{RESET}")
                print(f"    CN:     {cert_info.get('common_name', '?')}")
                print(f"    Issuer: {cert_info.get('issuer', '?')}")
                if cert_info.get("is_cdn_issued"):
                    print(f"    {YELLOW}CDN-issued certificate{RESET}")

            # Correlated IP table
            print(f"\n  {BOLD}Correlated IPs ({len(ranked)} unique){RESET}")
            print(f"  {'─' * 90}")
            print(f"  {BOLD}{'IP':<17} {'ASN':<10} {'Provider':<25} {'Type':<8} {'#Src':<5} Sources{RESET}")
            print(f"  {'─' * 90}")

            cdn_ips_found = []
            origin_candidates = []
            other_ips = []

            for ip, intel in ranked:
                cls = intel["classification"]
                src_count = intel["source_count"]
                sources_short = ", ".join(sorted(intel["sources"]))
                if len(sources_short) > 40:
                    sources_short = sources_short[:37] + "..."
                asn_str = f"AS{intel['asn']}" if intel['asn'] else "?"
                provider = intel["provider"][:24] if intel["provider"] else "?"

                if cls == "CDN":
                    color = RED
                    cdn_ips_found.append(ip)
                elif src_count >= 2:
                    color = GREEN
                    origin_candidates.append(ip)
                else:
                    color = YELLOW
                    origin_candidates.append(ip)

                bar = "█" * min(src_count, 10)
                print(f"  {color}{ip:<17}{RESET} {asn_str:<10} {provider:<25} {color}{cls:<8}{RESET} {src_count:<5}{DIM}{sources_short}{RESET}")

            print(f"  {'─' * 90}")

            # Verdict
            print(f"\n  {BOLD}Analysis{RESET}")
            if cdn_ips_found:
                print(f"    {RED}CDN/WAF IPs:{RESET} {', '.join(cdn_ips_found[:5])}")
            if origin_candidates:
                # Separate high-confidence (2+ sources) from low-confidence (1 source)
                high = [ip for ip in origin_candidates if ip_intel[ip]["source_count"] >= 2]
                low = [ip for ip in origin_candidates if ip_intel[ip]["source_count"] == 1]
                if high:
                    print(f"    {GREEN}High confidence origins (2+ sources):{RESET}")
                    for ip in high:
                        intel = ip_intel[ip]
                        print(f"      {GREEN}{ip:<17}{RESET} ({intel['source_count']} sources: {', '.join(sorted(intel['sources']))})")
                if low:
                    print(f"    {YELLOW}Low confidence (1 source):{RESET}")
                    for ip in low[:10]:
                        intel = ip_intel[ip]
                        src = next(iter(intel["sources"]))
                        print(f"      {YELLOW}{ip:<17}{RESET} ({src})")
                    if len(low) > 10:
                        print(f"      {DIM}... and {len(low) - 10} more{RESET}")
            else:
                print(f"    {DIM}No non-CDN IPs found.{RESET}")

            # Direct-IP command
            if origin_candidates:
                # Prioritize high-confidence
                test_ips = [ip for ip in origin_candidates if ip_intel[ip]["source_count"] >= 2]
                if not test_ips:
                    test_ips = origin_candidates[:10]
                ip_list = ",".join(test_ips[:15])
                print(f"\n  {BOLD}Next Steps{RESET}")
                print(f"    {CYAN}wtw {domain} --direct-ip {ip_list}{RESET}")
                if len(test_ips) > 15:
                    print(f"    {DIM}({len(test_ips) - 15} more IPs not shown — use --json for full list){RESET}")
            print()

        # Build JSON report
        report = {
            "target": domain,
            "sources_queried": source_status,
            "favicon": fav,
            "cert": cert_info,
            "ips": [],
        }
        for ip, intel in ranked:
            report["ips"].append({
                "ip": ip,
                "asn": intel["asn"],
                "provider": intel["provider"],
                "classification": intel["classification"],
                "country": intel["country"],
                "source_count": intel["source_count"],
                "sources": sorted(intel["sources"]),
                "ports": sorted(intel["ports"]),
                "hostnames": sorted(intel["hostnames"]),
            })
        all_reports.append(report)

    if is_json:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)


def _run_osint(targets, args):
    """Run individual OSINT / origin discovery tools."""
    from .modules import origin_finder, api_keys, dns_resolver

    is_json = args.json
    all_results = []

    # Favicon can work without a target if given a URL or hash directly
    if args.favicon is not None and args.favicon != "auto":
        _run_favicon_standalone(args.favicon, args, is_json)
        # If no other flags, we're done
        if not any([args.github_leaks, args.censys is not None, args.shodan is not None,
                     args.virustotal, args.securitytrails]):
            return

    # Shodan/Censys can run raw queries without a target
    if not targets:
        if args.shodan is not None and args.shodan != "auto":
            _run_shodan_raw(args.shodan, args, is_json)
        if args.censys is not None and args.censys != "auto":
            _run_censys_raw(args.censys, args, is_json)
        return

    for target in targets:
        domain = dns_resolver._clean_domain(target)
        report = {"target": domain, "sources": {}}

        # Favicon hash matching
        if args.favicon is not None and args.favicon == "auto":
            print(f"{CYAN}[*] Favicon hash: {domain}{RESET}", file=sys.stderr)
            fav = origin_finder.fetch_favicon_hash(domain, timeout=args.timeout)
            if fav:
                report["sources"]["favicon"] = {"hash": fav}
                _print_favicon_result(fav, api_keys)
                results = origin_finder.search_by_favicon_hash(fav["hash"], domain=domain, timeout=args.timeout)
                report["sources"]["favicon"]["results"] = results
                _print_favicon_search_results(results, api_keys)
            else:
                report["sources"]["favicon"] = {"error": "No favicon found or mmh3 not installed"}
                print(f"  {YELLOW}[!] No favicon found for {domain}{RESET}")
                try:
                    import mmh3 as _
                except ImportError:
                    print(f"  {DIM}Install mmh3 for favicon hashing: pip install mmh3{RESET}")
            print()

        # GitHub leak search
        if args.github_leaks:
            print(f"{CYAN}[*] GitHub leak search: {domain}{RESET}", file=sys.stderr)
            results = origin_finder.search_github_leaks(domain, timeout=args.timeout)
            report["sources"]["github"] = results
            if results:
                print(f"\n  {BOLD}GitHub Leaks{RESET}")
                print(f"    {GREEN}Found {len(results)} potential origin IP(s):{RESET}")
                for r in results:
                    print(f"      {GREEN}{r['ip']}{RESET}  in {CYAN}{r.get('repo', '?')}{RESET}")
                    print(f"        file: {DIM}{r.get('path', '?')}{RESET}")
                    ctx = r.get("context", "")
                    if ctx:
                        print(f"        {DIM}{ctx[:120]}{RESET}")
                    if r.get("url"):
                        print(f"        {DIM}{r['url']}{RESET}")
            else:
                print(f"  {DIM}No leaked IPs found on GitHub for {domain}{RESET}")
                print(f"  {DIM}(GitHub rate-limits unauthenticated searches){RESET}")
            print()

        # Censys
        if args.censys is not None:
            if not api_keys.get("censys_api_id") or not api_keys.get("censys_api_secret"):
                print(f"  {RED}[!] Censys API keys not configured{RESET}")
                print(f"  {DIM}Set CENSYS_API_ID and CENSYS_API_SECRET or run: wtw --api-init{RESET}")
                report["sources"]["censys"] = {"error": "API keys not configured"}
            else:
                if args.censys == "auto":
                    print(f"{CYAN}[*] Censys cert search: {domain}{RESET}", file=sys.stderr)
                    results = origin_finder.search_censys(domain, timeout=args.timeout)
                else:
                    print(f"{CYAN}[*] Censys query: {args.censys}{RESET}", file=sys.stderr)
                    results = origin_finder.search_censys_query(args.censys, timeout=args.timeout)
                report["sources"]["censys"] = results
                _print_censys_results(results, domain)
            print()

        # Shodan
        if args.shodan is not None:
            if not api_keys.get("shodan_api_key"):
                print(f"  {RED}[!] Shodan API key not configured{RESET}")
                print(f"  {DIM}Set SHODAN_API_KEY or run: wtw --api-init{RESET}")
                report["sources"]["shodan"] = {"error": "API key not configured"}
            else:
                if args.shodan == "auto":
                    print(f"{CYAN}[*] Shodan domain: {domain}{RESET}", file=sys.stderr)
                    results = origin_finder.search_shodan_domain(domain, timeout=args.timeout)
                    report["sources"]["shodan"] = results
                    _print_shodan_domain_results(results, domain)
                else:
                    print(f"{CYAN}[*] Shodan query: {args.shodan}{RESET}", file=sys.stderr)
                    results = origin_finder.search_shodan_query(args.shodan, timeout=args.timeout)
                    report["sources"]["shodan"] = results
                    _print_shodan_query_results(results)
            print()

        # VirusTotal
        if args.virustotal:
            print(f"{CYAN}[*] VirusTotal: {domain}{RESET}", file=sys.stderr)
            if not api_keys.get("virustotal_api_key"):
                print(f"  {RED}[!] VirusTotal API key not configured{RESET}")
                print(f"  {DIM}Set VIRUSTOTAL_KEY or run: wtw --api-init{RESET}")
                report["sources"]["virustotal"] = {"error": "API key not configured"}
            else:
                results = origin_finder.search_virustotal(domain, timeout=args.timeout)
                report["sources"]["virustotal"] = results
                if results:
                    print(f"\n  {BOLD}VirusTotal Resolutions{RESET}")
                    print(f"    {GREEN}Found {len(results)} historical IP(s):{RESET}")
                    for r in results:
                        seen = r.get("last_seen", "")
                        if isinstance(seen, int) and seen > 0:
                            import datetime
                            seen = datetime.datetime.utcfromtimestamp(seen).strftime("%Y-%m-%d")
                        seen_str = f"  {DIM}last seen: {seen}{RESET}" if seen else ""
                        print(f"      {GREEN}{r['ip']:<16}{RESET}{seen_str}")
                else:
                    print(f"  {DIM}No resolutions found on VirusTotal for {domain}{RESET}")
            print()

        # SecurityTrails
        if args.securitytrails:
            print(f"{CYAN}[*] SecurityTrails: {domain}{RESET}", file=sys.stderr)
            if not api_keys.get("securitytrails_key"):
                print(f"  {RED}[!] SecurityTrails API key not configured{RESET}")
                print(f"  {DIM}Set SECURITYTRAILS_KEY or run: wtw --api-init{RESET}")
                report["sources"]["securitytrails"] = {"error": "API key not configured"}
            else:
                results = origin_finder._securitytrails_history(domain, timeout=args.timeout)
                report["sources"]["securitytrails"] = results
                if results:
                    print(f"\n  {BOLD}SecurityTrails Historical DNS{RESET}")
                    print(f"    {GREEN}Found {len(results)} historical A record(s):{RESET}")
                    for r in results:
                        owner = r.get("owner", "")
                        owner_str = f"  {DIM}{owner}{RESET}" if owner else ""
                        seen = r.get("last_seen", "")
                        seen_str = f"  {DIM}last seen: {seen}{RESET}" if seen else ""
                        print(f"      {GREEN}{r['ip']:<16}{RESET}{owner_str}{seen_str}")
                else:
                    print(f"  {DIM}No historical records found on SecurityTrails for {domain}{RESET}")
            print()

        # Whoxy
        if args.whoxy:
            print(f"{CYAN}[*] Whoxy WHOIS: {domain}{RESET}", file=sys.stderr)
            if not api_keys.get("whoxy_api_key"):
                print(f"  {RED}[!] Whoxy API key not configured{RESET}")
                print(f"  {DIM}Set WHOXY_API_KEY or run: wtw --api-init{RESET}")
                report["sources"]["whoxy"] = {"error": "API key not configured"}
            else:
                whoxy = origin_finder.search_whoxy(domain, timeout=args.timeout)
                report["sources"]["whoxy"] = whoxy
                whois = whoxy.get("whois", {})
                if whois:
                    print(f"\n  {BOLD}Whoxy WHOIS{RESET}")
                    if whois.get("registrar"):
                        print(f"    Registrar: {whois['registrar']}")
                    if whoxy.get("registrant_email"):
                        print(f"    Email:     {whoxy['registrant_email']}")
                    if whoxy.get("registrant_name"):
                        print(f"    Name:      {whoxy['registrant_name']}")
                    if whoxy.get("registrant_company"):
                        print(f"    Company:   {whoxy['registrant_company']}")
                siblings = whoxy.get("sibling_domains", [])
                if siblings:
                    print(f"\n    {BOLD}Sibling Domains ({len(siblings)} by same registrant):{RESET}")
                    for s in siblings[:15]:
                        print(f"      {CYAN}{s}{RESET}")
                    if len(siblings) > 15:
                        print(f"      {DIM}... and {len(siblings) - 15} more{RESET}")
                ips = whoxy.get("ips", [])
                if ips:
                    print(f"\n    {GREEN}Resolved {len(ips)} IP(s) from sibling domains:{RESET}")
                    for r in ips:
                        print(f"      {GREEN}{r['ip']:<16}{RESET}  via {CYAN}{r.get('sibling_domain', '?')}{RESET}")
                elif siblings:
                    print(f"    {DIM}All sibling domains resolved to CDN IPs{RESET}")
                elif not whois:
                    print(f"  {DIM}No WHOIS data found for {domain}{RESET}")
                else:
                    print(f"  {DIM}WHOIS privacy enabled — no reverse WHOIS possible{RESET}")
            print()

        # DNSTrails
        if args.dnstrails:
            print(f"{CYAN}[*] DNSTrails: {domain}{RESET}", file=sys.stderr)
            if not api_keys.get("dnstrails_api_key"):
                print(f"  {RED}[!] DNSTrails API key not configured{RESET}")
                print(f"  {DIM}Set DNSTRAILS_API_KEY or run: wtw --api-init{RESET}")
                report["sources"]["dnstrails"] = {"error": "API key not configured"}
            else:
                results = origin_finder.search_dnstrails(domain, timeout=args.timeout)
                report["sources"]["dnstrails"] = results
                if results:
                    hist = [r for r in results if r.get("type") == "history"]
                    subs = [r for r in results if r.get("type") == "subdomain"]
                    print(f"\n  {BOLD}DNSTrails{RESET}")
                    if hist:
                        print(f"    {BOLD}Historical A Records ({len(hist)}):{RESET}")
                        for r in hist:
                            seen = r.get("last_seen", "")
                            seen_str = f"  {DIM}last seen: {seen}{RESET}" if seen else ""
                            print(f"      {GREEN}{r['ip']:<16}{RESET}{seen_str}")
                    if subs:
                        print(f"    {BOLD}Subdomain IPs ({len(subs)}):{RESET}")
                        for r in subs:
                            print(f"      {GREEN}{r['ip']:<16}{RESET}  {CYAN}{r.get('subdomain', '?')}{RESET}")
                else:
                    print(f"  {DIM}No results from DNSTrails for {domain}{RESET}")
            print()

        # Summary
        all_ips = {}
        for source_name, source_data in report["sources"].items():
            if isinstance(source_data, dict) and "error" in source_data:
                continue
            # Handle different data shapes
            if isinstance(source_data, list):
                items = source_data
            elif isinstance(source_data, dict):
                items = source_data.get("results", source_data.get("ips", []))
            else:
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                ip = item.get("ip", "")
                if ip:
                    if ip not in all_ips:
                        all_ips[ip] = []
                    all_ips[ip].append(source_name)

        if all_ips and not is_json:
            print(f"  {BOLD}{'=' * 55}{RESET}")
            print(f"  {BOLD}Summary: {len(all_ips)} unique IP(s) for {domain}{RESET}")
            print(f"  {BOLD}{'=' * 55}{RESET}")
            for ip, sources in sorted(all_ips.items()):
                src_str = ", ".join(sources)
                print(f"    {GREEN}{ip:<16}{RESET}  via {YELLOW}{src_str}{RESET}")
            ip_list = ",".join(all_ips.keys())
            print(f"\n  {BOLD}Test for bypass:{RESET}")
            print(f"    {CYAN}wtw {domain} --direct-ip {ip_list}{RESET}")
            print()

        report["unique_ips"] = [{"ip": ip, "sources": srcs} for ip, srcs in all_ips.items()]
        all_results.append(report)

    if is_json:
        _write_output(json.dumps(all_results, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_results, indent=2, default=str), args.output)


def _run_favicon_standalone(value, args, is_json):
    """Handle --favicon with a URL or hash value (no target needed)."""
    from .modules import origin_finder, api_keys

    # Determine if value is a hash (integer) or a URL
    fav = None
    try:
        fav_hash = int(value)
        fav = {"hash": fav_hash, "hash_str": str(fav_hash), "favicon_url": "(provided)", "size": 0}
    except ValueError:
        # It's a URL — fetch and hash it
        print(f"{CYAN}[*] Fetching favicon from {value}{RESET}", file=sys.stderr)
        fav = origin_finder.fetch_favicon_hash_from_url(value, timeout=args.timeout)
        if not fav:
            print(f"  {RED}[!] Could not fetch favicon from {value}{RESET}")
            try:
                import mmh3 as _
            except ImportError:
                print(f"  {DIM}Install mmh3: pip install mmh3{RESET}")
            return

    _print_favicon_result(fav, api_keys)
    results = origin_finder.search_by_favicon_hash(fav["hash"], timeout=args.timeout)
    _print_favicon_search_results(results, api_keys)

    if is_json:
        output = {"favicon": fav, "results": results}
        _write_output(json.dumps(output, indent=2, default=str), args.output)
    print()


def _print_favicon_result(fav, api_keys):
    """Print favicon hash info."""
    print(f"\n  {BOLD}Favicon Hash{RESET}")
    if fav.get("favicon_url") and fav["favicon_url"] != "(provided)":
        print(f"    URL:  {fav['favicon_url']}")
    print(f"    Hash: {BOLD}{fav['hash']}{RESET}")
    if fav.get("size"):
        print(f"    Size: {fav['size']} bytes")
    print(f"    {DIM}Shodan dork: http.favicon.hash:{fav['hash']}{RESET}")
    print(f"    {DIM}FOFA query:  icon_hash=\"{fav['hash']}\"{RESET}")


def _print_favicon_search_results(results, api_keys):
    """Print favicon search engine results."""
    if results:
        print(f"\n    {GREEN}Found {len(results)} host(s) with same favicon:{RESET}")
        for r in results:
            port_str = f":{r['port']}" if r.get("port") else ""
            org_str = f"  {DIM}{r['org']}{RESET}" if r.get("org") else ""
            hosts = ", ".join(r.get("hostnames", [])[:3])
            host_str = f"  {DIM}({hosts}){RESET}" if hosts else ""
            print(f"      {GREEN}{r['ip']}{port_str}{RESET}  via {YELLOW}{r['source']}{RESET}{org_str}{host_str}")
    else:
        configured = []
        if api_keys.get("shodan_api_key"): configured.append("Shodan")
        if api_keys.get("fofa_email") and api_keys.get("fofa_key"): configured.append("FOFA")
        if api_keys.get("zoomeye_key"): configured.append("ZoomEye")
        if configured:
            print(f"    {DIM}No matches found on {', '.join(configured)}{RESET}")
        else:
            print(f"    {YELLOW}No search engine API keys configured. Run: wtw --api-status{RESET}")


def _run_shodan_raw(query, args, is_json):
    """Run a raw Shodan search query (no target needed)."""
    from .modules import origin_finder, api_keys

    if not api_keys.get("shodan_api_key"):
        print(f"  {RED}[!] Shodan API key not configured{RESET}")
        print(f"  {DIM}Set SHODAN_API_KEY or run: wtw --api-init{RESET}")
        return

    print(f"{CYAN}[*] Shodan query: {query}{RESET}", file=sys.stderr)
    results = origin_finder.search_shodan_query(query, timeout=args.timeout)
    _print_shodan_query_results(results)
    print()

    if is_json:
        _write_output(json.dumps({"query": query, "results": results}, indent=2, default=str), args.output)


def _run_censys_raw(query, args, is_json):
    """Run a raw Censys search query (no target needed)."""
    from .modules import origin_finder, api_keys

    if not api_keys.get("censys_api_id") or not api_keys.get("censys_api_secret"):
        print(f"  {RED}[!] Censys API keys not configured{RESET}")
        print(f"  {DIM}Set CENSYS_API_ID and CENSYS_API_SECRET or run: wtw --api-init{RESET}")
        return

    print(f"{CYAN}[*] Censys query: {query}{RESET}", file=sys.stderr)
    results = origin_finder.search_censys_query(query, timeout=args.timeout)
    _print_censys_results(results, None)
    print()

    if is_json:
        _write_output(json.dumps({"query": query, "results": results}, indent=2, default=str), args.output)


def _print_censys_results(results, domain):
    """Print Censys search results."""
    label = f"for {domain}" if domain else ""
    if results:
        print(f"\n  {BOLD}Censys Results{RESET}")
        print(f"    {GREEN}Found {len(results)} host(s) {label}:{RESET}")
        for r in results:
            services = ", ".join(r.get("services", [])[:5]) or "?"
            asn_desc = r.get("autonomous_system", "")
            asn_str = f"  {DIM}{asn_desc}{RESET}" if asn_desc else ""
            print(f"      {GREEN}{r['ip']}{RESET}  services: {CYAN}{services}{RESET}{asn_str}")
    else:
        print(f"  {DIM}No results found on Censys {label}{RESET}")


def _print_shodan_domain_results(results, domain):
    """Print Shodan domain DNS results."""
    if results:
        print(f"\n  {BOLD}Shodan Domain Records{RESET}")
        print(f"    {GREEN}Found {len(results)} A record(s):{RESET}")
        for r in results:
            sub = r.get("subdomain", "")
            fqdn = f"{sub}.{domain}" if sub else domain
            seen = r.get("last_seen", "")
            seen_str = f"  {DIM}last seen: {seen}{RESET}" if seen else ""
            print(f"      {GREEN}{r['ip']:<16}{RESET}  {CYAN}{fqdn}{RESET}{seen_str}")
    else:
        print(f"  {DIM}No records found on Shodan for {domain}{RESET}")


def _print_shodan_query_results(results):
    """Print Shodan raw query results."""
    if results:
        print(f"\n  {BOLD}Shodan Search Results{RESET}")
        print(f"    {GREEN}Found {len(results)} host(s):{RESET}")
        for r in results:
            port_str = f":{r['port']}" if r.get("port") else ""
            org_str = f"  {DIM}{r['org']}{RESET}" if r.get("org") else ""
            hosts = ", ".join(r.get("hostnames", [])[:3])
            host_str = f"  {DIM}({hosts}){RESET}" if hosts else ""
            product = r.get("product", "")
            prod_str = f"  {CYAN}{product}{RESET}" if product else ""
            print(f"      {GREEN}{r['ip']}{port_str}{RESET}{org_str}{prod_str}{host_str}")
    else:
        print(f"  {DIM}No results found on Shodan{RESET}")


def _run_api_status():
    """Show which API keys are configured."""
    from .modules import api_keys

    print(f"\n{BOLD}API Key Status{RESET}")
    print("=" * 55)

    key_status = api_keys.status()
    labels = {
        "shodan_api_key": "Shodan",
        "censys_api_id": "Censys (ID)",
        "censys_api_secret": "Censys (Secret)",
        "fofa_email": "FOFA (Email)",
        "fofa_key": "FOFA (Key)",
        "zoomeye_key": "ZoomEye",
        "securitytrails_key": "SecurityTrails",
        "virustotal_api_key": "VirusTotal",
        "chinaz_api_key": "Chinaz",
        "passivetotal_username": "PassiveTotal (User)",
        "passivetotal_key": "PassiveTotal (Key)",
        "whoxy_api_key": "Whoxy",
        "dnstrails_api_key": "DNSTrails",
    }
    for key_name, configured in key_status.items():
        label = labels.get(key_name, key_name)
        icon = f"{GREEN}✓{RESET}" if configured else f"{RED}✗{RESET}"
        print(f"  {icon} {label:<25}")

    print(f"\n  Config file: {CYAN}{api_keys.config_path()}{RESET}")
    print(f"  {DIM}Env vars always override config file.{RESET}")
    print(f"  {DIM}Run {CYAN}wtw --api-init{RESET}{DIM} to create template config.{RESET}")
    print()


def _run_api_init():
    """Create template API key config file."""
    from .modules import api_keys

    path = api_keys.init_config()
    if path:
        print(f"{GREEN}[+] Created template config: {path}{RESET}")
        print(f"  {DIM}Edit this file and add your API keys.{RESET}")
        print(f"  {DIM}File permissions set to 600 (owner-only).{RESET}")
    else:
        existing = api_keys.config_path()
        print(f"{YELLOW}[!] Config file already exists: {existing}{RESET}")
        print(f"  {DIM}Edit it directly to update your keys.{RESET}")
    print()


def _run_waf_scan(targets, args):
    """Run deep WAF vulnerability scanner."""
    from .modules.waf_vuln_scanner import WAFVulnScanner

    is_json = args.json
    layers = None
    if args.waf_scan_layers:
        layers = [l.strip() for l in args.waf_scan_layers.split(",")]

    all_reports = []
    for target in targets:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        print(f"{CYAN}[*] WAF vulnerability scan: {domain}{RESET}", file=sys.stderr)

        scanner = WAFVulnScanner(domain, timeout=args.timeout, proxy=args.proxy, user_agent=args.user_agent)

        if layers:
            report = {}
            for layer in layers:
                print(f"  {DIM}[*] Scanning layer: {layer}{RESET}", file=sys.stderr)
                report[layer] = scanner.scan_layer(layer)
        else:
            report = scanner.scan_all()

        all_reports.append({"target": domain, "report": report})

        if not is_json:
            _print_waf_scan_report(domain, report)

    if is_json:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)


def _print_waf_scan_report(domain, report):
    """Print WAF vulnerability scan results."""
    W = max(len(domain) + 20, 60)
    print(f"\n{BOLD}{RED}{'=' * W}{RESET}")
    print(f"{BOLD}{RED}  WAF Vulnerability Scan: {domain}{RESET}")
    print(f"{BOLD}{RED}{'=' * W}{RESET}")

    findings = report.get("findings", [])
    if not findings:
        print(f"\n  {GREEN}No vulnerabilities found.{RESET}")

    # Group by severity
    for severity in ["critical", "high", "medium", "low", "info"]:
        sev_findings = [f for f in findings if f.get("severity") == severity]
        if not sev_findings:
            continue
        color = RED if severity in ("critical", "high") else YELLOW if severity == "medium" else DIM
        print(f"\n  {BOLD}{color}── {severity.upper()} ({len(sev_findings)}) ──{RESET}")
        for f in sev_findings:
            print(f"    {color}[{f.get('layer', '?')}]{RESET} {f.get('title', '?')}")
            if f.get("description"):
                print(f"      {DIM}{f['description'][:100]}{RESET}")
            conf = f.get("confidence", 0)
            verified = f"{GREEN}verified{RESET}" if f.get("verified") else f"{YELLOW}unverified{RESET}"
            print(f"      Confidence: {conf:.0%} | {verified}")

    # Summary
    layer_results = report.get("layers", {})
    if layer_results:
        print(f"\n  {BOLD}── Layer Summary ──{RESET}")
        for layer_name, layer_data in layer_results.items():
            count = len(layer_data.get("findings", []))
            icon = f"{RED}!" if count > 0 else f"{GREEN}✓"
            print(f"    {icon}{RESET} {layer_name:<15} {count} finding(s)")

    print()


def _run_cf_inject(targets, args):
    """Test Cloudflare header injection bypass."""
    from .modules.cf_header_inject import test_cf_header_trust

    for target in targets:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        print(f"{CYAN}[*] Testing CF header injection: {domain}{RESET}", file=sys.stderr)
        result = test_cf_header_trust(domain, timeout=args.timeout, proxy=args.proxy)

        print(f"\n{BOLD}{CYAN}  CF Header Injection Test: {domain}{RESET}")

        baseline = result.get("baseline", {})
        if baseline:
            print(f"    Baseline: [{baseline.get('status_code', '?')}] hash={baseline.get('body_hash', '?')}")

        for name, test in result.get("individual_results", {}).items():
            if test.get("different"):
                print(f"    {RED}! {name}: status changed to [{test.get('status_code', '?')}]{RESET}")
            else:
                print(f"    {DIM}  {name}: no change{RESET}")

        combined = result.get("combined_result", {})
        if combined.get("different"):
            print(f"    {RED}! ALL CF headers: status [{combined.get('status_code', '?')}] — WAF trusts CF headers!{RESET}")

        findings = result.get("findings", [])
        if findings:
            print(f"\n    {BOLD}Findings:{RESET}")
            for f in findings:
                print(f"      {RED}! {f}{RESET}")
        else:
            print(f"\n    {GREEN}WAF does not appear to trust injected CF headers.{RESET}")
        print()


def _run_proton_check():
    """Check ProtonVPN status and connectivity."""
    from .modules.proxy_manager import proton_status

    print(f"\n{BOLD}ProtonVPN Status Check{RESET}")
    print("-" * 50)

    status = proton_status()

    # Direct IP
    if status.get("direct_ip"):
        print(f"  Your IP (direct):  {CYAN}{status['direct_ip']}{RESET}")

    # CLI
    if status["cli_installed"]:
        print(f"  CLI installed:     {GREEN}Yes{RESET} ({status.get('cli_name', '?')})")
        if status.get("cli_version"):
            print(f"  CLI version:       {status['cli_version']}")
    else:
        print(f"  CLI installed:     {RED}No{RESET}")
        print(f"  {DIM}Install: pip install protonvpn-cli{RESET}")

    # Login
    if status["logged_in"]:
        print(f"  Logged in:         {GREEN}Yes{RESET}")
    else:
        print(f"  Logged in:         {RED}No{RESET}")
        if status["cli_installed"]:
            print(f"  {DIM}Login: {status.get('cli_name', 'protonvpn-cli')} login{RESET}")

    # Connection
    if status["connected"]:
        print(f"  Connected:         {GREEN}Yes{RESET}")
        if status.get("current_server"):
            print(f"  Server:            {CYAN}{status['current_server']}{RESET}")
    else:
        print(f"  Connected:         {RED}No{RESET}")
        if status["cli_installed"] and status["logged_in"]:
            print(f"  {DIM}Connect: {status.get('cli_name', 'protonvpn-cli')} connect --fastest{RESET}")

    # SOCKS proxy
    if status["socks_available"]:
        print(f"  SOCKS proxy:       {GREEN}Active (127.0.0.1:1080){RESET}")
        print(f"  Exit IP:           {CYAN}{status['exit_ip']}{RESET}")
        if status.get("country"):
            loc = status["country"]
            if status.get("city"):
                loc = f"{status['city']}, {loc}"
            print(f"  Location:          {loc}")
        if status.get("isp"):
            print(f"  ISP:               {status['isp']}")

        # Show if IP is different from direct
        if status.get("direct_ip") and status["exit_ip"] != status["direct_ip"]:
            print(f"\n  {GREEN}[+] IP successfully changed: {status['direct_ip']} -> {status['exit_ip']}{RESET}")
        elif status.get("direct_ip"):
            print(f"\n  {YELLOW}[!] Exit IP same as direct IP — VPN may not be routing all traffic{RESET}")
    else:
        print(f"  SOCKS proxy:       {RED}Not available (127.0.0.1:1080){RESET}")
        print(f"  {DIM}Ensure ProtonVPN is connected with SOCKS enabled{RESET}")

    # Rotation
    if status["can_rotate"]:
        print(f"\n  {GREEN}[+] IP rotation available{RESET} — use --proton-rotate to change IP")
    else:
        print(f"\n  {RED}[-] IP rotation not available{RESET}")
        if not status["cli_installed"]:
            print(f"  {DIM}Need ProtonVPN CLI for rotation{RESET}")

    print()


def _run_proton_rotate():
    """Rotate ProtonVPN IP."""
    from .modules.proxy_manager import rotate_proton_ip, test_proton_connectivity

    print(f"\n{BOLD}Rotating ProtonVPN IP...{RESET}")

    result = rotate_proton_ip()

    if result["success"]:
        print(f"  Old IP: {YELLOW}{result['old_ip']}{RESET}")
        print(f"  New IP: {GREEN}{result['new_ip']}{RESET}")
        if result.get("new_country"):
            print(f"  Country: {result['new_country']}")
        if result.get("warning"):
            print(f"  {YELLOW}[!] {result['warning']}{RESET}")
        else:
            print(f"\n  {GREEN}[+] IP rotated successfully{RESET}")
    else:
        print(f"  {RED}[!] Rotation failed: {result.get('error', 'unknown')}{RESET}")
        if result.get("detail"):
            print(f"  {DIM}{result['detail']}{RESET}")

    print()


def _collect_targets(args):
    targets = []
    if args.stdin or not sys.stdin.isatty():
        if args.stdin or (not args.targets and not args.list):
            for line in sys.stdin:
                t = line.strip()
                if t: targets.append(t)
    if args.list:
        try:
            with open(args.list) as f:
                for line in f:
                    t = line.strip()
                    if t and not t.startswith("#"): targets.append(t)
        except FileNotFoundError:
            print(f"{RED}[!] File not found: {args.list}{RESET}", file=sys.stderr); sys.exit(1)
    for t in (args.targets or []):
        if t.startswith("@"):
            try:
                with open(t[1:]) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"): targets.append(line)
            except FileNotFoundError:
                print(f"{RED}[!] File not found: {t[1:]}{RESET}", file=sys.stderr); sys.exit(1)
        else:
            targets.append(t)
    return targets


def _run_origins(targets, args):
    rows = origins_scan(targets)
    if args.json:
        _write_output(json.dumps(rows, indent=2), args.output); return
    print(f"\n{BLUE}{'Subdomain':<35} {'IP':<16} {'Provider':<45} {'Type'}{RESET}")
    print("-" * 110)
    for row in rows:
        cls = row["classification"]
        color = RED if cls == "CDN" else GREEN if cls == "ORIGIN?" else YELLOW
        parts = [row.get("bgp_prefix", ""), row.get("country", "??"), row.get("provider", "unknown")]
        parts = [p for p in parts if p]
        print(f"{YELLOW}{row['domain']:<35}{RESET} {row['ip']:<16}{color}{' | '.join(parts)} {cls}{RESET}")
    print()
    if args.output: _write_output(json.dumps(rows, indent=2), args.output)


def _run_direct_ip(targets, args):
    """Run direct IP bypass PoC."""
    from .modules import dns_resolver, asn_lookup, origin_finder

    is_json = args.json
    status_cb = _make_status_callback(quiet=is_json)
    reports = []
    path = args.path if args.path.startswith("/") else f"/{args.path}"

    for target in targets:
        domain = dns_resolver._clean_domain(target)

        if args.direct_ip == "auto":
            # Auto-discover origin IPs and test each
            print(f"{CYAN}[*] Auto-discovering origin IPs for {domain}...{RESET}", file=sys.stderr)

            # Resolve DNS A records
            dns_info = dns_resolver.resolve_domain(domain)
            a_records = dns_info.get("a_records", [])
            asn_records = []
            cdn_ips = set()
            if a_records:
                asn_records = asn_lookup.lookup_asn_bulk(a_records)
                cdn_ips = {r["ip"] for r in asn_records if r["classification"] == "CDN"}

            # Separate true CDN/WAF proxies from cloud hosting
            # True CDN/WAF (Cloudflare, Akamai, etc.) — IPs are proxy edges, not origins
            true_cdn_keywords = {
                "cloudflare", "akamai", "fastly", "cloudfront", "edgecast",
                "incapsula", "imperva", "sucuri", "ddos-guard", "qrator",
                "stackpath", "cdn77", "bunny", "gcore",
            }
            true_cdn_ips = set()
            hosting_ips = set()
            for r in asn_records:
                provider_lower = r.get("provider", "").lower()
                if any(kw in provider_lower for kw in true_cdn_keywords):
                    true_cdn_ips.add(r["ip"])
                else:
                    hosting_ips.add(r["ip"])

            # Collect unique IPs to test
            seen_ips = set()
            test_ips = []

            # Always include DNS A records that are hosting/cloud (AWS, Google, Azure, etc.)
            # These are likely direct origins, not proxy edges
            for r in asn_records:
                if r["ip"] not in seen_ips and r["ip"] not in true_cdn_ips:
                    seen_ips.add(r["ip"])
                    test_ips.append({"ip": r["ip"], "source": f"DNS A record ({r.get('provider', '?')})"})

            # Discover origin candidates via subdomains
            candidates = []
            if cdn_ips:
                status_cb("origins", "Subdomain origin leakage scan")
                sys.stderr.write("\r\033[K"); sys.stderr.flush()
                found = origin_finder.find_origins(domain, cdn_ips=cdn_ips)
                candidates.extend([c for c in found if not c.get("is_cdn")])

            for c in candidates:
                if c["ip"] not in seen_ips:
                    seen_ips.add(c["ip"])
                    test_ips.append({"ip": c["ip"], "source": c.get("source", "subdomain")})

            # Historical DNS (ViewDNS + SecurityTrails)
            status_cb("history", "Historical DNS lookup")
            sys.stderr.write("\r\033[K"); sys.stderr.flush()
            historical = origin_finder.fetch_historical_ips(domain)

            for h in historical:
                if h["ip"] not in seen_ips:
                    seen_ips.add(h["ip"])
                    src = h.get("source", "historical")
                    test_ips.append({"ip": h["ip"], "source": f"{src} ({h.get('last_seen', '?')})"})

            # Favicon hash matching (Shodan/FOFA/ZoomEye)
            status_cb("origins", "Favicon hash matching")
            sys.stderr.write("\r\033[K"); sys.stderr.flush()
            fav = origin_finder.fetch_favicon_hash(domain)
            if fav:
                fav_results = origin_finder.search_by_favicon_hash(fav["hash"], domain=domain)
                for r in fav_results:
                    if r["ip"] not in seen_ips:
                        seen_ips.add(r["ip"])
                        test_ips.append({"ip": r["ip"], "source": f"favicon:{r['source']}"})

            # Censys certificate search
            status_cb("origins", "Censys certificate search")
            sys.stderr.write("\r\033[K"); sys.stderr.flush()
            censys_results = origin_finder.search_censys(domain)
            for r in censys_results:
                if r["ip"] not in seen_ips:
                    seen_ips.add(r["ip"])
                    test_ips.append({"ip": r["ip"], "source": "censys"})

            # GitHub leak search
            status_cb("origins", "GitHub repository leak search")
            sys.stderr.write("\r\033[K"); sys.stderr.flush()
            github_results = origin_finder.search_github_leaks(domain)
            for r in github_results:
                if r["ip"] not in seen_ips:
                    seen_ips.add(r["ip"])
                    test_ips.append({"ip": r["ip"], "source": f"github ({r.get('repo', '?')})"})

            # Shodan DNS records — only keep IPs for the target subdomain, not unrelated services
            status_cb("origins", "Shodan domain search")
            sys.stderr.write("\r\033[K"); sys.stderr.flush()
            shodan_results = origin_finder.search_shodan_domain(domain)
            # Extract the subdomain prefix from target (e.g. "admin.pro.gms" from "admin.pro.gms.stratio.com")
            domain_parts = domain.split(".")
            base_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
            target_prefix = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""
            for r in shodan_results:
                if r["ip"] not in seen_ips:
                    sub = r.get("subdomain", "")
                    # Only include: exact target, no subdomain (apex), or same subdomain prefix
                    if not sub or sub == target_prefix or domain.startswith(sub + "."):
                        seen_ips.add(r["ip"])
                        test_ips.append({"ip": r["ip"], "source": f"shodan ({sub})" if sub else "shodan"})

            # VirusTotal resolutions
            status_cb("origins", "VirusTotal domain lookup")
            sys.stderr.write("\r\033[K"); sys.stderr.flush()
            vt_results = origin_finder.search_virustotal(domain)
            for r in vt_results:
                if r["ip"] not in seen_ips:
                    seen_ips.add(r["ip"])
                    test_ips.append({"ip": r["ip"], "source": "virustotal"})

            if not test_ips:
                print(f"{YELLOW}[!] No origin IP candidates found for {domain}{RESET}", file=sys.stderr)
                continue

            # ASN-classify all candidates and skip CDN/WAF edge IPs
            from .modules import asn_lookup as _asn
            all_candidate_ips = [t["ip"] for t in test_ips]
            asn_info = _asn.lookup_asn_bulk(all_candidate_ips) if all_candidate_ips else []
            asn_map = {r["ip"]: r for r in asn_info}

            cdn_waf_keywords = {
                "cloudflare", "akamai", "fastly", "cloudfront", "edgecast",
                "incapsula", "imperva", "sucuri", "ddos-guard", "qrator",
                "stackpath", "cdn77", "bunny", "gcore", "limelight",
                "stormwall", "radware", "barracuda", "f5 ", "fortinet",
                "datadome", "perimeterx", "reblaze", "wallarm",
                "azure front door", "aws shield", "google cloud armor",
                "netlify", "vercel",
            }

            kept = []
            skipped_cdn = []
            for t in test_ips:
                asn = asn_map.get(t["ip"], {})
                provider = asn.get("provider", "").lower()
                if any(kw in provider for kw in cdn_waf_keywords):
                    skipped_cdn.append(t)
                else:
                    kept.append(t)

            if skipped_cdn:
                print(f"{DIM}[*] Skipped {len(skipped_cdn)} CDN/WAF edge IP(s) (direct access = pointless):{RESET}", file=sys.stderr)
                for t in skipped_cdn[:5]:
                    asn = asn_map.get(t["ip"], {})
                    print(f"    {DIM}{t['ip']:<16} {asn.get('provider', '?')}{RESET}", file=sys.stderr)
                if len(skipped_cdn) > 5:
                    print(f"    {DIM}... and {len(skipped_cdn) - 5} more{RESET}", file=sys.stderr)

            if not kept:
                print(f"{YELLOW}[!] All {len(test_ips)} IPs are CDN/WAF edges — no origin candidates to test{RESET}", file=sys.stderr)
                continue

            print(f"{GREEN}[+] Testing {len(kept)} origin candidate IP(s) for {domain}:{RESET}", file=sys.stderr)
            for t in kept:
                asn = asn_map.get(t["ip"], {})
                asn_str = f"AS{asn.get('asn', '?')}" if asn.get("asn") else ""
                print(f"    {t['ip']:<16} via {t['source']:<35} {DIM}{asn_str}{RESET}", file=sys.stderr)
            print(file=sys.stderr)

            ips = [t["ip"] for t in kept]
        else:
            # Comma-separated IPs
            ips = [ip.strip() for ip in args.direct_ip.split(",") if ip.strip()]

        # Test each IP
        for ip in ips:
            print(f"{CYAN}[*] Testing {domain} → {ip} (path: {path}){RESET}", file=sys.stderr)
            try:
                report = direct_ip_scan(
                    target, ip, timeout=args.timeout,
                    user_agent=args.user_agent, on_status=status_cb,
                    path=path,
                )
                sys.stderr.write("\r\033[K"); sys.stderr.flush()
                reports.append(report)
                if not is_json:
                    _print_direct_ip_report(report)
            except Exception as e:
                sys.stderr.write("\r\033[K"); sys.stderr.flush()
                print(f"{RED}[!] Error: {target} → {ip}: {e}{RESET}", file=sys.stderr)
                reports.append({"target": target, "ip": ip, "error": str(e)})

    # Print summary table if multiple IPs tested
    if not is_json and len(reports) > 1:
        _print_direct_ip_summary(reports)

    if is_json:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)


def _print_direct_ip_summary(reports):
    """Print summary table when multiple IPs were tested."""
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Summary: {len(reports)} IP(s) tested{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    for r in reports:
        if r.get("error"):
            print(f"  {RED}✗{RESET} {r.get('ip', '?'):<16} Error: {r['error'][:40]}")
            continue
        ip = r.get("ip", "?")
        status = r.get("direct_https", {}).get("status", "?")
        match = r.get("hash_match", False)
        bypassed = r.get("bypass_confirmed", False)
        summary = r.get("summary", "")

        if bypassed and match:
            icon, color = "●", RED
        elif bypassed:
            icon, color = "◐", YELLOW
        elif r.get("default_vhost"):
            icon, color = "○", DIM
        else:
            icon, color = "○", GREEN

        label = summary.split("—")[0].strip() if "—" in summary else summary[:30]
        print(f"  {color}{icon}{RESET} {ip:<16} [{status}] {color}{label}{RESET}")
    print()


def _print_direct_ip_report(report):
    domain = report["target"]
    ip = report["ip"]
    path = report.get("path", "/")
    bypassed = report.get("bypass_confirmed", False)

    title = f"{domain} → {ip}"
    if path != "/":
        title += f" (path: {path})"
    W = max(len(title) + 6, 50)
    title_pad = W - len(title) - 4
    print(f"\n{BOLD}{CYAN}╔{'═' * W}╗{RESET}")
    print(f"{BOLD}{CYAN}║  {title}{' ' * max(title_pad, 1)}║{RESET}")
    print(f"{BOLD}{CYAN}╚{'═' * W}╝{RESET}")
    target_line = f"  Target: {BOLD}{domain}{RESET}  →  IP: {BOLD}{ip}{RESET}"
    if path != "/":
        target_line += f"  Path: {BOLD}{path}{RESET}"
    print(target_line)

    # Summary
    summary = report['summary']
    hash_match = report.get("hash_match", False)
    if bypassed and hash_match:
        print(f"\n  {BOLD}{RED}▶ {summary}{RESET}")
    elif bypassed and not hash_match:
        print(f"\n  {BOLD}{YELLOW}▶ {summary}{RESET}")
    elif report.get("default_vhost"):
        print(f"\n  {BOLD}{DIM}▶ {summary}{RESET}")
    else:
        print(f"\n  {BOLD}{GREEN}▶ {summary}{RESET}")

    # Hash comparison indicator
    cdn_hash = report.get("cdn_response", {}).get("body_hash")
    direct_hash_val = report.get("direct_https", {}).get("body_hash")
    if cdn_hash and direct_hash_val:
        if report.get("hash_match_fuzzy"):
            print(f"  {GREEN}≈ Fuzzy match: {cdn_hash} (CDN) ≈ {direct_hash_val} (direct){RESET}")
            print(f"    {DIM}{report.get('hash_match_note', '')}{RESET}")
        elif hash_match:
            print(f"  {GREEN}✓ Hash match: {cdn_hash} (CDN) == {direct_hash_val} (direct){RESET}")
        else:
            print(f"  {YELLOW}✗ Hash mismatch: {cdn_hash} (CDN) != {direct_hash_val} (direct){RESET}")

    # Redirect chain (shows exactly why each domain was pinned)
    chain = report.get("redirect_chain", [])
    pinned = report.get("pinned_domains", [])
    if chain and len(chain) > 1:
        _section("Redirect Chain (direct → IP)", CYAN)
        for i, step in enumerate(chain):
            status_code = step.get("status", "?")
            url = step.get("url", "?")
            if status_code in (301, 302, 303, 307, 308):
                _line(f"{DIM}[{status_code}]{RESET} {url}")
                if step.get("location"):
                    _line(f"     {YELLOW}→ {step['location']}{RESET}")
            else:
                _line(f"{GREEN}[{status_code}]{RESET} {url}")
    if len(pinned) > 1:
        _section("Pinned Domains (resolved → IP)", CYAN)
        for d in pinned:
            marker = f"{GREEN}●{RESET}" if d == domain else f"{YELLOW}→{RESET}"
            _line(f"{marker} {d}  →  {ip}")

    # DNS resolution info (only ASN records, no duplicate raw IPs)
    dns = report.get("dns_resolution", {})
    asn_list = dns.get("asn", [])
    if asn_list:
        _section("DNS Resolution (via CDN)", BLUE)
        for rec in asn_list:
            cls = rec.get("classification", "?")
            color = RED if cls == "CDN" else GREEN
            _line(f"{color}{rec['ip']:<16} AS{rec.get('asn', '?'):<8} {rec.get('provider', '?')} [{cls}]{RESET}")

    # Direct IP ASN
    dasn = report.get("direct_ip_asn", {})
    if dasn:
        cls = dasn.get("classification", "?")
        color = GREEN if cls != "CDN" else RED
        _section(f"Direct IP: {ip}", color)
        _line(f"{color}AS{dasn.get('asn', '?'):<8} {dasn.get('provider', '?')} [{cls}]{RESET}")

    # Comparison table
    cdn_resp = report.get("cdn_response", {})
    direct_https = report.get("direct_https", {})
    direct_http = report.get("direct_http", {})

    _section("Response Comparison", MAGENTA)
    _line(f"{'Method':<22} {'Status':<8} {'Server':<20} {'Hash':<18} {'Length'}")
    _line(f"{'─' * 22} {'─' * 8} {'─' * 20} {'─' * 18} {'─' * 8}")

    if cdn_resp and not cdn_resp.get("error"):
        _line(f"{YELLOW}☁ Via CDN (normal){RESET}     {cdn_resp.get('status', '?'):<8} {cdn_resp.get('server', '?'):<20} {cdn_resp.get('body_hash', '?'):<18} {cdn_resp.get('body_length', '?')}")
    elif cdn_resp.get("error"):
        _line(f"{RED}✗ Via CDN (normal)     Error: {cdn_resp['error'][:50]}{RESET}")

    if direct_https and not direct_https.get("error"):
        icon = f"{GREEN}●" if bypassed else f"{YELLOW}?"
        _line(f"{icon} Direct HTTPS → IP{RESET}   {direct_https.get('status', '?'):<8} {direct_https.get('server', '?'):<20} {direct_https.get('body_hash', '?'):<18} {direct_https.get('body_length', '?')}")
    elif direct_https.get("error"):
        _line(f"{RED}✗ Direct HTTPS → IP   {direct_https['error'][:50]}{RESET}")

    if direct_http and not direct_http.get("error"):
        _line(f"{'● Direct HTTP  → IP':<22} {direct_http.get('status', '?'):<8} {direct_http.get('server', '?'):<20} {direct_http.get('body_hash', '?'):<18} {direct_http.get('body_length', '?')}")
    elif direct_http and direct_http.get("error"):
        _line(f"{DIM}✗ Direct HTTP  → IP   {direct_http['error'][:50]}{RESET}")

    # WAF comparison
    waf_cdn = report.get("waf_via_cdn", [])
    waf_direct = report.get("waf_direct", [])
    cdn_names = {d["name"] for d in waf_cdn}
    direct_names = {d["name"] for d in waf_direct}

    if waf_cdn or waf_direct:
        _section("WAF Signatures", RED)
        all_names = cdn_names | direct_names
        for name in sorted(all_names):
            in_cdn = f"{YELLOW}✓{RESET}" if name in cdn_names else f"{DIM}✗{RESET}"
            in_direct = f"{RED}✓{RESET}" if name in direct_names else f"{GREEN}✗{RESET}"
            _line(f"{name:<25} CDN: {in_cdn}  Direct: {in_direct}")
        gone = cdn_names - direct_names
        if gone:
            print()
            _line(f"{GREEN}▶ Missing in direct: {', '.join(gone)}{RESET}")

    # Direct response details (title, headers, content-type)
    if direct_https and not direct_https.get("error"):
        import html as html_mod
        _section("Direct Response Details", CYAN)
        title = direct_https.get("title", "")
        if title:
            _line(f"Title:        {BOLD}{html_mod.unescape(title)}{RESET}")
        _line(f"Status:       {direct_https.get('status', '?')}")
        _line(f"Content-Type: {direct_https.get('content_type', '?')}")
        _line(f"Body Length:  {direct_https.get('body_length', '?')} bytes")
        _line(f"Body Hash:    {direct_https.get('body_hash', '?')}")

        notable = direct_https.get("notable_headers", {})
        if notable:
            print()
            _line(f"{BOLD}Headers:{RESET}")
            for k, v in notable.items():
                _line(f"  {DIM}{k}:{RESET} {v}")

    # Body as readable text (only when bypass confirmed)
    if bypassed and direct_https and not direct_https.get("error") and direct_https.get("body"):
        import re as _re
        body_html = direct_https["body"]

        # Strip scripts and styles before html2text
        clean_html = _re.sub(r'<script[^>]*>.*?</script>', '', body_html, flags=_re.DOTALL | _re.IGNORECASE)
        clean_html = _re.sub(r'<style[^>]*>.*?</style>', '', clean_html, flags=_re.DOTALL | _re.IGNORECASE)
        clean_html = _re.sub(r'<noscript[^>]*>.*?</noscript>', '', clean_html, flags=_re.DOTALL | _re.IGNORECASE)

        text = ""
        try:
            import html2text
            h = html2text.HTML2Text()
            h.ignore_links = True
            h.ignore_images = True
            h.ignore_emphasis = True
            h.body_width = 100
            text = h.handle(clean_html).strip()
        except ImportError:
            pass

        # If html2text produced nothing (JS-rendered page), extract text manually
        if not text:
            # Extract visible text from tags
            raw_text = _re.sub(r'<[^>]+>', ' ', clean_html)
            raw_text = _re.sub(r'\s+', ' ', raw_text).strip()
            import html as html_mod2
            text = html_mod2.unescape(raw_text)

        if text:
            lines = [l for l in text.split("\n") if l.strip()]
            _section("Direct Response Body (text)", GREEN)
            for ln in lines[:60]:
                _line(f"{DIM}{ln}{RESET}")
            if len(lines) > 60:
                _line(f"{DIM}... ({len(lines) - 60} more lines){RESET}")

    # PoC curl command
    pinned = report.get("pinned_domains", [domain])
    _section("Reproduce", BOLD)
    if len(pinned) <= 1:
        _line(f"{CYAN}curl -sk -H 'Host: {domain}' https://{ip}{path}{RESET}")
        _line(f"{CYAN}curl -skL --resolve {domain}:443:{ip} https://{domain}{path}{RESET}")
    else:
        resolve_args = " ".join(f"--resolve {d}:443:{ip}" for d in pinned)
        _line(f"{CYAN}curl -skL {resolve_args} https://{domain}{path}{RESET}")
    print()


def _make_status_callback(quiet=False):
    if quiet: return None
    icons = {"dns": "~", "asn": "$", "http": ">", "waf": "!", "errors": "E",
             "tls": "T", "evasion": "X", "proxy": "P", "cert": "@",
             "origins": "*", "history": "<", "bypass": "%"}
    def _status(phase, detail):
        icon = icons.get(phase, "*")
        sys.stderr.write(f"\r\033[K{DIM}  [{icon}] {detail}{RESET}")
        sys.stderr.flush()
    return _status


def _run_full(targets, args):
    reports = []
    is_json = args.json
    status_cb = _make_status_callback(quiet=is_json)

    only_modules = None
    if args.only:
        only_modules = set(m.strip().lower() for m in args.only.split(","))

    scan_kwargs = dict(
        timeout=args.timeout, scan_subs=not args.no_subs,
        check_cert=not args.no_cert, check_history=args.history,
        user_agent=args.user_agent, proxy=args.proxy, delay=args.delay,
        on_status=status_cb, check_tls=not args.no_tls,
        check_evasion=args.evasion, proxy_chain=args.proxy_chain,
        use_proton=args.proton, only_modules=only_modules,
    )

    if args.workers > 1 and len(targets) > 1:
        scan_kwargs["on_status"] = None
        reports = full_scan_batch(targets, max_workers=args.workers, **scan_kwargs)
        if not is_json:
            for r in reports:
                if "error" in r and "target" in r:
                    print(f"{RED}[!] Error: {r['target']}: {r['error']}{RESET}", file=sys.stderr)
                else: _print_report(r)
    else:
        for target in targets:
            print(f"{CYAN}[*] Scanning {target}...{RESET}", file=sys.stderr)
            try:
                report = full_scan(target, **scan_kwargs)
                sys.stderr.write("\r\033[K"); sys.stderr.flush()
                reports.append(report)
                if not is_json: _print_report(report)
            except Exception as e:
                sys.stderr.write("\r\033[K"); sys.stderr.flush()
                print(f"{RED}[!] Error: {target}: {e}{RESET}", file=sys.stderr)
                reports.append({"target": target, "error": str(e)})

    if is_json:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)


def _section(title, color):
    print(f"\n  {BOLD}{color}── {title} ──{RESET}")


def _line(text):
    print(f"    {text}")


def _print_report(report):
    target = report['target']
    W = max(len(target) + 16, 60)
    title_pad = W - len(target) - 14
    print(f"\n{BOLD}{CYAN}╔{'═' * W}╗{RESET}")
    print(f"{BOLD}{CYAN}║  WAF Recon: {target}{' ' * max(title_pad, 1)} ║{RESET}")
    print(f"{BOLD}{CYAN}╚{'═' * W}╝{RESET}")
    print(f"  {BOLD}Summary:{RESET} {report['summary']}")

    # HTTP
    http = report.get("http", {})
    if http and not http.get("error"):
        _section("HTTP Response", BLUE)
        _line(f"Status: {http.get('status', '?')}")
        if http.get("server"): _line(f"Server: {CYAN}{http['server']}{RESET}")
        if http.get("url"): _line(f"URL:    {http['url']}")
    elif http.get("error"):
        print(f"\n  {RED}✗ HTTP Error: {http['error']}{RESET}")

    # IPs + ASN
    if report.get("ips"):
        _section("IP Addresses", BLUE)
        for rec in report["ips"]:
            cls = rec["classification"]
            icon = "⚠" if cls == "CDN" else "●"
            color = RED if cls == "CDN" else GREEN
            asn_str = f"AS{rec['asn']}" if rec.get("asn") else "AS?"
            _line(f"{color}{icon}{RESET} {rec['ip']:<16} {color}{asn_str:<10} {rec.get('provider', 'unknown')} [{cls}]{RESET}")

    # CNAME
    if report.get("cnames"):
        _section("CNAME Chain", BLUE)
        for c in report["cnames"]:
            _line(f"→ {c}")

    # WAF/CDN
    if report.get("waf"):
        _section("WAF/CDN Detected", RED)
        for det in report["waf"]:
            cat = det["category"]
            color = RED if cat in ("WAF", "CDN/WAF") else YELLOW
            conf_pct = f"{det['confidence']:.0%}"
            _line(f"{color}{det['name']:<22}{RESET} {DIM}[{cat:<10}]{RESET} conf={BOLD}{conf_pct}{RESET}")
            if det.get("evidence"):
                _line(f"   {DIM}evidence: {', '.join(det['evidence'][:3])}{RESET}")

    # Error Pages
    ep = report.get("error_pages", {})
    ep_probes = ep.get("probes", [])
    if ep_probes:
        successful = [p for p in ep_probes if not p.get("error")]
        if successful:
            _section("Error Page Probes", YELLOW)
            for p in successful:
                st = p.get("status", "?")
                if st == 200: icon, color = "✓", GREEN
                elif st == 403: icon, color = "⊘", YELLOW
                elif isinstance(st, int) and st >= 500: icon, color = "✗", RED
                else: icon, color = "·", DIM
                waf_str = f"  {RED}← WAF: {', '.join(p['waf_hits'])}{RESET}" if p.get("waf_hits") else ""
                _line(f"{color}{icon} [{st}]{RESET} {p['path']:<40} {DIM}{p['description']}{RESET}{waf_str}")

    # TLS Fingerprint
    tls = report.get("tls_fingerprint", {})
    if tls and not tls.get("error"):
        _section("TLS Fingerprint", MAGENTA)
        _line(f"Version: {tls.get('our_tls_version', '?')}")
        _line(f"Cipher:  {tls.get('our_cipher', '?')}")
        _line(f"ALPN:    {tls.get('our_alpn', 'none')}")
        _line(f"Ciphers: {tls.get('our_ciphers_count', '?')} offered")
        for diff in tls.get("browser_differences", []):
            _line(f"{YELLOW}⚠ {diff}{RESET}")
        for rec in tls.get("recommendations", []):
            _line(f"{CYAN}→ {rec}{RESET}")
        configs = tls.get("config_tests", [])
        if configs:
            _line(f"{BOLD}Config Tests:{RESET}")
            for t in configs:
                status_str = f"{GREEN}accepted{RESET}" if t.get("accepted") else f"{RED}rejected{RESET}"
                if t.get("error"):
                    status_str = f"{DIM}{t['error']}{RESET}"
                sc = f" [{t.get('status_code', '?')}]" if t.get("status_code") else ""
                _line(f"  {t['config']:<25} {status_str}{sc}")

    # WAF Evasion
    evasion = report.get("waf_evasion", {})
    if evasion and not evasion.get("error"):
        if evasion.get("findings") or evasion.get("ua_sensitive"):
            _section("WAF Evasion Analysis", RED)
            if evasion.get("ua_tests"):
                _line(f"{BOLD}User-Agent Tests:{RESET}")
                for t in evasion["ua_tests"]:
                    if t.get("different"):
                        color = RED if t.get("status_code") in (403, 406, 429, 503) else YELLOW
                        _line(f"  {color}⚠ {t['ua_name']:<15} [{t.get('status_code', '?')}]{RESET} {DIM}{t['ua_string']}{RESET}")
            if evasion.get("encoding_tests"):
                changed = [t for t in evasion["encoding_tests"] if t.get("different")]
                if changed:
                    _line(f"{BOLD}Encoding Bypass:{RESET}")
                    for t in changed:
                        _line(f"  {YELLOW}⚠ {t['name']:<25}{RESET} {t['path']:<15} [{t.get('status_code', '?')}]")
            for finding in evasion.get("findings", []):
                _line(f"{RED}✗ {finding}{RESET}")
            for rec in evasion.get("evasion_recommendations", []):
                _line(f"{CYAN}→ {rec}{RESET}")

    # Proxy Effectiveness
    proxy_eff = report.get("proxy_effectiveness", {})
    if proxy_eff.get("proxy_results"):
        _section("Proxy Effectiveness", BLUE)
        bl = proxy_eff.get("baseline", {})
        if bl and not bl.get("error"):
            _line(f"Baseline: [{bl.get('status_code', '?')}] hash={bl.get('body_hash', '?')}")
        for pr in proxy_eff["proxy_results"]:
            icon = "✓" if pr.get("status_changed") else "·"
            color = GREEN if pr.get("status_changed") else DIM
            err = f" {RED}error: {pr['error']}{RESET}" if pr.get("error") else ""
            _line(f"{color}{icon} {pr['proxy']:<38} [{pr.get('status_code', '?')}] hash={pr.get('body_hash', '?')}{RESET}{err}")
        for f in proxy_eff.get("findings", []):
            _line(f"{YELLOW}⚠ {f}{RESET}")

    # SSL Cert
    if report.get("cert_info"):
        cert = report["cert_info"]
        _section("SSL Certificate", GREEN)
        _line(f"CN:     {cert.get('common_name', '?')}")
        _line(f"Issuer: {cert.get('issuer', '?')}")
        if cert.get("is_cdn_issued"):
            _line(f"{YELLOW}⚠ Certificate issued by CDN provider{RESET}")

    # Origin candidates
    if report.get("origin_candidates"):
        _section("Potential Origin IPs (subdomain leakage)", GREEN)
        for c in report["origin_candidates"]:
            asn_str = c["asn_info"].get("provider", "") if c.get("asn_info") else ""
            _line(f"{GREEN}●{RESET} {c['ip']:<16} via {c['source']:<30} {DIM}{asn_str}{RESET}")

    # WAF Bypass
    bypass = report.get("waf_bypass", {})
    if bypass.get("findings"):
        _section("WAF Bypass Testing", RED)
        bl = bypass.get("baseline", {})
        if bl and not bl.get("error"):
            _line(f"Baseline: [{bl.get('status_code', '?')}] hash={bl.get('body_hash', '?')}")
        for f in bypass["findings"]:
            sev = f.get("severity", "info")
            color = f"{BOLD}{RED}" if sev == "critical" else RED if sev == "high" else YELLOW
            _line(f"{color}[{sev.upper()}]{RESET} {f['detail']}")
            if f.get("curl"):
                _line(f"{BOLD}PoC:{RESET}")
                for ln in f["curl"].split("\n"):
                    _line(f"  {CYAN}{ln}{RESET}")
            if f.get("curl_resolve"):
                _line(f"{BOLD}PoC (--resolve):{RESET}")
                for ln in f["curl_resolve"].split("\n"):
                    _line(f"  {CYAN}{ln}{RESET}")
    elif bypass.get("ip_tests"):
        accessible = [t for t in bypass["ip_tests"] if t.get("accessible")]
        if not accessible:
            print(f"\n  {GREEN}✓ WAF Bypass: No direct IP access — origin protected{RESET}")

    # Historical
    if report.get("historical_ips"):
        _section("Historical DNS", DIM)
        for rec in report["historical_ips"][:10]:
            _line(f"{rec['ip']:<16} {rec['owner']:<30} last_seen={rec['last_seen']}")

    print()


def _write_output(content, filepath):
    if filepath:
        with open(filepath, "w") as f: f.write(content)
        print(f"{GREEN}[+] Results written to {filepath}{RESET}", file=sys.stderr)
    else:
        print(content)


if __name__ == "__main__":
    main()
