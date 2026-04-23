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
        description="WhatTheWAF - WAF/CDN Detection, Bypass, and TLS Fingerprint Evasion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  whatthewaf example.com
  whatthewaf example.com --only waf
  whatthewaf example.com --only ips,waf,errors
  whatthewaf example.com --direct-ip 1.2.3.4,5.6.7.8
  whatthewaf example.com --direct-ip auto
  whatthewaf example.com --direct-ip 1.2.3.4 --path /login
  whatthewaf example.com --evasion
  whatthewaf example.com --proton --evasion
  whatthewaf -l domains.txt -m origins
  whatthewaf example.com --proxy-chain socks5://proxy1:1080,http://proxy2:8080
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
    parser.add_argument("--no-banner", action="store_true")
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

    targets = _collect_targets(args)
    if not targets:
        parser.error("No targets specified.")

    if args.direct_ip:
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

    # TLS (always available via proxy mode)
    print(f"\n  {BOLD}TLS Fingerprint (JA3 evasion):{RESET}")
    print(f"    Status: {GREEN}Available via --proxy-mode{RESET}")

    print(f"\n{'=' * 60}")
    print(f"  {BOLD}Full stealth command:{RESET}")
    print(f"    {CYAN}whatthewaf --proxy-mode --proton --random-delay 2{RESET}")
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

            # Resolve DNS to find CDN IPs
            dns_info = dns_resolver.resolve_domain(domain)
            a_records = dns_info.get("a_records", [])
            cdn_ips = set()
            if a_records:
                asn_records = asn_lookup.lookup_asn_bulk(a_records)
                cdn_ips = {r["ip"] for r in asn_records if r["classification"] == "CDN"}

            # Discover origin candidates via subdomains
            candidates = []
            if cdn_ips:
                status_cb("origins", "Subdomain origin leakage scan")
                sys.stderr.write("\r\033[K"); sys.stderr.flush()
                found = origin_finder.find_origins(domain, cdn_ips=cdn_ips)
                candidates.extend([c for c in found if not c.get("is_cdn")])

            # Historical DNS
            status_cb("history", "Historical DNS lookup")
            sys.stderr.write("\r\033[K"); sys.stderr.flush()
            historical = origin_finder.fetch_historical_ips(domain)

            # Collect unique IPs
            seen_ips = set()
            test_ips = []
            for c in candidates:
                if c["ip"] not in seen_ips and c["ip"] not in cdn_ips:
                    seen_ips.add(c["ip"])
                    test_ips.append({"ip": c["ip"], "source": c.get("source", "subdomain")})
            for h in historical:
                if h["ip"] not in seen_ips and h["ip"] not in cdn_ips:
                    seen_ips.add(h["ip"])
                    test_ips.append({"ip": h["ip"], "source": f"historical ({h.get('last_seen', '?')})"})

            if not test_ips:
                print(f"{YELLOW}[!] No origin IP candidates found for {domain}{RESET}", file=sys.stderr)
                continue

            print(f"{GREEN}[+] Found {len(test_ips)} candidate IP(s) for {domain}:{RESET}", file=sys.stderr)
            for t in test_ips:
                print(f"    {t['ip']:<16} via {t['source']}", file=sys.stderr)
            print(file=sys.stderr)

            ips = [t["ip"] for t in test_ips]
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
        if hash_match:
            print(f"  {GREEN}✓ Hash match: {cdn_hash} (CDN) == {direct_hash_val} (direct){RESET}")
        else:
            print(f"  {YELLOW}✗ Hash mismatch: {cdn_hash} (CDN) != {direct_hash_val} (direct){RESET}")

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
    _section("Reproduce", BOLD)
    _line(f"{CYAN}curl -sk -H 'Host: {domain}' https://{ip}{path}{RESET}")
    _line(f"{CYAN}curl -sk --resolve {domain}:443:{ip} https://{domain}{path}{RESET}")
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
