"""WhatTheWAF CLI — WAF/CDN Detection, Bypass Testing, TLS Fingerprint Evasion."""

import argparse
import json
import re
import sys
import os
import warnings

warnings.filterwarnings("ignore", message="urllib3.*doesn't match a supported")
warnings.filterwarnings("ignore", message="The 'strict' parameter")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="urllib3")

from . import __version__
from .constants import CDN_WAF_KEYWORDS
from .scanner import origins_scan, full_scan, full_scan_batch, direct_ip_scan


def _extract_domain(target):
    """Extract clean domain from target (URL or domain string)."""
    return target.replace("https://", "").replace("http://", "").split("/")[0]


def _clear_status():
    """Clear the status line on stderr."""
    sys.stderr.write("\r\033[K")
    sys.stderr.flush()

RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"
CYAN = "\033[36m"; MAGENTA = "\033[35m"; WHITE = "\033[37m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"


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


_PROFILES_PATH = os.path.expanduser("~/.config/whatthewaf/profiles.conf")

# Profiles only define identity/stealth — not actions (no --trace, --waf-scan, --mitm, etc.)
_BOOL_FLAGS = {
    "proton", "tor", "tls_rotate", "h2_rotate", "auto_retry",
    "no_spoof_ua", "no_spoof_tls", "proxy_verbose",
}

_VALUE_FLAGS = {
    "header_profile", "proxy", "dot", "doh",
    "random_delay", "timeout", "delay",
    "user_agent", "source_port", "tcp_options",
}

# Flags that support multiple comma-separated values for rotation
_ROTATABLE_FLAGS = {"header_profile", "doh", "dot", "user_agent"}

# Store rotation options (populated by _apply_profile)
_rotation_pool = {}  # {flag_name: [value1, value2, ...]}


def _list_profiles():
    """List all available profiles with their settings."""
    import configparser

    if not os.path.isfile(_PROFILES_PATH):
        print(f"\n  {YELLOW}No profiles configured.{RESET}")
        print(f"  Create: {CYAN}{_PROFILES_PATH}{RESET}")
        return

    cp = configparser.ConfigParser()
    cp.read(_PROFILES_PATH)

    if not cp.sections():
        print(f"\n  {YELLOW}No profiles found in {_PROFILES_PATH}{RESET}")
        return

    print(f"\n{BOLD}Available Profiles{RESET}")
    print(f"  {DIM}{_PROFILES_PATH}{RESET}\n")

    for section in cp.sections():
        items = dict(cp.items(section))
        flags = []
        for k, v in items.items():
            k_flag = k.replace("_", "-")
            if v.lower() in ("true", "yes", "1", "on"):
                flags.append(f"--{k_flag}")
            else:
                flags.append(f"--{k_flag} {v}")
        print(f"  {GREEN}{BOLD}{section}{RESET}")
        print(f"    {DIM}{' '.join(flags)}{RESET}")
    print(f"\n  {BOLD}Available options for profiles:{RESET}")
    bool_list = ", ".join(f"--{f.replace('_', '-')}" for f in sorted(_BOOL_FLAGS))
    val_list = ", ".join(f"--{f.replace('_', '-')}" for f in sorted(_VALUE_FLAGS))
    print(f"    {DIM}On/off: {bool_list}{RESET}")
    print(f"    {DIM}Values: {val_list}{RESET}")
    dns_note = "DNS providers: cloudflare, google, quad9, adguard"
    hdr_note = "Header profiles: chrome, firefox, safari, edge"
    print(f"    {DIM}{dns_note}{RESET}")
    print(f"    {DIM}{hdr_note}{RESET}")
    print(f"\n  Usage: {CYAN}wtw example.com --profile <name>{RESET}\n")


def _apply_profile(args):
    """Load a profile from config file and apply as defaults (CLI flags override)."""
    import configparser

    profile_name = args.profile

    # Check if it's a file path or a profile name
    if os.path.isfile(profile_name):
        config_path = profile_name
        # Use the first section in the file
        cp = configparser.ConfigParser()
        cp.read(config_path)
        sections = cp.sections()
        if not sections:
            print(f"{RED}[!] No sections found in {config_path}{RESET}", file=sys.stderr)
            return
        section = sections[0]
    else:
        config_path = _PROFILES_PATH
        section = profile_name
        if not os.path.isfile(config_path):
            print(f"{RED}[!] Profile '{profile_name}' not found. Create: {config_path}{RESET}", file=sys.stderr)
            return

    cp = configparser.ConfigParser()
    cp.read(config_path)

    if not cp.has_section(section):
        available = ", ".join(cp.sections()) if cp.sections() else "none"
        print(f"{RED}[!] Profile '{section}' not found. Available: {available}{RESET}", file=sys.stderr)
        return

    if not args.quiet:
        print(f"  {DIM}[profile] Loaded '{section}' from {config_path}{RESET}", file=sys.stderr)

    for key, value in cp.items(section):
        attr = key.replace("-", "_")

        if attr in _BOOL_FLAGS:
            if not getattr(args, attr, False):
                setattr(args, attr, value.lower() in ("true", "yes", "1", "on"))
        elif attr in _VALUE_FLAGS:
            current = getattr(args, attr, None)
            defaults = {"timeout": 10, "delay": 0, "random_delay": 0}
            if current is None or (isinstance(current, (int, float)) and current == defaults.get(attr)):
                # Parse comma-separated values for rotatable flags
                values = [v.strip() for v in value.split(",") if v.strip()]
                if attr in _ROTATABLE_FLAGS and len(values) > 1:
                    _rotation_pool[attr] = values
                    # Set the first value as default
                    setattr(args, attr, values[0])
                elif attr in ("timeout",):
                    setattr(args, attr, int(values[0]))
                elif attr in ("random_delay", "delay"):
                    setattr(args, attr, float(values[0]))
                else:
                    setattr(args, attr, values[0])


def main():
    parser = argparse.ArgumentParser(
        description="WhatTheWAF - WAF/CDN Detection, Bypass, TLS Fingerprint Evasion & WAF Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  whatthewaf example.com
  whatthewaf example.com --waf
  whatthewaf example.com --waf --tls
  whatthewaf example.com --ip auto
  whatthewaf example.com --evasion
  whatthewaf example.com --waf-scan

  # individual OSINT tools
  whatthewaf example.com --favicon
  whatthewaf example.com --github-leaks
  whatthewaf example.com --censys --shodan --virustotal
  whatthewaf example.com --favicon --censys --shodan --github-leaks --securitytrails --virustotal

  # stealth
  whatthewaf example.com --tor --tls-rotate --source-port rotating
  whatthewaf --mitm --proton --listen-port 8888
  cat subs.txt | whatthewaf --stdin -m origins""",
    )
    parser.add_argument("targets", nargs="*", help="Domain(s), IP(s), or @file.txt")
    parser.add_argument("--profile", metavar="NAME",
                        help="Load settings from profile (name in ~/.config/whatthewaf/profiles.conf or path to file)")
    parser.add_argument("--stdin", action="store_true", help="Read targets from stdin")
    parser.add_argument("-l", "--list", metavar="FILE", help="Read targets from file")
    parser.add_argument("-m", "--mode", choices=["origins", "full"], default="full",
                        help="Scan mode (default: full)")
    parser.add_argument("--origins", action="store_true",
                        help="Quick DNS + ASN classification (which IPs are CDN vs origin)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-o", "--output", metavar="FILE")
    parser.add_argument("--waf", action="store_true", help="WAF/CDN detection + error page probing")
    parser.add_argument("--errors", action="store_true", help="Error page probing only")
    parser.add_argument("--bypass", action="store_true", help="WAF bypass testing with resolved IPs")
    parser.add_argument("--only", metavar="MODULES", help=argparse.SUPPRESS)
    parser.add_argument("--ip", metavar="IP",
                        help="IP(s) to test — single IP, comma-separated, CIDR range (1.2.3.0/24), or ('auto'/'history', WAF bypass mode only)")
    parser.add_argument("--path", metavar="PATH", default="/",
                        help="Path to test in --ip mode (default: /)")
    parser.add_argument("--subs", action="store_true", help="Enable subdomain leakage scan")
    parser.add_argument("--cert", action="store_true", help="Enable SSL certificate check")
    parser.add_argument("--history", action="store_true", help="Check historical DNS records")
    parser.add_argument("--evasion", action="store_true", help="Run WAF evasion analysis (UA, encoding, methods)")
    parser.add_argument("--trace", action="store_true", help="Trace infrastructure chain (CDN → proxy → origin) with full TLS audit")
    parser.add_argument("--tls", action="store_true", help="TLS/SSL audit: protocols, ciphers, certificate, vulnerabilities")
    parser.add_argument("--proxy-chain", metavar="PROXIES", help="Comma-separated proxy URLs to test")
    parser.add_argument("--proton", action="store_true", help="Use ProtonVPN SOCKS proxy (socks5://127.0.0.1:1080)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--proxy", metavar="URL", help="HTTP/SOCKS proxy for all requests")
    parser.add_argument("--user-agent", metavar="UA")
    parser.add_argument("--cookie", metavar="COOKIE", help="Cookie header value (e.g. 'session=abc; token=xyz')")
    parser.add_argument("--header", "-H", metavar="HEADER", action="append",
                        help="Extra header(s) in 'Name: Value' format (repeatable)")
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--proxy-mode", action="store_true",
                        help="(deprecated, use --mitm) Transparent tunnel proxy")
    parser.add_argument("--listen-port", type=int, default=8888,
                        help="Port for --mitm proxy (default: 8888)")
    parser.add_argument("--no-spoof-ua", action="store_true",
                        help="MITM proxy: don't replace User-Agent")
    parser.add_argument("--no-spoof-tls", action="store_true",
                        help="MITM proxy: don't modify TLS fingerprint")
    parser.add_argument("--proxy-verbose", action="store_true",
                        help="Proxy mode: log all requests")
    parser.add_argument("--random-delay", type=float, default=0,
                        help="Proxy mode: max random delay (secs) between requests to mimic human")
    parser.add_argument("--rotate", type=int, default=0, metavar="MINS",
                        help="MITM proxy: rotate profile options every N minutes (header profile, DNS, country)")
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
    parser.add_argument("--whoami", action="store_true",
                        help="Show your current fingerprint (IP, TLS, headers, geolocation)")
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
    parser.add_argument("--h3", action="store_true",
                        help="Probe target for HTTP/3 (QUIC) support and compare with HTTP/2")
    parser.add_argument("--proto-probe", action="store_true",
                        help="Test HTTP/1.1 vs HTTP/2 vs HTTP/3 and report WAF differences per protocol")
    parser.add_argument("--dot", nargs="?", const="cloudflare", default=None, metavar="PROVIDER",
                        help="Use DNS-over-TLS (providers: cloudflare, google, quad9, adguard)")
    parser.add_argument("--doh", nargs="?", const="cloudflare", default=None, metavar="PROVIDER",
                        help="Use DNS-over-HTTPS (providers: cloudflare, google, quad9, adguard)")
    parser.add_argument("--header-profile", metavar="BROWSER",
                        choices=["chrome", "firefox", "safari", "edge", "none"],
                        help="Use browser-accurate header ordering (chrome, firefox, safari, edge)")
    parser.add_argument("--tcp-options", metavar="PROFILE",
                        choices=["chrome", "firefox", "safari", "edge", "windows10", "linux", "random"],
                        help="Set TCP SYN options to match browser profile (requires scapy + root)")
    parser.add_argument("--waf-scan", action="store_true",
                        help="Run deep WAF vulnerability scanner (10 layers)")
    parser.add_argument("--waf-scan-layers", metavar="LAYERS",
                        help="Scan specific layers (comma-separated): network,ruleengine,ratelimit,evasion,behavioural,header,tls,method,session,misconfig")
    parser.add_argument("--no-persist", action="store_true",
                        help="Don't store waf-scan results in history database")
    parser.add_argument("--scan-history", action="store_true",
                        help="Show scan history and statistical analysis for target domain")
    parser.add_argument("--purge-history", action="store_true",
                        help="Delete all stored scan history for target domain")
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
    parser.add_argument("--headers", action="store_true",
                        help="Audit HTTP security headers (HSTS, CSP, X-Frame-Options, cookies, info leaks)")
    parser.add_argument("--vecino", action="store_true",
                        help="Reverse IP neighbours + hosting type classification (shared/VPS/SaaS). "
                             "Accepts IPs directly as targets, or via --ip (single, comma-separated, or CIDR)")
    parser.add_argument("--recon", action="store_true",
                        help="Run all OSINT sources, correlate results, and classify IPs")
    parser.add_argument("-v", "--version", action="version", version=f"WhatTheWAF {__version__}")

    args = parser.parse_args()

    # Load profile if specified (profile values are defaults, CLI flags override)
    if args.profile:
        if args.profile in ("?", "list", "help"):
            _list_profiles()
            return
        _apply_profile(args)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Activate encrypted DNS if requested
    if args.dot:
        from .modules.dns_encrypted import configure_dot
        configure_dot(args.dot)
        if not args.quiet and not args.no_banner:
            print(f"  {DIM}[dns] DNS-over-TLS via {args.dot}{RESET}", file=sys.stderr)
    elif args.doh:
        from .modules.dns_encrypted import configure_doh
        configure_doh(args.doh)
        if not args.quiet and not args.no_banner:
            print(f"  {DIM}[dns] DNS-over-HTTPS via {args.doh}{RESET}", file=sys.stderr)

    # Activate header order profile if requested
    if args.header_profile:
        from .modules.header_order import set_profile
        set_profile(args.header_profile)

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
    if args.whoami:
        _run_whoami(proxy=args.proxy)
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

    if args.headers:
        if not targets:
            parser.error("--headers requires at least one target.")
        _run_headers(targets, args)
        return

    if args.vecino:
        if args.ip and args.ip not in ("auto", "history"):
            targets = list(targets) + _expand_ip_targets(args.ip)
        if not targets:
            parser.error("--vecino requires at least one target (or --ip).")
        _run_vecino(targets, args)
        return

    if args.recon:
        if not targets:
            parser.error("--recon requires at least one target domain.")
        _run_recon(targets, args)
        return

    if not targets:
        parser.error("No targets specified.")

    if args.scan_history:
        _run_scan_history(targets, args)
        return
    if args.purge_history:
        _run_purge_history(targets, args)
        return

    # --tls alone = standalone TLS audit; --tls with other flags = modifier for full scan
    tls_standalone = args.tls and not (args.subs or args.cert or args.history or
                                        args.evasion or args.trace or args.ip or
                                        args.waf_scan)
    if tls_standalone:
        _run_tls_audit(targets, args)
    elif args.proto_probe:
        _run_proto_probe(targets, args)
    elif args.h3:
        _run_h3_probe(targets, args)
    elif args.waf_scan:
        _run_waf_scan(targets, args)
    elif args.cf_inject:
        _run_cf_inject(targets, args)
    elif args.ip and not args.trace:
        _run_direct_ip(targets, args)
    elif args.mode == "origins" or args.origins:
        _run_origins(targets, args)
    elif args.trace:
        _run_trace(targets, args)
    else:
        _run_full(targets, args)


def _http_get(url, proxy=None, timeout=10):
    """HTTP GET that works through HTTP CONNECT proxies (uses curl when proxy set)."""
    import httpx
    import subprocess
    import json as _json

    if proxy:
        # Python HTTP libs have issues with HTTP proxies for HTTPS (SSL to proxy instead of CONNECT)
        # curl handles this correctly, so we use it when a proxy is set
        try:
            cmd = ["curl", "-s", "-x", proxy, "-k", "--connect-timeout", "5",
                   "--max-time", str(timeout), url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            if result.returncode == 0 and result.stdout.strip():
                class CurlResponse:
                    status_code = 200
                    text = result.stdout
                    def json(self):
                        return _json.loads(self.text)
                return CurlResponse()
            elif result.stderr:
                raise Exception(result.stderr.strip()[:100])
            else:
                raise Exception(f"curl exit code {result.returncode}")
        except subprocess.TimeoutExpired:
            raise Exception("proxy timeout")
        except Exception:
            raise

    resp = httpx.get(url, timeout=timeout, verify=False)
    return resp


def _run_whoami(proxy=None):
    """Show your current fingerprint — what servers see when you connect."""
    import ssl
    import socket

    print(f"\n{BOLD}Your Fingerprint{RESET}")
    if proxy:
        print(f"  {DIM}(via proxy: {proxy}){RESET}")
    print("=" * 60)

    # 1. Public IP + geolocation via ipquery.io
    print(f"\n  {BOLD}Network{RESET}")
    ip = "?"
    isp = {}
    try:
        resp = _http_get("https://api.ipquery.io/?format=json", proxy=proxy)
        if resp and resp.status_code == 200:
            data = resp.json()
            ip = data.get("ip", "?")
            isp = data.get("isp", {})
            location = data.get("location", {})
            risk = data.get("risk", {})

            print(f"    IP:          {BOLD}{ip}{RESET}")
            if isp.get("org"):
                print(f"    ISP:         {isp.get('isp', '')} ({isp.get('org', '')})")
                _asn_display = str(isp.get('asn', '?'))
                if not _asn_display.startswith("AS"):
                    _asn_display = f"AS{_asn_display}"
                print(f"    ASN:         {_asn_display}")
            if location.get("country"):
                city = location.get("city", "")
                country = location.get("country", "")
                print(f"    Location:    {city}, {country}" if city else f"    Location:    {country}")
                if location.get("timezone"):
                    print(f"    Timezone:    {location['timezone']}")

            # BGP info via Team Cymru
            try:
                from .modules import asn_lookup
                asn_info = asn_lookup.lookup_asn_bulk([ip])
                if asn_info:
                    a = asn_info[0]
                    if a.get("bgp_prefix"):
                        print(f"    BGP Prefix:  {a['bgp_prefix']}")
                    if a.get("provider"):
                        print(f"    Provider:    {a['provider']}")
            except Exception:
                pass

            # Risk flags
            risk_flags = []
            if risk.get("is_vpn"): risk_flags.append("VPN")
            if risk.get("is_tor"): risk_flags.append("Tor")
            if risk.get("is_proxy"): risk_flags.append("Proxy")
            if risk.get("is_datacenter"): risk_flags.append("Datacenter")
            if risk_flags:
                print(f"    Detected as: {YELLOW}{', '.join(risk_flags)}{RESET}")
            else:
                print(f"    Detected as: {GREEN}Residential{RESET}")
    except Exception as e:
        print(f"    {RED}Could not determine IP: {e}{RESET}")

    # 2. BGP neighbours (upstreams/peers)
    print(f"\n  {BOLD}BGP Routing{RESET}")
    try:
        import urllib.request
        import ssl as _ssl
        _ctx = _ssl.create_default_context()
        _ctx.check_hostname = False
        _ctx.verify_mode = _ssl.CERT_NONE
        _asn_raw = isp.get("asn", "")
        _asn_num = str(_asn_raw).replace("AS", "").strip()
        if _asn_num:
            _url = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{_asn_num}&sourceapp=whatthewaf"
            _req = urllib.request.Request(_url, headers={"User-Agent": "Mozilla/5.0"})
            import json as _json
            _bgp_data = _json.loads(urllib.request.urlopen(_req, timeout=8, context=_ctx).read())
            _neighbours = _bgp_data.get("data", {}).get("neighbours", [])
            _upstreams = sorted([n for n in _neighbours if n.get("type") == "left"],
                                key=lambda x: -x.get("power", 0))
            if _upstreams:
                # Resolve names for top upstreams
                from .modules.infra_trace import _cymru_asn_name
                print(f"    You:         {BOLD}AS{_asn_num}{RESET} ({isp.get('org', isp.get('isp', ''))})")
                print(f"    Upstreams:")
                for u in _upstreams[:5]:
                    u_info = _cymru_asn_name(u["asn"])
                    u_name = u_info.get("provider", "").split(",")[0].strip()[:35]
                    u_country = u_info.get("country", "")
                    print(f"      → AS{u['asn']:<8} {u_name:<35} {u_country}")
            else:
                print(f"    AS{_asn_num}: no upstream data available")
    except Exception:
        print(f"    {DIM}Could not fetch BGP data{RESET}")

    # 3. TLS fingerprint (direct — not through proxy, to show your raw TLS)
    print(f"\n  {BOLD}TLS Fingerprint{RESET}")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection(("www.google.com", 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="www.google.com") as ssock:
                print(f"    TLS Version: {ssock.version()}")
                cipher = ssock.cipher()
                if cipher:
                    print(f"    Cipher:      {cipher[0]}")
                    print(f"    Bits:        {cipher[2]}")
                alpn = ssock.selected_alpn_protocol()
                print(f"    ALPN:        {alpn or f'{YELLOW}none (detectable){RESET}'}")
        ciphers_count = len(ctx.get_ciphers())
        if ciphers_count > 50:
            print(f"    Cipher list: {YELLOW}{ciphers_count} suites (browsers use ~15 — detectable){RESET}")
        else:
            print(f"    Cipher list: {GREEN}{ciphers_count} suites{RESET}")
    except Exception as e:
        print(f"    {RED}Error: {e}{RESET}")

    # 3. HTTP fingerprint (through proxy if set — shows what the target sees)
    print(f"\n  {BOLD}HTTP Fingerprint{RESET}")
    try:
        resp = _http_get("https://httpbin.org/headers", proxy=proxy)
        if resp and resp.status_code == 200:
            headers = resp.json().get("headers", {})
            ua = headers.get("User-Agent", "?")
            print(f"    User-Agent:  {DIM}{ua[:70]}{RESET}")
            accept = headers.get("Accept", "")
            if accept:
                print(f"    Accept:      {DIM}{accept[:60]}{RESET}")
            hdr_count = len(headers)
            print(f"    Headers:     {hdr_count} sent")
    except Exception:
        print(f"    {DIM}Could not reach httpbin.org{RESET}")

    # 4. TCP fingerprint
    try:
        from .modules import tcp_fingerprint
        tcp = tcp_fingerprint.get_status()
        print(f"\n  {BOLD}TCP Fingerprint{RESET}")
        print(f"    TTL:         {tcp['current_ttl']} → looks like: {YELLOW}{tcp['looks_like']}{RESET}")
    except Exception:
        pass

    print(f"\n{'=' * 60}")
    print()


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
    print(f"    {CYAN}whatthewaf --mitm --proton --random-delay 2 --listen-port 8888{RESET}")
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
    """Start MITM proxy with dynamic cert generation and optional rotation."""
    from .modules.mitm_proxy import MITMProxy
    import random
    import threading
    import time

    proxy = MITMProxy(
        listen_host="127.0.0.1",
        listen_port=args.listen_port,
        upstream_proxy=args.proxy,
        use_proton=args.proton,
        spoof_ua=not args.no_spoof_ua,
        spoof_tls=not args.no_spoof_tls,
        verbose=args.proxy_verbose,
    )

    # Rotation thread
    rotate_mins = args.rotate
    if rotate_mins > 0 and _rotation_pool:
        def _rotate_loop():
            while proxy.running:
                time.sleep(rotate_mins * 60)
                if not proxy.running:
                    break
                rotated = []
                for flag, values in _rotation_pool.items():
                    new_val = random.choice(values)
                    rotated.append(f"{flag.replace('_', '-')}={new_val}")

                    # Apply rotation
                    if flag == "header_profile":
                        try:
                            from .modules.header_order import set_profile
                            set_profile(new_val)
                        except Exception:
                            pass
                    elif flag == "doh":
                        try:
                            from .modules.dns_encrypted import configure_doh
                            configure_doh(new_val)
                        except Exception:
                            pass
                    elif flag == "dot":
                        try:
                            from .modules.dns_encrypted import configure_dot
                            configure_dot(new_val)
                        except Exception:
                            pass

                print(f"  {YELLOW}[rotate] {', '.join(rotated)}{RESET}", file=sys.stderr)

        pool_summary = {k: v for k, v in _rotation_pool.items()}
        print(f"  {CYAN}[rotate] Every {rotate_mins}m: {pool_summary}{RESET}", file=sys.stderr)
        t = threading.Thread(target=_rotate_loop, daemon=True)
        t.start()

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

        # 0. Resolve + platform detection (gates subsequent scans)
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [~] DNS resolution{RESET}"); sys.stderr.flush()
        dns_info = dns_resolver.resolve_domain(domain)
        a_records = dns_info.get("a_records", [])
        for ip in a_records:
            _add(ip, "dns")
        source_status["dns"] = len(a_records)

        # Platform detection — skip origin-hunting scans on SaaS/PaaS
        from .modules.intel import detect_platform
        _resp = None
        try:
            import httpx
            with httpx.Client(timeout=args.timeout, follow_redirects=True, verify=False) as _c:
                _resp = _c.get(f"https://{domain}")
            _server_hdr = _resp.headers.get("server", "")
        except Exception:
            _server_hdr = ""
        _platform = detect_platform(
            server_header=_server_hdr,
            cnames=dns_info.get("cnames", []),
        )
        if not is_json and _platform.get("platform_name"):
            _ht = _platform["hosting_type"]
            _label = {"saas": "provider-hosted SaaS", "paas": "PaaS", "managed": "managed hosting"}.get(_ht, "")
            if _label:
                print(f"  {DIM}Platform: {_platform['platform_name']} ({_label}){RESET}", file=sys.stderr)
                if not _platform["origin_discoverable"]:
                    print(f"  {YELLOW}Origin discovery skipped — {_platform['platform_name']} uses shared provider infrastructure{RESET}", file=sys.stderr)

        # Origin-hunting scans — skip on SaaS/PaaS (shared infra, no real origin to find)
        _origin_hunt = _platform.get("origin_discoverable", True)

        # 2. Subdomain leakage
        cdn_ips = set()
        if a_records:
            asn_records = asn_lookup.lookup_asn_bulk(a_records)
            cdn_ips = {r["ip"] for r in asn_records if r["classification"] == "CDN"}
        if _origin_hunt:
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [*] Subdomain leakage scan{RESET}"); sys.stderr.flush()
            subs = origin_finder.find_origins(domain, cdn_ips=cdn_ips, timeout=args.timeout)
            for c in subs:
                if not c.get("is_cdn"):
                    _add(c["ip"], f"subdomain:{c.get('subdomain', '?')}")
            source_status["subdomains"] = len([c for c in subs if not c.get("is_cdn")])
        else:
            source_status["subdomains"] = "skipped (SaaS)"

        # 3. Historical DNS (ViewDNS + SecurityTrails)
        if _origin_hunt:
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [<] Historical DNS{RESET}"); sys.stderr.flush()
            historical = origin_finder.fetch_historical_ips(domain, timeout=args.timeout)
            for h in historical:
                _add(h["ip"], f"history:{h.get('source', 'viewdns')}", last_seen=h.get("last_seen", ""))
            source_status["historical_dns"] = len(historical)
        else:
            source_status["historical_dns"] = "skipped (SaaS)"

        # 4. SSL certificate (always run — useful for platform classification)
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [@] SSL certificate inspection{RESET}"); sys.stderr.flush()
        cert_info = None
        if a_records:
            cert_info = origin_finder.check_ssl_cert(a_records[0], domain, timeout=args.timeout)

        # 5. Favicon hash
        if _origin_hunt:
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
        else:
            source_status["favicon"] = "skipped (SaaS)"

        # 6. GitHub leaks
        if _origin_hunt:
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [G] GitHub leak search{RESET}"); sys.stderr.flush()
            github = origin_finder.search_github_leaks(domain, timeout=args.timeout)
            for r in github:
                _add(r["ip"], "github", repo=r.get("repo", ""), context=r.get("context", "")[:100])
            source_status["github"] = len(github)
        else:
            source_status["github"] = "skipped (SaaS)"

        # 7. Censys (skip on SaaS — shared infra IPs are not actionable)
        if not _origin_hunt:
            source_status["censys"] = "skipped (SaaS)"
            source_status["shodan"] = "skipped (SaaS)"
            source_status["virustotal"] = "skipped (SaaS)"
            source_status["whoxy"] = "skipped (SaaS)"
            source_status["dnstrails"] = "skipped (SaaS)"
        elif api_keys.get("censys_api_id") and api_keys.get("censys_api_secret"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [C] Censys certificate search{RESET}"); sys.stderr.flush()
            censys = origin_finder.search_censys(domain, timeout=args.timeout)
            for r in censys:
                _add(r["ip"], "censys", org=r.get("autonomous_system", ""))
            source_status["censys"] = len(censys)
        else:
            source_status["censys"] = "no key"

        # 8. Shodan
        if _origin_hunt and api_keys.get("shodan_api_key"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [S] Shodan domain search{RESET}"); sys.stderr.flush()
            shodan = origin_finder.search_shodan_domain(domain, timeout=args.timeout)
            for r in shodan:
                sub = r.get("subdomain", "")
                _add(r["ip"], f"shodan" + (f":{sub}" if sub else ""), last_seen=r.get("last_seen", ""))
            source_status["shodan"] = len(shodan)
        elif _origin_hunt:
            source_status["shodan"] = "no key"

        # 9. VirusTotal
        if _origin_hunt and api_keys.get("virustotal_api_key"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [V] VirusTotal resolutions{RESET}"); sys.stderr.flush()
            vt = origin_finder.search_virustotal(domain, timeout=args.timeout)
            for r in vt:
                _add(r["ip"], "virustotal", last_seen=r.get("last_seen", ""))
            source_status["virustotal"] = len(vt)
        elif _origin_hunt:
            source_status["virustotal"] = "no key"

        # 10. Whoxy (WHOIS + reverse WHOIS → sibling domains → IPs)
        if _origin_hunt and api_keys.get("whoxy_api_key"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [W] Whoxy reverse WHOIS{RESET}"); sys.stderr.flush()
            whoxy = origin_finder.search_whoxy(domain, timeout=args.timeout)
            for r in whoxy.get("ips", []):
                _add(r["ip"], f"whoxy:{r.get('sibling_domain', '?')}")
            source_status["whoxy"] = len(whoxy.get("ips", []))
            if whoxy.get("sibling_domains"):
                source_status["whoxy_siblings"] = len(whoxy["sibling_domains"])
        elif _origin_hunt:
            source_status["whoxy"] = "no key"

        # 11. DNSTrails
        if _origin_hunt and api_keys.get("dnstrails_api_key"):
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [D] DNSTrails{RESET}"); sys.stderr.flush()
            dt = origin_finder.search_dnstrails(domain, timeout=args.timeout)
            for r in dt:
                label = r.get("subdomain", "") if r.get("type") == "subdomain" else "history"
                _add(r["ip"], f"dnstrails:{label}")
            source_status["dnstrails"] = len(dt)
        elif _origin_hunt:
            source_status["dnstrails"] = "no key"

        _clear_status()

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

        # === SSL CERT VALIDATION of non-CDN candidates ===
        # Connect to each candidate IP:443 and check if cert matches target domain
        candidates_to_verify = [
            ip for ip, intel in ip_intel.items()
            if intel.get("classification") != "CDN"
            or not any(k in intel.get("provider", "").lower() for k in CDN_WAF_KEYWORDS)
        ][:15]  # cap at 15 to avoid slowness

        if candidates_to_verify:
            if not is_json:
                sys.stderr.write(f"\r\033[K{DIM}  [🔒] SSL cert validation ({len(candidates_to_verify)} candidate IPs){RESET}")
                sys.stderr.flush()
            import concurrent.futures
            def _check_cert(ip):
                return ip, origin_finder.check_ssl_cert(ip, domain, timeout=min(args.timeout, 5))
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                for ip, cert in pool.map(lambda ip: _check_cert(ip), candidates_to_verify):
                    if cert:
                        cn = cert.get("common_name", "")
                        alt_names = cert.get("alt_names", [])
                        # Check if cert matches target domain (exact or wildcard)
                        all_names = [cn] + alt_names
                        matches = any(
                            n == domain or
                            (n.startswith("*.") and domain.endswith(n[1:]))
                            for n in all_names if n
                        )
                        if matches:
                            ip_intel[ip]["sources"].add("ssl-verified")
                            ip_intel[ip]["extra"]["cert_cn"] = cn
                            ip_intel[ip]["extra"]["cert_match"] = True
                            ip_intel[ip]["source_count"] = len(ip_intel[ip]["sources"])
            _clear_status()

        # Sort: most sources first, then non-CDN first, cert-verified first
        ranked = sorted(ip_intel.items(), key=lambda x: (
            -int(x[1].get("extra", {}).get("cert_match", False)),
            -x[1]["source_count"],
            x[1]["classification"] == "CDN",
            x[0],
        ))

        # === PERSIST recon IPs for cross-session analysis ===
        try:
            from .modules.scan_persistence import ScanPersistence
            db = ScanPersistence()
            for ip, intel in ip_intel.items():
                for source in intel["sources"]:
                    db.store_recon_ip(
                        domain=domain,
                        ip=ip,
                        source=source,
                        classification=intel.get("classification"),
                        provider=intel.get("provider"),
                    )
            db.close()
        except Exception:
            pass

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

                cert_tag = f" {GREEN}[SSL ✓]{RESET}" if intel.get("extra", {}).get("cert_match") else ""
                print(f"  {color}{ip:<17}{RESET} {asn_str:<10} {provider:<25} {color}{cls:<8}{RESET} {src_count:<5}{DIM}{sources_short}{RESET}{cert_tag}")

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
                print(f"    {CYAN}wtw {domain} --ip {ip_list}{RESET}")
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
            print(f"    {CYAN}wtw {domain} --ip {ip_list}{RESET}")
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
    for key_name, info in key_status.items():
        label = labels.get(key_name, key_name)
        configured = info["configured"]
        count = info["count"]
        failed = info["failed"]
        if configured:
            icon = f"{GREEN}✓{RESET}"
            count_str = f" {DIM}({count} key{'s' if count > 1 else ''}){RESET}" if count > 1 else ""
            fail_str = f" {RED}({failed} failed){RESET}" if failed else ""
            print(f"  {icon} {label:<25}{count_str}{fail_str}")
        else:
            icon = f"{RED}✗{RESET}"
            print(f"  {icon} {label:<25}")

    print(f"\n  Config file: {CYAN}{api_keys.config_path()}{RESET}")
    print(f"  {DIM}Multiple keys per service: shodan_api_key = key1, key2, key3{RESET}")
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


def _run_h3_probe(targets, args):
    """Probe HTTP/3 (QUIC) support and compare with HTTP/2."""
    from .modules.http3_probe import check_alt_svc, probe_h3, compare_h2_vs_h3
    from .modules import dns_resolver

    is_json = args.json
    all_reports = []

    for target in targets:
        domain = dns_resolver._clean_domain(target)
        print(f"{CYAN}[*] HTTP/3 probe: {domain}{RESET}", file=sys.stderr)

        report = compare_h2_vs_h3(domain, path=args.path if hasattr(args, 'path') else "/", timeout=args.timeout)
        all_reports.append(report)

        if not is_json:
            print(f"\n{BOLD}{CYAN}  HTTP/3 vs HTTP/2: {domain}{RESET}")
            print(f"  {'─' * 50}")

            h2 = report.get("h2", {})
            h3 = report.get("h3", {})

            if h2.get("status"):
                proto = h2.get("protocol", "?")
                print(f"  {BOLD}HTTP/2:{RESET}  [{h2['status']}] server={h2.get('server', '?')} hash={h2.get('body_hash', '?')} ({h2.get('time_ms', '?')}ms) [{proto}]")
            elif h2.get("error"):
                print(f"  {RED}HTTP/2:  error: {h2['error']}{RESET}")

            if h3.get("h3_supported"):
                print(f"  {GREEN}{BOLD}HTTP/3:{RESET}  [{h3.get('status_code', '?')}] server={h3.get('server_name', '?')} hash={h3.get('body_hash', '?')} ({h3.get('handshake_time_ms', '?')}ms) [QUIC]")
            elif h3.get("error"):
                print(f"  {YELLOW}HTTP/3:  not supported ({h3.get('error', '?')}){RESET}")
            else:
                print(f"  {YELLOW}HTTP/3:  not supported{RESET}")

            diffs = report.get("differences", [])
            if diffs:
                print(f"\n  {BOLD}Differences:{RESET}")
                for d in diffs:
                    color = RED if "BYPASS" in d else YELLOW
                    print(f"    {color}{d}{RESET}")

            if report.get("h3_bypass_potential"):
                print(f"\n  {RED}{BOLD}! HTTP/3 BYPASS POTENTIAL — WAF rules may not apply to QUIC traffic{RESET}")

            # Alt-Svc
            alt_svc = h2.get("alt_svc", "")
            if alt_svc:
                print(f"\n  {DIM}Alt-Svc: {alt_svc}{RESET}")
            print()

    if is_json:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)


def _run_proto_probe(targets, args):
    """Full protocol probe — test H1 vs H2 vs H3 and report WAF differences."""
    from .modules.proto_probe import probe_all_protocols
    from .modules import dns_resolver

    is_json = args.json
    all_reports = []

    for target in targets:
        domain = dns_resolver._clean_domain(target)
        print(f"{CYAN}[*] Protocol probe: {domain}{RESET}", file=sys.stderr)

        report = probe_all_protocols(domain, timeout=args.timeout, user_agent=args.user_agent or "")
        all_reports.append(report)

        if not is_json:
            print(f"\n{BOLD}{CYAN}  Protocol Probe: {domain}{RESET}")
            print(f"  {'─' * 60}")

            protos = report.get("protocols", {})
            for name, label in [("h1", "HTTP/1.1"), ("h2", "HTTP/2"), ("h3", "HTTP/3")]:
                p = protos.get(name, {})
                if p.get("supported"):
                    print(f"  {GREEN}✓{RESET} {label:<10} [{p.get('status', '?')}] server={p.get('server', '?'):<20} hash={p.get('body_hash', '?')} ({p.get('time_ms', '?')}ms)")
                elif p.get("error"):
                    print(f"  {RED}✗{RESET} {label:<10} {DIM}{p.get('error', 'unsupported')}{RESET}")
                else:
                    print(f"  {YELLOW}·{RESET} {label:<10} {DIM}not supported{RESET}")

            diffs = report.get("differences", [])
            if diffs:
                print(f"\n  {BOLD}Differences:{RESET}")
                for d in diffs:
                    color = RED if "BYPASS" in d else YELLOW
                    print(f"    {color}{d}{RESET}")

            recs = report.get("recommendations", [])
            if recs:
                print(f"\n  {BOLD}Recommendations:{RESET}")
                for r in recs:
                    print(f"    {CYAN}{r}{RESET}")

            timing = report.get("timing", {})
            if timing:
                fastest = report.get("fastest_protocol", "?")
                print(f"\n  {DIM}Timing: {timing} (fastest: {fastest}){RESET}")

            print()

    if is_json:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)


def _run_scan_history(targets, args):
    """Show scan history and statistical analysis for a domain."""
    from .modules.scan_persistence import ScanPersistence
    import datetime

    db = ScanPersistence()
    is_json = args.json

    all_results = []
    for target in targets:
        domain = _extract_domain(target)

        history = db.get_scan_history(domain)
        finding_stats = db.get_finding_stats(domain)
        ip_stats = db.get_ip_stats(domain)
        detections = db.get_detections(domain)

        result = {
            "domain": domain,
            "scan_history": history,
            "detections": detections,
            "finding_stats": [
                {
                    "title": s.title,
                    "category": s.category,
                    "layer": s.layer,
                    "severity": s.severity,
                    "times_seen": s.times_seen,
                    "total_scans": s.total_scans,
                    "hit_rate": round(s.hit_rate, 2),
                    "stability": s.stability,
                    "statistical_confidence": round(s.statistical_confidence, 3),
                    "fp_verified": s.fp_verified,
                    "first_seen": s.first_seen,
                    "last_seen": s.last_seen,
                }
                for s in finding_stats
            ],
            "ip_stats": [
                {
                    "ip": s.ip,
                    "sources": s.sources,
                    "times_seen": s.times_seen,
                    "confidence": round(s.confidence, 2),
                    "classification": s.classification,
                    "provider": s.provider,
                    "bypass_confirmed": s.bypass_confirmed,
                }
                for s in ip_stats
            ],
        }
        all_results.append(result)

        if not is_json:
            print(f"\n{BOLD}{CYAN}  Scan History: {domain}{RESET}")
            print(f"  {'─' * 50}")

            has_any = history or detections or ip_stats
            if not has_any:
                print(f"  {DIM}No history found for this domain.{RESET}")
                print(f"  Run: wtw {domain}")
                continue

            if history:
                print(f"\n  {BOLD}Scans ({len(history)}):{RESET}")
                for h in history[:10]:
                    ts = datetime.datetime.fromtimestamp(h["timestamp"]).strftime("%Y-%m-%d %H:%M")
                    meta = ""
                    if h.get("total_findings"):
                        meta = f"  {h['total_findings']} findings"
                    print(f"    {DIM}{ts}{RESET}  {h['scan_type']:<10}{meta}  ({h.get('duration_seconds', 0):.1f}s)")

            if detections:
                print(f"\n  {BOLD}WAF/CDN Detections ({len(detections)}):{RESET}")
                for d in detections:
                    ts = datetime.datetime.fromtimestamp(d["last_seen"]).strftime("%Y-%m-%d")
                    cat_color = RED if "WAF" in d["category"] else YELLOW
                    print(
                        f"    {cat_color}{d['name']:<22}{RESET} "
                        f"[{d['category']}]  "
                        f"conf: {d['confidence']:.0%}  "
                        f"seen {d['times_seen']}x  "
                        f"{DIM}last: {ts}{RESET}"
                    )
                    if d.get("evidence"):
                        print(f"      {DIM}{d['evidence'][:80]}{RESET}")

            if finding_stats:
                print(f"\n  {BOLD}WAF Scan Findings ({len(finding_stats)} unique):{RESET}")
                important = [s for s in finding_stats if s.severity in ("critical", "high", "medium")]
                for s in important[:20]:
                    stab_color = GREEN if s.stability == "stable" else YELLOW if s.stability == "intermittent" else RED if s.stability == "rare" else CYAN
                    sev_color = RED if s.severity in ("critical", "high") else YELLOW
                    fp_tag = f" {GREEN}[FP-clean]{RESET}" if s.fp_verified else ""
                    print(
                        f"    {sev_color}{s.severity:<8}{RESET} "
                        f"{stab_color}{s.stability:<12}{RESET} "
                        f"seen {s.times_seen}/{s.total_scans} "
                        f"(conf: {s.statistical_confidence:.0%}){fp_tag}"
                    )
                    print(f"      {DIM}{s.title[:70]}{RESET}")

            if ip_stats:
                print(f"\n  {BOLD}Known IPs ({len(ip_stats)} tracked):{RESET}")
                for s in ip_stats[:15]:
                    bypass_tag = f" {GREEN}[BYPASS]{RESET}" if s.bypass_confirmed else ""
                    cls_color = RED if s.classification == "CDN" else GREEN
                    cls_tag = f" {cls_color}[{s.classification}]{RESET}" if s.classification else ""
                    prov = f" {DIM}{s.provider}{RESET}" if s.provider else ""
                    print(
                        f"    {s.ip:<18} "
                        f"seen {s.times_seen}x  "
                        f"conf: {s.confidence:.0%}  "
                        f"sources: {','.join(s.sources)}"
                        f"{cls_tag}{prov}{bypass_tag}"
                    )

                # Suggest --ip history if there are non-CDN IPs
                non_cdn = [s for s in ip_stats if s.classification != "CDN"]
                if non_cdn:
                    print(f"\n  {DIM}Test stored IPs: wtw {domain} --ip history{RESET}")

            print()

    if is_json:
        _write_output(json.dumps(all_results, indent=2, default=str), args.output)

    db.close()


def _run_tls_audit(targets, args):
    """Standalone TLS/SSL audit — protocols, ciphers, cert, vulns."""
    from .modules import tls_fingerprint

    is_json = args.json
    status_cb = _make_status_callback(quiet=is_json)
    all_reports = []

    for target in targets:
        domain = _extract_domain(target)
        print(f"{CYAN}[*] TLS/SSL audit: {domain}{RESET}", file=sys.stderr)

        result = tls_fingerprint.analyze_tls_fingerprint(
            domain, timeout=args.timeout, on_status=status_cb)
        _clear_status()

        # Platform detection for context
        from .modules.intel import detect_platform
        from .modules import dns_resolver as _dns
        _dns_info = _dns.resolve_domain(domain)
        _platform = detect_platform(cnames=_dns_info.get("cnames", []))

        all_reports.append({"target": domain, "tls": result, "platform": _platform})

        if not is_json:
            _print_tls_report(domain, result, platform=_platform)

    if is_json:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)


def _print_tls_report(domain, tls, platform=None):
    """Print standalone TLS audit results."""
    W = max(len(domain) + 16, 60)
    print(f"\n{BOLD}{CYAN}╔{'═' * W}╗{RESET}")
    print(f"{BOLD}{CYAN}║  TLS Audit: {domain}{' ' * max(W - len(domain) - 14, 1)}║{RESET}")
    print(f"{BOLD}{CYAN}╚{'═' * W}╝{RESET}")

    if platform and not platform.get("server_controlled"):
        pname = platform.get("platform_name", "provider")
        print(f"  {YELLOW}TLS config is managed by {pname} — findings below are not customer-configurable{RESET}")

    if tls.get("error"):
        print(f"\n  {RED}Error: {tls['error']}{RESET}")
        return

    # Connection info
    _section("Connection", BLUE)
    _line(f"TLS Version:  {BOLD}{tls.get('our_tls_version', '?')}{RESET}")
    _line(f"Cipher:       {tls.get('our_cipher', '?')}")
    _line(f"ALPN:         {tls.get('our_alpn') or f'{YELLOW}none{RESET}'}")

    # Protocol support
    protocols = tls.get("protocols", {})
    if protocols:
        _section("Protocol Support", BLUE)
        for proto_name in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
            p = protocols.get(proto_name, {})
            if p.get("supported"):
                deprecated = proto_name in ("TLSv1.0", "TLSv1.1", "SSLv3")
                color = RED if deprecated else GREEN
                icon = "!" if deprecated else "+"
                cipher_info = f"  {DIM}{p.get('cipher', '')}{RESET}" if p.get("cipher") else ""
                _line(f"{color}[{icon}] {proto_name:<10}{RESET}{cipher_info}")
            elif proto_name in protocols:
                _line(f"{DIM}[-] {proto_name}{RESET}")

    # Certificate
    cert = tls.get("certificate", {})
    if cert and not cert.get("error"):
        _section("Certificate", BLUE)
        if cert.get("subject"):
            _line(f"Subject:     {BOLD}{cert['subject']}{RESET}")
        if cert.get("issuer"):
            org = f" ({cert['issuer_org']})" if cert.get("issuer_org") else ""
            _line(f"Issuer:      {cert['issuer']}{org}")
        if cert.get("key_type"):
            bits = f" {cert['key_bits']}" if cert.get("key_bits") else ""
            _line(f"Key:         {cert['key_type']}{bits} bits")
        if cert.get("sig_algorithm"):
            _line(f"Signature:   {cert['sig_algorithm']}")
        if cert.get("serial"):
            _line(f"Serial:      {DIM}{cert['serial']}{RESET}")
        if cert.get("days_remaining") is not None:
            days = cert["days_remaining"]
            if cert.get("expired"):
                _line(f"Validity:    {RED}EXPIRED ({abs(days)} days ago){RESET}")
            elif days < 30:
                _line(f"Validity:    {YELLOW}{days} days remaining{RESET}")
            else:
                _line(f"Validity:    {GREEN}{days} days remaining{RESET}")
        if cert.get("self_signed"):
            _line(f"             {RED}Self-signed certificate{RESET}")
        if cert.get("hsts"):
            max_age = cert.get("hsts_max_age", 0)
            color = GREEN if max_age >= 31536000 else YELLOW
            _line(f"HSTS:        {color}enabled (max-age={max_age}){RESET}")
        else:
            _line(f"HSTS:        {RED}not enabled{RESET}")
        if cert.get("san"):
            sans = cert["san"]
            _line(f"SANs ({len(sans)}):")
            for san in sans[:10]:
                _line(f"  {DIM}{san}{RESET}")
            if len(sans) > 10:
                _line(f"  {DIM}... +{len(sans) - 10} more{RESET}")

    # Ciphers
    ciphers = tls.get("ciphers", [])
    if ciphers:
        _section("Accepted Ciphers", BLUE)
        strength_colors = {"strong": GREEN, "acceptable": CYAN, "weak": YELLOW, "insecure": RED}
        # Group by strength
        for strength in ("strong", "acceptable", "weak", "insecure"):
            group = [c for c in ciphers if c["strength"] == strength]
            if group:
                color = strength_colors[strength]
                print(f"\n    {color}{BOLD}{strength.upper()} ({len(group)}){RESET}")
                for c in group:
                    pfs_tag = "" if c.get("pfs") else f" {YELLOW}[no PFS]{RESET}"
                    _line(f"  {color}{'●'}{RESET} {c['name']:<45} {DIM}{c.get('bits', '')}bit{RESET}{pfs_tag}")

    # Vulnerabilities
    vulns = tls.get("vulnerabilities", [])
    if vulns:
        _section("Vulnerabilities", RED)
        sev_colors = {"critical": RED, "high": RED, "medium": YELLOW, "low": CYAN, "info": DIM}
        for v in vulns:
            color = sev_colors.get(v["severity"], DIM)
            _line(f"{color}{v['severity']:<9}{RESET} {v['title']}")
            _line(f"          {DIM}{v['description']}{RESET}")
    else:
        _section("Vulnerabilities", GREEN)
        _line(f"{GREEN}No TLS vulnerabilities found{RESET}")

    # Fingerprint
    if tls.get("browser_differences"):
        _section("Fingerprint vs Browsers", MAGENTA)
        for diff in tls["browser_differences"]:
            _line(f"{YELLOW}{diff}{RESET}")
        for rec in tls.get("recommendations", []):
            _line(f"{GREEN}→ {rec}{RESET}")

    # WAF config tests
    config_tests = tls.get("config_tests", [])
    if config_tests:
        _section("WAF TLS Acceptance", BLUE)
        for t in config_tests:
            if t.get("error"):
                _line(f"{RED}✗ {t['config']:<25}{RESET} {DIM}{t['error']}{RESET}")
            elif t.get("accepted"):
                _line(f"{GREEN}✓ {t['config']:<25}{RESET} [{t.get('status_code', '?')}] {DIM}{t.get('tls_version', '')} {t.get('cipher', '')}{RESET}")
            else:
                _line(f"{YELLOW}✗ {t['config']:<25}{RESET} [{t.get('status_code', '?')}] {DIM}rejected{RESET}")

    print()


def _run_trace(targets, args):
    """Trace infrastructure chain — CDN, proxies, LBs, hosting, origin, frameworks.

    Combinable with --ip (traceroute to origin IPs) and --evasion.
    """
    from .modules import infra_trace, dns_resolver
    from .scanner import full_scan

    is_json = args.json
    status_cb = _make_status_callback(quiet=is_json)
    all_reports = []

    # Determine which modules to run
    modules = {"waf", "errors"}
    if args.evasion:
        modules.add("evasion")

    # Resolve --ip targets
    ip_mode = getattr(args, "ip", None)  # auto, history, or comma-separated IPs

    for target in targets:
        domain = _extract_domain(target)
        print(f"{CYAN}[*] Tracing infrastructure: {domain}{RESET}", file=sys.stderr)

        # Phase 1: full scan for signals
        report = full_scan(target, timeout=args.timeout, user_agent=args.user_agent,
                           proxy=args.proxy, on_status=status_cb,
                           only_modules=modules, check_evasion=args.evasion,
                           check_tls=False, scan_subs=False, check_cert=False)
        _clear_status()

        # Phase 2: build infra chain
        status_cb("trace", "Analyzing infrastructure chain")
        sys.stderr.flush()
        chain = infra_trace.trace_infra(report)
        report["infra_chain"] = chain
        _clear_status()

        # Phase 3: traceroute to domain (via CDN path)
        traceroute = infra_trace.run_traceroute(domain, on_status=status_cb)
        report["traceroute"] = traceroute
        _clear_status()

        # Phase 4: resolve direct IPs and traceroute to them
        direct_ips = _resolve_trace_ips(ip_mode, domain, report, status_cb)
        if direct_ips:
            report["traceroute_direct"] = {}
            for ip in direct_ips:
                status_cb("trace", f"Traceroute → {ip} (direct)")
                sys.stderr.flush()
                tr_direct = infra_trace.run_traceroute(ip, on_status=status_cb)
                report["traceroute_direct"][ip] = tr_direct
                _clear_status()

        # Phase 5-6: subdomain takeover + cache poisoning only with --waf-scan
        if getattr(args, "waf_scan", False):
            from .modules import subdomain_takeover
            extra_subs = []
            try:
                from .modules.scan_persistence import ScanPersistence
                db = ScanPersistence()
                ip_stats = db.get_ip_stats(domain)
                for s in ip_stats:
                    for src in s.sources:
                        if src.startswith("subdomain:") or src.startswith("shodan:"):
                            sub = src.split(":", 1)[1]
                            if sub:
                                extra_subs.append(sub)
                db.close()
            except Exception:
                pass

            status_cb("trace", "Subdomain takeover check (CNAME + NS)")
            sys.stderr.flush()
            takeover = subdomain_takeover.scan_takeover(
                domain, extra_subdomains=extra_subs,
                timeout=min(args.timeout, 5), on_status=status_cb)
            report["takeover"] = takeover
            _clear_status()

            from .modules.deep_scan import test_cache_poisoning
            http_url = report.get("http", {}).get("url", f"https://{domain}")
            status_cb("trace", "Cache poisoning tests")
            sys.stderr.flush()
            report["cache_poisoning"] = test_cache_poisoning(http_url, timeout=min(args.timeout, 5))
            _clear_status()

        all_reports.append({"target": domain, "report": report})

        if not is_json:
            _print_trace_report(domain, report)

    if is_json:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_reports, indent=2, default=str), args.output)


def _resolve_trace_ips(ip_mode, domain, report, status_cb):
    """Resolve IPs to traceroute based on --ip flag value."""
    if not ip_mode:
        return []

    if ip_mode == "history":
        from .modules.scan_persistence import ScanPersistence
        db = ScanPersistence()
        ip_stats = db.get_ip_stats(domain)
        db.close()
        # Skip CDN edges
        cdn_kw = CDN_WAF_KEYWORDS
        ips = [s.ip for s in ip_stats
               if not any(k in (s.provider or "").lower() for k in cdn_kw)]
        return ips[:5]

    if ip_mode == "auto":
        # Use origin candidates from the scan + subdomain leakage
        from .modules import origin_finder, asn_lookup
        status_cb("trace", "Discovering origin IPs for traceroute")
        cdn_ips = {r["ip"] for r in report.get("ips", []) if r.get("classification") == "CDN"}
        candidates = []
        if cdn_ips:
            found = origin_finder.find_origins(domain, cdn_ips=cdn_ips)
            candidates = [c["ip"] for c in found if not c.get("is_cdn")]
        # Also try historical DNS
        historical = origin_finder.fetch_historical_ips(domain)
        for h in historical:
            if h["ip"] not in candidates:
                candidates.append(h["ip"])
        # ASN-filter: skip CDN edges
        if candidates:
            asn_records = asn_lookup.lookup_asn_bulk(candidates[:10])
            cdn_kw = {"cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
                       "imperva", "sucuri", "ddos-guard"}
            candidates = [r["ip"] for r in asn_records
                          if not any(k in r.get("provider", "").lower() for k in cdn_kw)]
        return candidates[:5]

    # Explicit comma-separated IPs
    return _expand_ip_targets(ip_mode)


def _print_trace_report(domain, report):
    """Print infrastructure trace results."""
    W = max(len(domain) + 20, 60)
    print(f"\n{BOLD}{CYAN}╔{'═' * W}╗{RESET}")
    print(f"{BOLD}{CYAN}║  Infrastructure Trace: {domain}{' ' * max(W - len(domain) - 25, 1)}║{RESET}")
    print(f"{BOLD}{CYAN}╚{'═' * W}╝{RESET}")

    layer_colors = {
        "cdn": RED, "waf": RED, "cdn/waf": RED,
        "cache": YELLOW, "loadbalancer": YELLOW,
        "proxy": YELLOW, "hosting": CYAN,
        "server": GREEN, "runtime": GREEN,
        "framework": MAGENTA, "cms": MAGENTA,
        "app-waf": RED,
    }
    layer_labels = {
        "cdn": "CDN", "waf": "WAF", "cdn/waf": "CDN/WAF",
        "cache": "CACHE", "loadbalancer": "LB",
        "proxy": "PROXY", "hosting": "HOSTING",
        "server": "SERVER", "runtime": "RUNTIME",
        "framework": "FRAMEWORK", "cms": "CMS",
        "app-waf": "WAF",
    }

    # Traffic path chain
    chain = report.get("infra_chain", [])
    if chain:
        _section("Traffic Path", CYAN)
        chain_parts = []
        for node in chain:
            color = layer_colors.get(node["layer"], DIM)
            label = layer_labels.get(node["layer"], node["layer"].upper())
            chain_parts.append(f"{color}{BOLD}{node['name']}{RESET} {DIM}[{label}]{RESET}")
        _line(f"{'  →  '.join(chain_parts)}")

        # Details per node
        _section("Details", BLUE)
        for node in chain:
            color = layer_colors.get(node["layer"], DIM)
            label = layer_labels.get(node["layer"], node["layer"].upper())
            conf_pct = f"{node['confidence']:.0%}"
            _line(f"{color}{BOLD}{node['name']}{RESET} {DIM}[{label}]{RESET}  conf={BOLD}{conf_pct}{RESET}")
            for ev in node.get("evidence", [])[:4]:
                _line(f"   {DIM}{ev}{RESET}")
    else:
        _section("Traffic Path", CYAN)
        _line(f"{DIM}Could not determine infrastructure chain{RESET}")

    # IPs
    if report.get("ips"):
        _section("IP Addresses", BLUE)
        for rec in report["ips"]:
            cls = rec["classification"]
            icon = "⚠" if cls == "CDN" else "●"
            color = RED if cls == "CDN" else GREEN
            asn_str = f"AS{rec['asn']}" if rec.get("asn") else "AS?"
            _line(f"{color}{icon}{RESET} {rec['ip']:<16} {color}{asn_str:<10} {rec.get('provider', 'unknown')} [{cls}]{RESET}")

    # CNAME chain
    if report.get("cnames"):
        _section("CNAME Chain", BLUE)
        for c in report["cnames"]:
            _line(f"→ {c}")

    # Network traceroute
    tr = report.get("traceroute", {})
    _print_traceroute_hops(tr, f"Network Traceroute", BLUE)

    # BGP AS path — shows intermediate networks when hops are filtered
    as_path = tr.get("as_path", [])
    if as_path:
        _ROLE_STYLE_PATH = {
            "isp": WHITE, "transit": CYAN, "ixp": MAGENTA,
            "cdn": RED, "cloud": YELLOW, "hosting": GREEN,
        }
        _section("BGP AS Path (intermediate networks)", BLUE)
        # Arrow chain summary
        chain_parts = []
        for a in as_path:
            role = a.get("role", "isp")
            c = _ROLE_STYLE_PATH.get(role, WHITE)
            short = a["provider"].split(" - ")[0].split(",")[0].strip()[:20]
            chain_parts.append(f"{c}{BOLD}AS{a['asn']}{RESET} {short}")
        print(f"    {'  →  '.join(chain_parts)}")
        print()
        # Detail table
        for a in as_path:
            role = a.get("role", "isp")
            c = _ROLE_STYLE_PATH.get(role, WHITE)
            country = a.get("country", "")
            provider = a["provider"].split(",")[0].strip()[:40]
            _line(f"{c}AS{a['asn']:<8} {provider:<40} {country:<3} [{role}]{RESET}")

    # Diagnostic hints
    tr_hops = tr.get("hops", [])
    if tr_hops:
        total = len(tr_hops)
        filtered = sum(1 for h in tr_hops if h.get("ip") == "*")
        if total > 3 and filtered / total > 0.7:
            print(f"\n    {DIM}Filtered hops: routers with ICMP/UDP disabled (normal). BGP path above shows the networks.{RESET}")
    if tr.get("needs_root"):
        print(f"\n    {YELLOW}TCP traceroute needs root. Fix: sudo chmod u+s $(readlink -f $(which traceroute)){RESET}")

    # Direct IP traceroutes (--ip)
    for ip, tr_direct in report.get("traceroute_direct", {}).items():
        _print_traceroute_hops(tr_direct, f"Traceroute → {ip} (direct)", YELLOW)

    # Subdomain takeover
    takeover = report.get("takeover", [])
    if takeover:
        _section(f"Subdomain Takeover ({len(takeover)} found)", RED)
        for t in takeover:
            sev_color = RED if t["severity"] == "high" else YELLOW
            _line(f"{sev_color}{t['severity']:<6}{RESET} {BOLD}{t['subdomain']}{RESET}")
            _line(f"       CNAME → {t['cname']} ({t['service']})")
            _line(f"       {DIM}{t['reason']}{RESET}")

    # Cache poisoning
    cache = report.get("cache_poisoning", [])
    if cache:
        _section(f"Cache Vulnerabilities ({len(cache)} found)", RED)
        for c in cache:
            sev_color = RED if c["severity"] == "high" else YELLOW
            _line(f"{sev_color}{c['severity']:<6}{RESET} {c['title']}")
            _line(f"       {DIM}{c['description']}{RESET}")

    # Contextual insights
    from .modules.intel import build_insights
    insights = build_insights(report)
    if insights:
        _section("Insights", CYAN)
        for insight in insights:
            _line(f"{DIM}{insight}{RESET}")

    print()


def _print_traceroute_hops(tr, title, color):
    """Print traceroute hops with role classification and hostnames."""
    tr_hops = tr.get("hops", [])
    if tr_hops:
        methods = ", ".join(tr.get("methods", []))
        _section(f"{title} ({methods})", color)

        _ROLE_STYLE = {
            "local":    (DIM,    "local"),
            "isp":      (WHITE,  "isp"),
            "ixp":      (MAGENTA, "ixp"),
            "transit":  (CYAN,   "transit"),
            "cdn":      (RED,    "cdn"),
            "cloud":    (YELLOW, "cloud"),
            "hosting":  (GREEN,  "hosting"),
            "filtered": (DIM,    ""),
        }

        prev_asn = None
        for h in tr_hops:
            hop_num = h.get("hop", "?")
            ip = h.get("ip", "*")

            if ip == "*":
                _line(f"{DIM}{hop_num:>2}  {'*':<20}                                    *{RESET}")
                continue

            rtt = h.get("rtt_ms")
            provider = h.get("provider", "")
            asn = h.get("asn", "")
            country = h.get("country", "")
            bgp_prefix = h.get("bgp_prefix", "")
            hostname = h.get("hostname", "")
            role = h.get("role", "isp")
            cdn_provider = h.get("cdn_provider")
            rtt_str = f"{rtt:.1f}ms" if rtt is not None else ""

            c, role_tag = _ROLE_STYLE.get(role, (WHITE, role))

            # Boundary marker when ASN changes
            boundary = ""
            if asn and asn != prev_asn and prev_asn is not None:
                boundary = f" {YELLOW}◄{RESET}"
            if asn:
                prev_asn = asn

            asn_str = f"AS{asn}" if asn else ""
            country_str = country if country else ""

            # Build the info string: provider or CDN name
            if cdn_provider:
                info = cdn_provider
            elif provider:
                info = provider.split(" - ")[0].split(",")[0].strip()[:25]
            elif _is_private_display(ip):
                info = "gateway"
            else:
                info = ""

            role_str = f"[{role_tag}]" if role_tag else ""

            # Main hop line
            _line(
                f"{c}{hop_num:>2}  {ip:<18} {rtt_str:>7}  "
                f"{asn_str:<8} {info:<25} {country_str:<3} {role_str}{RESET}{boundary}"
            )

            # Detail line: hostname, prefix, POP detection
            details = []
            if hostname and hostname != ip:
                details.append(hostname[:50])
            if bgp_prefix:
                details.append(bgp_prefix)
            # Detect CDN POP from hostname (e.g. mad56 from cloudfront, ams from akamai)
            if hostname and cdn_provider:
                pop = _extract_pop(hostname, cdn_provider)
                if pop:
                    details.append(f"POP: {pop}")
            if details:
                _line(f"{DIM}    {'':18}        {' | '.join(details)}{RESET}")

        # (trailing * hops are already printed inline above)

    elif tr.get("methods") is not None and not tr.get("methods"):
        _section(title, color)
        if tr.get("error"):
            _line(f"{DIM}{tr['error']}{RESET}")
        else:
            _line(f"{DIM}traceroute failed{RESET}")


_POP_CODES = {
    "mad": "Madrid", "bcn": "Barcelona", "lis": "Lisbon", "lhr": "London",
    "cdg": "Paris", "ams": "Amsterdam", "fra": "Frankfurt", "mxp": "Milan",
    "fco": "Rome", "vie": "Vienna", "waw": "Warsaw", "prg": "Prague",
    "zrh": "Zurich", "arn": "Stockholm", "hel": "Helsinki", "cph": "Copenhagen",
    "osl": "Oslo", "dub": "Dublin", "bru": "Brussels", "mrs": "Marseille",
    "jfk": "New York", "iad": "Washington DC", "ord": "Chicago",
    "lax": "Los Angeles", "sfo": "San Francisco", "sea": "Seattle",
    "atl": "Atlanta", "dfw": "Dallas", "mia": "Miami", "den": "Denver",
    "bos": "Boston", "phx": "Phoenix", "pdx": "Portland", "slc": "Salt Lake City",
    "yyz": "Toronto", "yul": "Montreal", "yvr": "Vancouver",
    "gru": "São Paulo", "gig": "Rio de Janeiro", "eze": "Buenos Aires",
    "scl": "Santiago", "bog": "Bogotá", "lim": "Lima", "mex": "Mexico City",
    "nrt": "Tokyo", "hnd": "Tokyo", "kix": "Osaka", "icn": "Seoul",
    "hkg": "Hong Kong", "sin": "Singapore", "bom": "Mumbai", "del": "Delhi",
    "syd": "Sydney", "mel": "Melbourne", "akl": "Auckland",
    "dxb": "Dubai", "bah": "Bahrain", "jnb": "Johannesburg", "cpt": "Cape Town",
}


def _extract_pop(hostname, cdn_provider):
    """Extract CDN POP location from hostname."""
    hostname = hostname.lower()
    # CloudFront: server-x-x-x-x.mad56.r.cloudfront.net → mad56
    if cdn_provider == "cloudfront":
        m = re.match(r'server-[\d-]+\.([a-z]{3}\d+)\.', hostname)
        if m:
            code = m.group(1)
            city_code = code[:3]
            city = _POP_CODES.get(city_code, city_code.upper())
            return f"{code} ({city})"
    # Cloudflare: usually in headers (cf-ray), not hostname
    # Fastly: cache-mad22948.MAD → mad
    if cdn_provider == "fastly":
        m = re.search(r'cache-([a-z]{3})', hostname)
        if m:
            city_code = m.group(1)
            city = _POP_CODES.get(city_code, city_code.upper())
            return f"{city_code} ({city})"
    # Akamai: a]N].dscb.akamaiedge.net — extract from hostname region codes
    if "akamai" in hostname:
        for code, city in _POP_CODES.items():
            if code in hostname:
                return f"{code} ({city})"
    return None


def _expand_ip_targets(ip_arg):
    """Expand comma-separated IPs and CIDR ranges into a flat list.

    Supports: 1.2.3.4, 1.2.3.0/24, 1.2.3.4,5.6.7.0/28
    """
    import ipaddress
    ips = []
    for part in ip_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                # Skip network and broadcast for /31 and larger
                hosts = list(network.hosts()) if network.prefixlen < 31 else list(network)
                for host in hosts:
                    ips.append(str(host))
            except ValueError:
                ips.append(part)  # not a valid CIDR, pass through
        else:
            ips.append(part)
    return ips


def _is_private_display(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (a == 10 or (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or a == 127)


def _run_purge_history(targets, args):
    """Delete scan history for a domain."""
    from .modules.scan_persistence import ScanPersistence

    db = ScanPersistence()
    for target in targets:
        domain = _extract_domain(target)
        count = db.purge_domain(domain)
        print(f"  {YELLOW}Purged {count} scan(s) for {domain}{RESET}")
    db.close()


def _run_waf_scan(targets, args):
    """Run deep WAF vulnerability scanner."""
    from .modules.waf_vuln_scanner import WAFVulnScanner

    is_json = args.json
    persist = not args.no_persist
    layers = None
    if args.waf_scan_layers:
        layers = [l.strip() for l in args.waf_scan_layers.split(",")]

    all_reports = []
    for target in targets:
        domain = _extract_domain(target)
        print(f"{CYAN}[*] WAF vulnerability scan: {domain}{RESET}", file=sys.stderr)

        # Platform detection for context
        from .modules.intel import detect_platform
        from .modules import dns_resolver as _dns
        _dns_info = _dns.resolve_domain(domain)
        try:
            import httpx
            with httpx.Client(timeout=args.timeout, follow_redirects=True, verify=False) as _c:
                _resp = _c.get(f"https://{domain}")
            _server_hdr = _resp.headers.get("server", "")
        except Exception:
            _server_hdr = ""
        _platform = detect_platform(server_header=_server_hdr, cnames=_dns_info.get("cnames", []))

        if _platform.get("is_saas") and not is_json:
            print(f"  {YELLOW}Platform: {_platform['platform_name']} (provider-hosted SaaS){RESET}", file=sys.stderr)
            print(f"  {YELLOW}Network/path probes may not be applicable — server config is provider-managed{RESET}", file=sys.stderr)

        scanner = WAFVulnScanner(domain, timeout=args.timeout, proxy=args.proxy, user_agent=args.user_agent)

        if layers:
            report = {}
            for layer in layers:
                print(f"  {DIM}[*] Scanning layer: {layer}{RESET}", file=sys.stderr)
                report[layer] = scanner.scan_layer(layer)
        else:
            report = scanner.scan_all(persist=persist)

        report["platform"] = _platform
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

    plat = report.get("platform", {})
    if plat.get("is_saas"):
        print(f"  {YELLOW}{plat['platform_name']} (SaaS) — network/path findings may not be customer-actionable{RESET}")

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
            # Build verification status string
            v_parts = []
            if f.get("verified"):
                v_parts.append(f"{GREEN}verified{RESET}")
            else:
                v_parts.append(f"{YELLOW}unverified{RESET}")
            if f.get("fp_verified"):
                v_parts.append(f"{GREEN}FP-clean{RESET}")
            v_str = " | ".join(v_parts)
            print(f"      Confidence: {conf:.0%} | {v_str}")

    # Summary
    summary = report.get("summary", {})
    if summary:
        fp_count = summary.get("fp_verified_count", 0)
        verified_count = summary.get("verified_count", 0)
        total = summary.get("total_findings", 0)
        print(f"\n  {BOLD}── Summary ──{RESET}")
        print(f"    Total: {total} | Verified: {verified_count} | FP-clean: {fp_count}")

    layer_results = report.get("layers", {})
    if layer_results:
        print(f"\n  {BOLD}── Layer Summary ──{RESET}")
        for layer_name, layer_data in layer_results.items():
            count = len(layer_data) if isinstance(layer_data, list) else 0
            icon = f"{RED}!" if count > 0 else f"{GREEN}✓"
            print(f"    {icon}{RESET} {layer_name:<15} {count} finding(s)")

    # Cross-session statistics
    stats = report.get("statistics", {})
    if stats and not stats.get("error"):
        total_scans = stats.get("total_scans_for_domain", 0)
        if total_scans > 1:
            print(f"\n  {BOLD}{CYAN}── Statistical Analysis (scan #{total_scans}) ──{RESET}")
            new_count = stats.get("new_findings_this_scan", 0)
            gone_count = stats.get("disappeared_from_previous", 0)
            if new_count:
                print(f"    {GREEN}+ {new_count} new finding(s) this scan{RESET}")
            if gone_count:
                print(f"    {YELLOW}- {gone_count} finding(s) disappeared (patched or intermittent){RESET}")

            stability_data = stats.get("finding_stability", [])
            if stability_data:
                print(f"\n    {BOLD}Finding Stability:{RESET}")
                for s in stability_data[:15]:
                    stab = s["stability"]
                    stab_color = GREEN if stab == "stable" else YELLOW if stab == "intermittent" else RED if stab == "rare" else CYAN
                    fp_tag = f" {GREEN}[FP-clean]{RESET}" if s.get("fp_verified") else ""
                    print(
                        f"      {stab_color}{stab:<12}{RESET} "
                        f"{s['severity']:<8} "
                        f"seen {s['times_seen']}/{s['total_scans']} "
                        f"(conf: {s['statistical_confidence']:.0%}){fp_tag} "
                        f"{DIM}{s['title'][:50]}{RESET}"
                    )

            disappeared = stats.get("disappeared_findings", [])
            if disappeared:
                print(f"\n    {BOLD}Previously Seen (now absent):{RESET}")
                for d in disappeared[:10]:
                    print(f"      {DIM}[{d['severity']}] {d['title'][:60]}{RESET}")
                    print(f"        {DIM}{d.get('note', '')}{RESET}")

    print()


def _run_cf_inject(targets, args):
    """Test Cloudflare header injection bypass."""
    from .modules.cf_header_inject import test_cf_header_trust

    for target in targets:
        domain = _extract_domain(target)
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


def _run_headers(targets, args):
    """Audit HTTP security headers."""
    from .modules import security_headers
    from .scanner import fetch_response

    is_json = args.json
    all_results = []

    # Build extra headers
    extra_headers = {}
    if getattr(args, "cookie", None):
        extra_headers["Cookie"] = args.cookie
    for h in (getattr(args, "header", None) or []):
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    for target in targets:
        url = target if target.startswith("http") else f"https://{target}"

        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [~] Fetching {url}...{RESET}")
            sys.stderr.flush()

        resp = fetch_response(url, timeout=args.timeout,
                              user_agent=args.user_agent,
                              proxy=args.proxy,
                              extra_headers=extra_headers or None)

        if not is_json:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

        if "error" in resp:
            print(f"{RED}[!] Error fetching {url}: {resp['error']}{RESET}", file=sys.stderr)
            continue

        audit = security_headers.audit_headers(
            resp["headers"], cookies=resp.get("cookies", []), url=url
        )
        audit["target"] = target
        audit["status"] = resp.get("status")
        all_results.append(audit)

        if not is_json:
            W = max(len(target) + 20, 60)
            print(f"\n{BOLD}{CYAN}{'=' * W}{RESET}")
            print(f"{BOLD}{CYAN}  Security Headers: {target}{RESET}")
            print(f"{BOLD}{CYAN}{'=' * W}{RESET}")
            print(f"  {BOLD}Score:{RESET} {audit['score']}% ({len(audit['present'])}/{audit['total']} headers present)")
            print(f"  {BOLD}URL:{RESET}   {url}  [{resp.get('status', '?')}]")

            # Missing headers
            if audit["missing"]:
                _section("Missing Headers", RED)
                for h in audit["missing"]:
                    sev_color = RED if h["severity"] == "high" else YELLOW if h["severity"] == "medium" else DIM
                    _line(f"{sev_color}✗ {h['name']:<35}{RESET} [{h['severity'].upper():<6}] {h['description']}")
                    _line(f"  {DIM}Recommended: {h['recommended']}{RESET}")

            # Present headers
            if audit["present"]:
                _section("Present Headers", GREEN)
                for h in audit["present"]:
                    val_preview = h["value"][:80]
                    _line(f"{GREEN}✓ {h['name']:<35}{RESET} {DIM}{val_preview}{RESET}")

            # Warnings (present but weak)
            if audit["warnings"]:
                _section("Weak Configuration", YELLOW)
                for h in audit["warnings"]:
                    _line(f"{YELLOW}⚠ {h['name']:<35}{RESET} {h['value'][:60]}")
                    _line(f"  {RED}→ {h['warning']}{RESET}")

            # Dangerous/deprecated headers
            if audit.get("dangerous"):
                _section("Dangerous / Deprecated Headers", RED)
                for h in audit["dangerous"]:
                    _line(f"{RED}✗ {h['name']}: {h['value']}{RESET}")
                    _line(f"  {DIM}{h['description']}{RESET}")
                    _line(f"  {CYAN}→ {h['recommendation']}{RESET}")

            # Info leak
            if audit["info_leak"]:
                _section("Information Leakage", YELLOW)
                for h in audit["info_leak"]:
                    _line(f"{YELLOW}⚠ {h['name']}: {h['value']}{RESET}")

            # Cookie issues
            if audit["cookie_issues"]:
                _section("Cookie Security Issues", RED)
                for c in audit["cookie_issues"]:
                    issues_str = ", ".join(c["issues"])
                    _line(f"{RED}✗{RESET} {c['name']}: {YELLOW}{issues_str}{RESET}")

            print()

    if is_json:
        _write_output(json.dumps(all_results, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_results, indent=2, default=str), args.output)


def _run_vecino(targets, args):
    """Run reverse IP neighbours + SSL cert hosting classification."""
    try:
        import importlib.util
        for candidate in [
            os.path.expanduser("~/BB_tools/vecino.py"),
            os.path.join(os.environ.get("BB_TOOLS", ""), "vecino.py"),
        ]:
            if os.path.isfile(candidate):
                vecino_path = candidate
                break
        else:
            raise FileNotFoundError("vecino.py not found")
        spec = importlib.util.spec_from_file_location("vecino", vecino_path)
        vecino = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vecino)
    except Exception as e:
        print(f"{RED}[!] Could not load vecino.py: {e}{RESET}", file=sys.stderr)
        print(f"{DIM}    Expected at ~/BB_tools/vecino.py{RESET}", file=sys.stderr)
        return

    from .modules import dns_resolver, origin_finder

    is_json = args.json
    all_results = []

    for target in targets:
        domain = dns_resolver._clean_domain(target)

        # Resolve to IP
        ip, hostname = vecino.resolve_to_ip(target)
        if not ip:
            print(f"{RED}[!] Could not resolve {target}{RESET}", file=sys.stderr)
            continue

        if not is_json:
            W = max(len(domain) + 20, 60)
            print(f"\n{BOLD}{CYAN}{'=' * W}{RESET}")
            print(f"{BOLD}{CYAN}  Vecino + Cert Analysis: {domain} ({ip}){RESET}")
            print(f"{BOLD}{CYAN}{'=' * W}{RESET}")

        # 0. Quick platform detection
        from .modules.intel import detect_platform
        try:
            import httpx
            with httpx.Client(timeout=args.timeout, follow_redirects=True, verify=False) as _c:
                _resp = _c.get(f"https://{domain}")
            _server_hdr = _resp.headers.get("server", "")
        except Exception:
            _server_hdr = ""
        from .modules import dns_resolver as _dns
        _dns_info = _dns.resolve_domain(domain)
        _platform = detect_platform(server_header=_server_hdr, cnames=_dns_info.get("cnames", []))

        # 1. SSL cert hosting classification
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [~] SSL cert inspection (with/without SNI)...{RESET}")
            sys.stderr.flush()
        cert_class = origin_finder.classify_hosting_by_cert(ip, domain)
        if not is_json:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

        # 2. Vecino neighbour scan
        if not is_json:
            sys.stderr.write(f"\r\033[K{DIM}  [~] Reverse IP neighbours...{RESET}")
            sys.stderr.flush()
        neighbours = vecino.scan_neighbours(ip, hostname=hostname)
        if not is_json:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

        combined = {
            "target": target, "domain": domain, "ip": ip,
            "cert_classification": cert_class,
            "neighbours": neighbours,
            "platform": _platform,
        }
        all_results.append(combined)

        if not is_json:
            # ── Cert Classification ──
            _section("SSL Certificate Hosting Classification", MAGENTA)
            ct = cert_class.get("hosting_type", "UNKNOWN")
            conf = cert_class.get("confidence", "low")
            type_color = {
                "VPS/DEDICATED": GREEN, "SHARED_HOSTING": YELLOW,
                "SAAS": CYAN, "MANAGED_HOSTING": CYAN, "CDN": RED,
            }.get(ct, DIM)
            _line(f"Type:       {type_color}{BOLD}{ct}{RESET}  (confidence: {conf})")

            cert_no = cert_class.get("cert_no_sni")
            cert_sni = cert_class.get("cert_with_sni")
            if cert_no:
                _line(f"Cert (no SNI):   {BOLD}{cert_no['cn']}{RESET}  issuer: {cert_no.get('issuer', '?')}  SANs: {cert_no.get('san_count', '?')}")
            else:
                _line(f"Cert (no SNI):   {DIM}none / connection failed{RESET}")
            if cert_sni:
                _line(f"Cert (with SNI): {BOLD}{cert_sni['cn']}{RESET}  issuer: {cert_sni.get('issuer', '?')}  SANs: {cert_sni.get('san_count', '?')}")
            else:
                _line(f"Cert (with SNI): {DIM}none / connection failed{RESET}")

            for sig in cert_class.get("signals", []):
                _line(f"{DIM}→ {sig}{RESET}")

            # ── Neighbours ──
            _section("Reverse IP Neighbours", BLUE)
            n = neighbours
            if _platform.get("is_saas"):
                _line(f"{YELLOW}Note: {_platform['platform_name']} is provider-hosted SaaS — this IP is shared infrastructure.{RESET}")
                _line(f"{YELLOW}Domains below are unrelated third-party sites on the same provider, not security-relevant.{RESET}")
            _line(f"Domains found: {BOLD}{n['domain_count']}{RESET}  "
                  f"(PTR: {n['sources'].get('ptr', 0)}, HackerTarget: {n['sources'].get('hackertarget', 0)}, "
                  f"RapidDNS: {n['sources'].get('rapiddns', 0)})")
            _line(f"Provider:      {n.get('provider', '?')}")
            _line(f"Hosting type:  {BOLD}{n.get('hosting_type', '?')}{RESET}")

            if n.get("panels"):
                panels_str = ", ".join(f"{k}:{v}" for k, v in n["panels"].items()) if isinstance(n["panels"], dict) else str(n["panels"])
                _line(f"Panels:        {RED}{panels_str}{RESET}")

            if n.get("domains"):
                shown = n["domains"][:20]
                _line(f"\n{BOLD}  Domains on same IP:{RESET}")
                for d in shown:
                    _line(f"  {DIM}•{RESET} {d}")
                if len(n["domains"]) > 20:
                    _line(f"  {DIM}... and {len(n['domains']) - 20} more{RESET}")

            # ── Combined verdict ──
            _section("Verdict", GREEN)
            vecino_type = n.get("hosting_type", "UNKNOWN")
            cert_type = cert_class.get("hosting_type", "UNKNOWN")
            cert_conf = cert_class.get("confidence", "low")

            # Cert analysis with high confidence takes priority
            if cert_conf == "high" and cert_type != "UNKNOWN":
                verdict = cert_type
                if vecino_type != "UNKNOWN" and vecino_type.replace("VPS/DEDICATED", "VPS") != cert_type.replace("VPS/DEDICATED", "VPS"):
                    verdict_source = f"SSL cert analysis (vecino says {vecino_type} but cert overrides)"
                else:
                    verdict_source = "SSL cert analysis"
            elif cert_type in ("SHARED_HOSTING", "SAAS", "MANAGED_HOSTING", "CDN"):
                verdict = cert_type
                verdict_source = "SSL cert analysis"
            elif vecino_type == "SHARED" and n.get("domain_count", 0) > 5:
                verdict = "SHARED_HOSTING"
                verdict_source = "reverse IP neighbours"
            elif cert_type == "VPS/DEDICATED":
                verdict = "VPS/DEDICATED"
                verdict_source = "SSL cert analysis"
            elif vecino_type != "UNKNOWN":
                verdict = vecino_type
                verdict_source = "reverse IP neighbours"
            else:
                verdict = "UNKNOWN"
                verdict_source = "insufficient data"

            verdict_color = {
                "VPS/DEDICATED": GREEN, "SHARED_HOSTING": YELLOW, "SHARED": YELLOW,
                "SAAS": CYAN, "MANAGED_HOSTING": CYAN, "CDN": RED,
            }.get(verdict, DIM)
            _line(f"{verdict_color}{BOLD}{verdict}{RESET}  (based on: {verdict_source})")
            print()

    if is_json:
        _write_output(json.dumps(all_results, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(all_results, indent=2, default=str), args.output)


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

        if args.ip == "history":
            # Load IPs from local database instead of calling APIs
            from .modules.scan_persistence import ScanPersistence
            db = ScanPersistence()
            ip_stats = db.get_ip_stats(domain)
            db.close()

            if not ip_stats:
                print(f"{YELLOW}[!] No stored IPs for {domain}. Run a scan first: wtw {domain}{RESET}", file=sys.stderr)
                continue

            # Skip CDN edge IPs, prioritize bypass-confirmed and high-confidence
            kept = []
            skipped = []
            for s in ip_stats:
                provider_lower = (s.provider or "").lower()
                if any(kw in provider_lower for kw in CDN_WAF_KEYWORDS):
                    skipped.append(s)
                else:
                    kept.append(s)

            if skipped:
                print(f"{DIM}[*] Skipped {len(skipped)} CDN/WAF edge IP(s) from history{RESET}", file=sys.stderr)

            if not kept:
                print(f"{YELLOW}[!] All stored IPs for {domain} are CDN/WAF edges — no origin candidates{RESET}", file=sys.stderr)
                continue

            # Sort: bypass-confirmed first, then by confidence
            kept.sort(key=lambda s: (-int(s.bypass_confirmed), -s.confidence))

            print(f"{GREEN}[+] Loaded {len(kept)} IP(s) from history for {domain}:{RESET}", file=sys.stderr)
            for s in kept:
                bypass_tag = f" {GREEN}[BYPASS]{RESET}" if s.bypass_confirmed else ""
                print(
                    f"    {s.ip:<16} conf: {s.confidence:.0%}  "
                    f"seen {s.times_seen}x  sources: {','.join(s.sources)}{bypass_tag}",
                    file=sys.stderr,
                )
            print(file=sys.stderr)

            ips = [s.ip for s in kept]

        elif args.ip == "auto":
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
                _clear_status()
                found = origin_finder.find_origins(domain, cdn_ips=cdn_ips)
                candidates.extend([c for c in found if not c.get("is_cdn")])

            for c in candidates:
                if c["ip"] not in seen_ips:
                    seen_ips.add(c["ip"])
                    test_ips.append({"ip": c["ip"], "source": c.get("source", "subdomain")})

            # Historical DNS (ViewDNS + SecurityTrails)
            status_cb("history", "Historical DNS lookup")
            _clear_status()
            historical = origin_finder.fetch_historical_ips(domain)

            for h in historical:
                if h["ip"] not in seen_ips:
                    seen_ips.add(h["ip"])
                    src = h.get("source", "historical")
                    test_ips.append({"ip": h["ip"], "source": f"{src} ({h.get('last_seen', '?')})"})

            # Favicon hash matching (Shodan/FOFA/ZoomEye)
            status_cb("origins", "Favicon hash matching")
            _clear_status()
            fav = origin_finder.fetch_favicon_hash(domain)
            if fav:
                fav_results = origin_finder.search_by_favicon_hash(fav["hash"], domain=domain)
                for r in fav_results:
                    if r["ip"] not in seen_ips:
                        seen_ips.add(r["ip"])
                        test_ips.append({"ip": r["ip"], "source": f"favicon:{r['source']}"})

            # Censys certificate search
            status_cb("origins", "Censys certificate search")
            _clear_status()
            censys_results = origin_finder.search_censys(domain)
            for r in censys_results:
                if r["ip"] not in seen_ips:
                    seen_ips.add(r["ip"])
                    test_ips.append({"ip": r["ip"], "source": "censys"})

            # GitHub leak search
            status_cb("origins", "GitHub repository leak search")
            _clear_status()
            github_results = origin_finder.search_github_leaks(domain)
            for r in github_results:
                if r["ip"] not in seen_ips:
                    seen_ips.add(r["ip"])
                    test_ips.append({"ip": r["ip"], "source": f"github ({r.get('repo', '?')})"})

            # Shodan DNS records — only keep IPs for the target subdomain, not unrelated services
            status_cb("origins", "Shodan domain search")
            _clear_status()
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
            _clear_status()
            vt_results = origin_finder.search_virustotal(domain)
            for r in vt_results:
                if r["ip"] not in seen_ips:
                    seen_ips.add(r["ip"])
                    test_ips.append({"ip": r["ip"], "source": "virustotal"})

            if not test_ips:
                print(f"{YELLOW}[!] No origin IP candidates found for {domain}{RESET}", file=sys.stderr)
                continue

            # Fast local CIDR check: discard IPs in known CDN ranges before ASN lookup
            from .modules import asn_lookup as _asn
            cidr_filtered = []
            cidr_skipped = []
            for t in test_ips:
                cdn_provider = _asn.is_cdn_ip(t["ip"])
                if cdn_provider:
                    cidr_skipped.append((t, cdn_provider))
                else:
                    cidr_filtered.append(t)
            if cidr_skipped:
                print(f"{DIM}[*] Filtered {len(cidr_skipped)} IP(s) in known CDN CIDR ranges:{RESET}", file=sys.stderr)
                for t, prov in cidr_skipped[:5]:
                    print(f"    {DIM}{t['ip']:<16} {prov}{RESET}", file=sys.stderr)
                if len(cidr_skipped) > 5:
                    print(f"    {DIM}... and {len(cidr_skipped) - 5} more{RESET}", file=sys.stderr)
            test_ips = cidr_filtered

            if not test_ips:
                print(f"{YELLOW}[!] All IPs are in known CDN ranges — no origin candidates to test{RESET}", file=sys.stderr)
                continue

            # ASN-classify remaining candidates and skip CDN/WAF edge IPs
            all_candidate_ips = [t["ip"] for t in test_ips]
            asn_info = _asn.lookup_asn_bulk(all_candidate_ips) if all_candidate_ips else []
            asn_map = {r["ip"]: r for r in asn_info}

            kept = []
            skipped_cdn = []
            for t in test_ips:
                asn = asn_map.get(t["ip"], {})
                provider = asn.get("provider", "").lower()
                if any(kw in provider for kw in CDN_WAF_KEYWORDS):
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

            # Quick pre-filter: parallel TCP connect + lightweight probe to discard dead/unrelated IPs
            if len(kept) > 3:
                # Fetch target title from CDN for comparison
                cdn_title = ""
                try:
                    import httpx as _httpx
                    with _httpx.Client(timeout=8, verify=False, follow_redirects=True) as _hc:
                        _cdn_resp = _hc.get(
                            f"https://{domain}/",
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                        )
                        if _cdn_resp.status_code == 200:
                            import re as _re
                            _tm = _re.search(r'<title[^>]*>(.*?)</title>', _cdn_resp.text[:5000], _re.IGNORECASE | _re.DOTALL)
                            if _tm:
                                cdn_title = " ".join(_tm.group(1).strip().lower().split())
                except Exception:
                    pass

                print(f"{CYAN}[*] Quick probe: {len(kept)} IPs (TCP:443 + Host header check)...{RESET}", file=sys.stderr)
                probed = _quick_probe_ips([t["ip"] for t in kept], domain, timeout=min(args.timeout, 5))

                alive = []
                dead = []
                wrong_host = []
                title_mismatch = []
                for t in kept:
                    probe = probed.get(t["ip"], {})
                    if probe.get("error"):
                        dead.append(t)
                    elif probe.get("wrong_host"):
                        wrong_host.append(t)
                    else:
                        t["probe_status"] = probe.get("status")
                        t["probe_title"] = probe.get("title", "")
                        probe_title_norm = " ".join(t["probe_title"].lower().split()) if t["probe_title"] else ""
                        status = t["probe_status"]
                        is_favicon_src = "favicon" in t.get("source", "")

                        # Decide if this IP is clearly unrelated
                        skip = False
                        if cdn_title and probe_title_norm and probe_title_norm != cdn_title:
                            if status == 200:
                                # 200 with wrong title = definitely unrelated
                                skip = True
                            elif is_favicon_src:
                                # Non-200 with wrong title from favicon = unrelated server
                                skip = True
                            elif status in (400, 403, 404):
                                # Client error with wrong title = not our target
                                skip = True
                        # Favicon source: skip error/redirect responses (not the target)
                        if not skip and is_favicon_src:
                            if status in (301, 302, 303, 307, 308):
                                location = probe.get("location", "").lower()
                                if not location or domain.lower() not in location:
                                    skip = True
                            elif status in (403, 404):
                                skip = True

                        if skip:
                            title_mismatch.append(t)
                        else:
                            alive.append(t)

                if dead:
                    print(f"  {DIM}Skipped {len(dead)} IP(s) — no response on port 443{RESET}", file=sys.stderr)
                if wrong_host:
                    print(f"  {DIM}Skipped {len(wrong_host)} IP(s) — responds but wrong host/default page{RESET}", file=sys.stderr)
                if title_mismatch:
                    print(f"  {DIM}Skipped {len(title_mismatch)} IP(s) — title mismatch (unrelated site){RESET}", file=sys.stderr)

                if not alive:
                    print(f"{YELLOW}[!] No IPs responded for {domain} on port 443{RESET}", file=sys.stderr)
                    continue
                kept = alive

            print(f"{GREEN}[+] Testing {len(kept)} origin candidate IP(s) for {domain}:{RESET}", file=sys.stderr)
            for t in kept:
                asn = asn_map.get(t["ip"], {})
                asn_str = f"AS{asn.get('asn', '?')}" if asn.get("asn") else ""
                probe_info = ""
                if t.get("probe_status"):
                    probe_info = f" [{t['probe_status']}]"
                    if t.get("probe_title"):
                        probe_info += f" {t['probe_title'][:30]}"
                print(f"    {t['ip']:<16} via {t['source']:<35} {DIM}{asn_str}{probe_info}{RESET}", file=sys.stderr)
            print(file=sys.stderr)

            ips = [t["ip"] for t in kept]
        else:
            # Comma-separated IPs and/or CIDR ranges
            ips = _expand_ip_targets(args.ip)

            # Filter out CDN/WAF edge IPs (Cloudflare, Akamai, etc.)
            if ips:
                from .modules import asn_lookup as _asn
                print(f"{DIM}[*] ASN classification for {len(ips)} IP(s)...{RESET}", file=sys.stderr)
                asn_info = _asn.lookup_asn_bulk(ips[:500])
                asn_map = {r["ip"]: r for r in asn_info}

                kept = []
                skipped_cdn = []
                for ip in ips:
                    asn = asn_map.get(ip, {})
                    provider = asn.get("provider", "").lower()
                    if any(kw in provider for kw in CDN_WAF_KEYWORDS):
                        skipped_cdn.append((ip, asn))
                    else:
                        kept.append(ip)

                if skipped_cdn:
                    print(f"{YELLOW}[!] Skipped {len(skipped_cdn)} CDN/WAF edge IP(s):{RESET}", file=sys.stderr)
                    for ip, asn in skipped_cdn[:5]:
                        print(f"    {DIM}{ip:<16} {asn.get('provider', '?')}{RESET}", file=sys.stderr)
                    if len(skipped_cdn) > 5:
                        print(f"    {DIM}... and {len(skipped_cdn) - 5} more{RESET}", file=sys.stderr)

                if not kept:
                    print(f"{RED}[!] All IPs are CDN/WAF edges — no origin candidates to test{RESET}", file=sys.stderr)
                    continue

                _clear_status()
                ips = kept

        # Test each IP
        from .modules.deep_scan import scan_alt_ports, probe_cloud_metadata

        for ip in ips:
            print(f"{CYAN}[*] Testing {domain} → {ip} (path: {path}){RESET}", file=sys.stderr)
            try:
                report = direct_ip_scan(
                    target, ip, timeout=args.timeout,
                    user_agent=args.user_agent, on_status=status_cb,
                    path=path,
                )
                _clear_status()

                # Alt port scan
                status_cb("bypass", f"Scanning alternative ports on {ip}")
                sys.stderr.flush()
                alt_ports = scan_alt_ports(ip, domain, timeout=min(args.timeout, 3))
                if alt_ports:
                    report["alt_ports"] = [p for p in alt_ports if p["port"] not in (80, 443)]
                _clear_status()

                # Cloud metadata check (only for cloud-hosted IPs)
                asn_provider = report.get("direct_ip_asn", {}).get("provider", "").lower()
                cloud_keywords = {"amazon", "aws", "google", "gcp", "azure", "microsoft",
                                  "digitalocean", "linode", "vultr", "oracle cloud"}
                if any(k in asn_provider for k in cloud_keywords):
                    status_cb("bypass", f"Cloud metadata probe on {ip}")
                    sys.stderr.flush()
                    metadata = probe_cloud_metadata(ip, timeout=3)
                    if metadata:
                        report["cloud_metadata"] = metadata
                    _clear_status()

                reports.append(report)
                if not is_json:
                    _print_direct_ip_report(report)
            except Exception as e:
                _clear_status()
                print(f"{RED}[!] Error: {target} → {ip}: {e}{RESET}", file=sys.stderr)
                reports.append({"target": target, "ip": ip, "error": str(e)})

    # Persist bypass results for cross-session tracking
    try:
        from .modules.scan_persistence import ScanPersistence
        db = ScanPersistence()
        for r in reports:
            if r.get("ip") and r.get("target"):
                rdomain = dns_resolver._clean_domain(r["target"])
                db.store_recon_ip(
                    domain=rdomain,
                    ip=r["ip"],
                    source="direct-ip-test",
                    bypass_confirmed=r.get("bypass_confirmed", False),
                )
        db.close()
    except Exception:
        pass

    # Print summary table if multiple IPs tested
    if not is_json and len(reports) > 1:
        _print_direct_ip_summary(reports)

    if is_json:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)


def _quick_probe_ips(ips, domain, timeout=5):
    """Fast parallel probe: TCP connect to 443 + lightweight GET with Host header.

    Returns dict: ip -> {status, title, error, wrong_host}
    Runs all probes concurrently for speed.
    """
    import ssl
    import re
    import concurrent.futures
    import httpx

    default_page_signatures = {
        "welcome to nginx", "apache2 default", "it works!", "test page",
        "iis windows server", "default web site", "parking page",
        "domain is not pointed", "cpanel", "plesk", "directadmin",
        "congrats", "default page", "coming soon", "under construction",
    }

    def _probe_one(ip):
        try:
            # Single GET with Host header, no redirects, short timeout
            with httpx.Client(
                timeout=timeout, verify=False, follow_redirects=False,
                headers={"Host": domain, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            ) as client:
                resp = client.get(f"https://{ip}/")

            status = resp.status_code
            body = resp.text[:5000]
            title = ""
            m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()

            # Check if this is a default/unrelated page
            body_lower = body.lower()
            title_lower = title.lower()
            wrong_host = False
            for sig in default_page_signatures:
                if sig in body_lower or sig in title_lower:
                    wrong_host = True
                    break

            # 4xx/5xx with no meaningful content = probably not our target
            if status in (400, 421) and len(body) < 500:
                wrong_host = True

            location = ""
            if status in (301, 302, 303, 307, 308):
                location = str(resp.headers.get("location", ""))

            return {"status": status, "title": title, "wrong_host": wrong_host, "location": location}

        except Exception as e:
            err = str(e)
            # Distinguish timeout from connection refused
            if "timed out" in err.lower() or "timeout" in err.lower():
                return {"error": "timeout"}
            elif "refused" in err.lower():
                return {"error": "refused"}
            else:
                return {"error": err[:50]}

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ips), 20)) as pool:
        futures = {pool.submit(_probe_one, ip): ip for ip in ips}
        try:
            for future in concurrent.futures.as_completed(futures, timeout=timeout + 10):
                ip = futures[future]
                try:
                    results[ip] = future.result()
                except Exception:
                    results[ip] = {"error": "probe failed"}
        except TimeoutError:
            # Some probes hung — mark unfinished ones as timed out
            for future, ip in futures.items():
                if ip not in results:
                    results[ip] = {"error": "timeout"}
                    future.cancel()

    return results


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

    # Alternative ports
    alt_ports = report.get("alt_ports", [])
    if alt_ports:
        _section("Alternative Ports", YELLOW)
        for p in alt_ports:
            title_str = f" {DIM}{p['title'][:40]}{RESET}" if p.get("title") else ""
            _line(f"{GREEN}{p['scheme']}://{ip}:{p['port']}{RESET}  [{p['status']}] server={p.get('server', '?')}{title_str}")

    # Cloud metadata
    metadata = report.get("cloud_metadata", [])
    if metadata:
        _section("Cloud Metadata EXPOSED", RED)
        for m in metadata:
            _line(f"{RED}{m['severity']:<8}{RESET} {m['endpoint']}")
            _line(f"         {DIM}{m['evidence'][:100]}{RESET}")

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

    # Build only_modules from individual flags
    # If no module flags are passed, only_modules stays None → all modules run
    only_modules = None
    if args.only:
        # Legacy --only support (hidden)
        only_modules = set(m.strip().lower() for m in args.only.split(","))
        if "waf" in only_modules:
            only_modules.add("errors")
    else:
        _flag_to_modules = {
            "waf": {"waf", "errors"},
            "errors": {"errors"},
            "tls": {"tls"},
            "evasion": {"evasion"},
            "bypass": {"bypass"},
            "cert": {"cert"},
            "subs": {"subs"},
            "history": {"history"},
        }
        selected = set()
        for flag, modules in _flag_to_modules.items():
            if getattr(args, flag, False):
                selected.update(modules)
        if selected:
            only_modules = selected

    # All features are opt-in: --subs, --cert, --tls, --history, --evasion
    # Build extra headers from --cookie and --header
    extra_headers = {}
    if getattr(args, "cookie", None):
        extra_headers["Cookie"] = args.cookie
    for h in (getattr(args, "header", None) or []):
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    scan_kwargs = dict(
        timeout=args.timeout, scan_subs=args.subs,
        check_cert=args.cert, check_history=args.history,
        user_agent=args.user_agent, proxy=args.proxy, delay=args.delay,
        on_status=status_cb, check_tls=args.tls,
        check_evasion=args.evasion, proxy_chain=args.proxy_chain,
        use_proton=args.proton, only_modules=only_modules,
        extra_headers=extra_headers or None,
    )

    if args.workers > 1 and len(targets) > 1:
        scan_kwargs["on_status"] = None
        reports = full_scan_batch(targets, max_workers=args.workers, **scan_kwargs)
        if not is_json:
            for r in reports:
                if "error" in r and "target" in r:
                    print(f"{RED}[!] Error: {r['target']}: {r['error']}{RESET}", file=sys.stderr)
                else: _print_report(r)
        # Persist batch results
        try:
            from .modules.scan_persistence import ScanPersistence
            db = ScanPersistence()
            for r in reports:
                if "domain" in r:
                    db.store_full_scan(r["domain"], r)
            db.close()
        except Exception:
            pass
    else:
        for target in targets:
            print(f"{CYAN}[*] Scanning {target}...{RESET}", file=sys.stderr)
            try:
                report = full_scan(target, **scan_kwargs)
                _clear_status()
                reports.append(report)
                if not is_json: _print_report(report)
                # Persist scan data for cross-session history
                try:
                    from .modules.scan_persistence import ScanPersistence
                    db = ScanPersistence()
                    db.store_full_scan(report.get("domain", target), report)
                    db.close()
                except Exception:
                    pass
            except Exception as e:
                _clear_status()
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


def _waf_active_analysis(report):
    """Analyze error page probes to determine if WAF is actively blocking attacks.

    Returns (blocked, passed, redirected) for attack payloads only (trigger == "waf").
    - blocked: 403/406/429/etc — WAF or server explicitly rejected the payload
    - passed: 200 — payload went through without filtering
    - redirected: 301/302/307/308 — ambiguous, payload may or may not have been processed
    """
    ep = report.get("error_pages", {})
    ep_probes = ep.get("probes", [])
    blocked = []
    passed = []
    redirected = []
    waf_trigger_statuses = {400, 403, 406, 429, 451, 493, 503}
    redirect_statuses = {301, 302, 307, 308}

    for p in ep_probes:
        if p.get("error") or p.get("trigger") != "waf":
            continue
        status = p.get("status", 0)
        entry = {"path": p["path"], "description": p["description"],
                 "status": status, "waf_hits": p.get("waf_hits", [])}

        if status in waf_trigger_statuses:
            blocked.append(entry)
        elif status in redirect_statuses:
            # Check if redirect was followed (payload preserved → final status available)
            if p.get("redirect_payload_stripped"):
                entry["redirect_note"] = "payload stripped"
                redirected.append(entry)
            elif p.get("final_status"):
                # Redirect was followed — use final status for verdict
                entry["final_status"] = p["final_status"]
                entry["redirect_note"] = "followed"
                if p["final_status"] in waf_trigger_statuses:
                    entry["status"] = p["final_status"]
                    blocked.append(entry)
                else:
                    passed.append(entry)
            else:
                redirected.append(entry)
        else:
            passed.append(entry)

    return blocked, passed, redirected


# Attack categories for gap analysis
_ATTACK_CATEGORIES = {
    "SQL injection probe": "SQLi",
    "XSS probe": "XSS",
    "Path traversal probe": "Path Traversal",
    "Command injection probe": "Command Injection",
    "PHP filter probe": "LFI/PHP Wrappers",
}

# Categories that are critical if unprotected
_CRITICAL_CATEGORIES = {"SQLi", "LFI/PHP Wrappers", "Command Injection"}


def _classify_waf_type(waf_detections):
    """Classify detections as real WAFs vs web server hardening.

    Returns (real_wafs, server_hardening) — both lists of names.
    """
    real_wafs = []
    server_hardening = []
    for d in waf_detections:
        if d["category"] in ("WAF", "CDN/WAF"):
            real_wafs.append(d["name"])
        elif d["category"] == "Web Server":
            server_hardening.append(d["name"])
    return list(dict.fromkeys(real_wafs)), list(dict.fromkeys(server_hardening))


def _print_report(report):
    target = report['target']
    W = max(len(target) + 16, 60)
    title_pad = W - len(target) - 14
    print(f"\n{BOLD}{CYAN}╔{'═' * W}╗{RESET}")
    print(f"{BOLD}{CYAN}║  WAF Recon: {target}{' ' * max(title_pad, 1)} ║{RESET}")
    print(f"{BOLD}{CYAN}╚{'═' * W}╝{RESET}")
    print(f"  {BOLD}Summary:{RESET} {report['summary']}")

    # ── WAF STATUS (the main verdict) ──
    waf_detections = report.get("waf", [])
    real_wafs, server_hardening = _classify_waf_type(waf_detections)
    cdn_names = [d["name"] for d in waf_detections if d["category"] in ("CDN", "CDN/WAF")]
    for rec in report.get("ips", []):
        if rec.get("classification") == "CDN" and rec.get("provider"):
            prov = rec["provider"].split(" - ")[0].strip()
            if prov not in cdn_names:
                cdn_names.append(prov)

    blocked, passed, redirected = _waf_active_analysis(report)
    total_probes = len(blocked) + len(passed) + len(redirected)

    _section("WAF Status", CYAN)
    if real_wafs:
        _line(f"{RED}[+] WAF Detected:{RESET} {BOLD}{', '.join(real_wafs)}{RESET}")
        if blocked:
            _line(f"{RED}[+] WAF Active:{RESET}   {GREEN}YES{RESET} — blocking {len(blocked)}/{total_probes} attack payloads")
            for b in blocked:
                waf_str = f" ({', '.join(b['waf_hits'])})" if b["waf_hits"] else ""
                _line(f"    {RED}BLOCKED{RESET}    [{b['status']}] {b['description']}{waf_str}")
            for r in redirected:
                _line(f"    {DIM}REDIRECT{RESET}   [{r['status']}] {r['description']} {DIM}(inconclusive){RESET}")
            for p in passed:
                _line(f"    {YELLOW}PASSED{RESET}     [{p['status']}] {p['description']}")
        elif passed:
            _line(f"{YELLOW}[!] WAF Active:{RESET}   {YELLOW}NO{RESET} — detected but {BOLD}not blocking{RESET} attack payloads")
            for p in passed:
                _line(f"    {YELLOW}PASSED{RESET}     [{p['status']}] {p['description']}")
            for r in redirected:
                _line(f"    {DIM}REDIRECT{RESET}   [{r['status']}] {r['description']}{RESET}")
        else:
            _line(f"{DIM}[?] WAF Active:   Unknown (no probe results){RESET}")
    elif server_hardening:
        # Only web server detected, no real WAF — important distinction
        _line(f"{YELLOW}[~] WAF Detected:{RESET} {BOLD}No{RESET}")
        _line(f"{YELLOW}[~] Server Hardening:{RESET} {BOLD}{', '.join(server_hardening)}{RESET} — {DIM}not a WAF, just server config (e.g. Deny rules in .htaccess){RESET}")
        if blocked:
            _line(f"{YELLOW}[~] Blocking:{RESET}     {len(blocked)}/{total_probes} attack payloads — {DIM}likely mod_rewrite/mod_security basic rules, not a full WAF{RESET}")
            for b in blocked:
                waf_str = f" ({', '.join(b['waf_hits'])})" if b["waf_hits"] else ""
                _line(f"    {RED}BLOCKED{RESET}    [{b['status']}] {b['description']}{waf_str}")
            for r in redirected:
                _line(f"    {DIM}REDIRECT{RESET}   [{r['status']}] {r['description']}{RESET}")
            for p in passed:
                _line(f"    {YELLOW}PASSED{RESET}     [{p['status']}] {p['description']}")
        elif passed:
            _line(f"{YELLOW}[~] Blocking:{RESET}     {YELLOW}NONE{RESET} — {BOLD}no attack payloads blocked{RESET}")
            for p in passed:
                _line(f"    {YELLOW}PASSED{RESET}     [{p['status']}] {p['description']}")
    else:
        # No WAF signature, no server hardening detected
        plat = report.get("platform", {})
        if blocked and plat.get("is_saas"):
            pname = plat.get("platform_name", "Platform")
            _line(f"{YELLOW}[-] WAF Detected:{RESET} {BOLD}No{RESET}")
            _line(f"{YELLOW}[~] Platform Blocking:{RESET} {BOLD}{pname}{RESET} blocks {len(blocked)}/{total_probes} payloads — {DIM}built-in platform protection, not a configurable WAF{RESET}")
            for b in blocked:
                _line(f"    {RED}BLOCKED{RESET}    [{b['status']}] {b['description']} {DIM}({pname}){RESET}")
            for r in redirected:
                _line(f"    {DIM}REDIRECT{RESET}   [{r['status']}] {r['description']}{RESET}")
            for p in passed:
                _line(f"    {YELLOW}PASSED{RESET}     [{p['status']}] {p['description']}")
        elif blocked:
            _line(f"{YELLOW}[-] WAF Detected:{RESET} {BOLD}No{RESET}")
            _line(f"{YELLOW}[~] Server Blocking:{RESET} {len(blocked)}/{total_probes} payloads blocked — {DIM}server-level input validation, not a WAF{RESET}")
            for b in blocked:
                _line(f"    {RED}BLOCKED{RESET}    [{b['status']}] {b['description']} {DIM}(server){RESET}")
            for r in redirected:
                _line(f"    {DIM}REDIRECT{RESET}   [{r['status']}] {r['description']}{RESET}")
            for p in passed:
                _line(f"    {YELLOW}PASSED{RESET}     [{p['status']}] {p['description']}")
        else:
            _line(f"{GREEN}[-] WAF Detected:{RESET} {BOLD}No{RESET}")
            if passed:
                _line(f"{GREEN}[-] WAF Active:{RESET}   {BOLD}No{RESET} — all {len(passed)} attack payloads passed through")
            else:
                _line(f"{GREEN}[-] WAF Active:{RESET}   {BOLD}No{RESET}")

    # Protection gap analysis — only flag categories where payload clearly PASSED (200)
    # Redirects (301/302) are inconclusive — the payload may not have reached the app
    if blocked or passed:
        passed_cats = []
        blocked_cats = []
        for p in passed:
            cat = _ATTACK_CATEGORIES.get(p["description"])
            if cat:
                passed_cats.append(cat)
        for b in blocked:
            cat = _ATTACK_CATEGORIES.get(b["description"])
            if cat:
                blocked_cats.append(cat)
        critical_gaps = [c for c in passed_cats if c in _CRITICAL_CATEGORIES]
        if critical_gaps:
            _line(f"{RED}[!] Unprotected:{RESET}  {BOLD}{', '.join(critical_gaps)}{RESET} — {RED}critical attack vectors not blocked{RESET}")

    if cdn_names:
        unique_cdn = list(dict.fromkeys(cdn_names))
        _line(f"{YELLOW}[*] CDN:{RESET}          {', '.join(unique_cdn)}")

    # ── CONTEXTUAL INSIGHTS ──
    from .modules.intel import build_insights, identify_server
    insights = build_insights(report)
    if insights:
        _section("Insights", CYAN)
        for insight in insights:
            _line(f"{DIM}{insight}{RESET}")

    # HTTP
    http = report.get("http", {})
    if http and not http.get("error"):
        _section("HTTP Response", BLUE)
        _line(f"Status: {http.get('status', '?')}")
        server_header = http.get("server", "")
        if server_header:
            server_id = identify_server(server_header)
            if server_id:
                _line(f"Server: {CYAN}{server_header}{RESET} {DIM}({server_id[0]}){RESET}")
            else:
                _line(f"Server: {CYAN}{server_header}{RESET}")
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
        from .modules.intel import identify_cname_platform
        _section("CNAME Chain", BLUE)
        cname_platform = identify_cname_platform(report["cnames"])
        for c in report["cnames"]:
            _line(f"→ {c}")
        if cname_platform:
            _line(f"  {DIM}Platform: {cname_platform[0]} — {cname_platform[1]}{RESET}")

    # WAF/CDN/Server detections
    if report.get("waf"):
        has_real_waf = any(d["category"] in ("WAF", "CDN/WAF") for d in report["waf"])
        section_title = "WAF/CDN Detected" if has_real_waf else "Detections"
        _section(section_title, RED if has_real_waf else YELLOW)
        for det in report["waf"]:
            cat = det["category"]
            if cat == "Web Server":
                color = DIM
                label = "Server"
            elif cat in ("WAF", "CDN/WAF"):
                color = RED
                label = cat
            else:
                color = YELLOW
                label = cat
            conf_pct = f"{det['confidence']:.0%}"
            _line(f"{color}{det['name']:<22}{RESET} {DIM}[{label:<10}]{RESET} conf={BOLD}{conf_pct}{RESET}")
            if det.get("evidence"):
                _line(f"   {DIM}evidence: {', '.join(det['evidence'][:3])}{RESET}")

        # WAF tier info
        tier = report.get("waf_tier", {})
        if tier.get("tier") and tier["tier"] != "unknown":
            _line(f"\n   {YELLOW}Plan: {BOLD}{tier['tier']}{RESET} {DIM}(conf={tier.get('confidence', 0):.0%}){RESET}")
            for ev in tier.get("evidence", []):
                _line(f"   {DIM}  {ev}{RESET}")

    # Error Pages — split into attack payloads vs file access / error triggers
    ep = report.get("error_pages", {})
    ep_probes = ep.get("probes", [])
    if ep_probes:
        successful = [p for p in ep_probes if not p.get("error")]
        attack_probes = [p for p in successful if p.get("trigger") == "waf"]
        access_probes = [p for p in successful if p.get("trigger") != "waf"]

        if attack_probes:
            _section("Attack Payload Probes", RED)
            _line(f"{DIM}Real attack payloads — 403 = WAF blocked, 200 = passed through{RESET}")
            for p in attack_probes:
                st = p.get("status", "?")
                waf_trigger_statuses = {400, 403, 406, 429, 451, 493, 503}
                has_waf_hit = bool(p.get("waf_hits"))
                is_blocked = st in waf_trigger_statuses or (has_waf_hit and st not in (200, 201, 301, 302))

                # Determine who blocked: WAF or backend server?
                blocker = ""
                if is_blocked and p.get("waf_hits"):
                    # Check if the blocking WAF has WAF-specific headers (not just CDN presence)
                    probe_hdrs = p.get("headers", {})
                    _sigsci = any(k.lower().startswith("x-sigsci") for k in probe_hdrs)
                    _cf_block = any(k.lower() in ("cf-chl-bypass", "cf-mitigated") for k in probe_hdrs)
                    _akamai_block = any(k.lower() in ("x-akamai-session", "akamai-grn") for k in probe_hdrs)
                    if _sigsci:
                        blocker = f" {DIM}(Fastly WAF){RESET}"
                    elif _cf_block:
                        blocker = f" {DIM}(Cloudflare WAF){RESET}"
                    elif _akamai_block:
                        blocker = f" {DIM}(Akamai WAF){RESET}"
                    else:
                        # WAF signature present but no WAF-specific block headers
                        # Likely the backend server blocking, not the WAF
                        blocker = f" {DIM}(server){RESET}"
                elif is_blocked:
                    blocker = f" {DIM}(server){RESET}"

                if is_blocked:
                    icon, color = "⊘", RED
                    verdict = f"{RED}BLOCKED{RESET}{blocker}"
                elif st == 200:
                    # Check if this was a followed redirect that ended in 200
                    if p.get("final_status") == 200:
                        icon, color = "✓", GREEN
                        verdict = f"{YELLOW}PASSED{RESET} {DIM}(redirect followed → 200){RESET}"
                    else:
                        icon, color = "✓", GREEN
                        verdict = f"{YELLOW}PASSED{RESET}"
                elif st in (301, 302, 307, 308):
                    if p.get("redirect_payload_stripped"):
                        icon, color = "→", DIM
                        verdict = f"{DIM}REDIRECT{RESET} {DIM}(payload stripped — inconclusive){RESET}"
                    else:
                        icon, color = "→", YELLOW
                        verdict = f"{YELLOW}REDIRECT{RESET} {DIM}(inconclusive){RESET}"
                else:
                    icon, color = "·", DIM
                    verdict = f"{DIM}[{st}]{RESET}"
                _line(f"{color}{icon}{RESET} [{st}] {verdict} {p['path']:<40} {DIM}{p['description']}{RESET}")

        is_saas = ep.get("is_saas", False)
        if is_saas and not access_probes:
            _section("File Access Probes", DIM)
            _line(f"{DIM}Skipped — provider-hosted SaaS (server config not controlled by customer){RESET}")
        elif access_probes:
            _section("File Access & Error Probes", YELLOW)
            _line(f"{DIM}Server path access — 403/404 = normal server config, not WAF blocking{RESET}")
            # Collect globally-detected WAF/CDN names to filter out redundant tags
            global_waf_names = {d["name"] for d in report.get("waf", [])}
            for p in access_probes:
                st = p.get("status", "?")
                if st == 200: icon, color = "✓", GREEN
                elif st in (403, 400): icon, color = "·", DIM
                elif st == 404: icon, color = "·", DIM
                elif isinstance(st, int) and st >= 500: icon, color = "✗", RED
                else: icon, color = "·", DIM
                # Only show WAF tag if it's a NEW detection not already known globally
                waf_str = ""
                if p.get("waf_hits"):
                    new_hits = [w for w in p["waf_hits"] if w not in global_waf_names]
                    if new_hits:
                        waf_str = f"  {RED}← NEW: {', '.join(new_hits)}{RESET}"
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

    # Cert Hosting Classification
    cert_h = report.get("cert_hosting")
    if cert_h and cert_h.get("hosting_type", "UNKNOWN") != "UNKNOWN":
        ct = cert_h["hosting_type"]
        conf = cert_h.get("confidence", "low")
        type_color = {
            "VPS/DEDICATED": GREEN, "SHARED_HOSTING": YELLOW,
            "SAAS": CYAN, "MANAGED_HOSTING": CYAN, "CDN": RED,
        }.get(ct, DIM)
        _section("Hosting Type (cert analysis)", MAGENTA)
        _line(f"Type: {type_color}{BOLD}{ct}{RESET}  (confidence: {conf})")
        cert_no = cert_h.get("cert_no_sni")
        cert_sni = cert_h.get("cert_with_sni")
        if cert_no:
            _line(f"Default cert (no SNI): {cert_no['cn']}")
        if cert_sni:
            _line(f"SNI cert:              {cert_sni['cn']}")
        for sig in cert_h.get("signals", []):
            _line(f"{DIM}→ {sig}{RESET}")

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
