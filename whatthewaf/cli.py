"""WhatTheWAF CLI — WAF/CDN Detection, Bypass Testing, TLS Fingerprint Evasion."""

import argparse
import json
import sys
import os

from . import __version__
from .scanner import origins_scan, full_scan, full_scan_batch

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

    # Handle proton-check / proton-rotate (no target needed)
    if args.proton_check:
        _run_proton_check()
        return
    if args.proton_rotate:
        _run_proton_rotate()
        return

    targets = _collect_targets(args)
    if not targets:
        parser.error("No targets specified.")

    if args.mode == "origins":
        _run_origins(targets, args)
    else:
        _run_full(targets, args)


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

    scan_kwargs = dict(
        timeout=args.timeout, scan_subs=not args.no_subs,
        check_cert=not args.no_cert, check_history=args.history,
        user_agent=args.user_agent, proxy=args.proxy, delay=args.delay,
        on_status=status_cb, check_tls=not args.no_tls,
        check_evasion=args.evasion, proxy_chain=args.proxy_chain,
        use_proton=args.proton,
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


def _print_report(report):
    print(f"\n{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}{CYAN}  WAF Recon: {report['target']}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}Summary:{RESET} {report['summary']}")

    # HTTP
    http = report.get("http", {})
    if http and not http.get("error"):
        print(f"\n{BOLD}HTTP Response:{RESET}")
        print(f"  Status: {http.get('status', '?')}")
        if http.get("server"): print(f"  Server: {CYAN}{http['server']}{RESET}")
        if http.get("url"): print(f"  URL: {http['url']}")
    elif http.get("error"):
        print(f"\n{RED}HTTP Error: {http['error']}{RESET}")

    # IPs + ASN
    if report.get("ips"):
        print(f"\n{BOLD}IP Addresses:{RESET}")
        for rec in report["ips"]:
            cls = rec["classification"]
            color = RED if cls == "CDN" else GREEN
            asn_str = f"AS{rec['asn']}" if rec.get("asn") else "AS?"
            print(f"  {rec['ip']:<16} {color}{asn_str:<10} {rec.get('provider', 'unknown')} {cls}{RESET}")

    # CNAME
    if report.get("cnames"):
        print(f"\n{BOLD}CNAME Chain:{RESET}")
        for c in report["cnames"]:
            print(f"  -> {c}")

    # WAF/CDN
    if report.get("waf"):
        print(f"\n{BOLD}WAF/CDN Detected:{RESET}")
        for det in report["waf"]:
            color = RED if det["category"] in ("WAF", "CDN/WAF") else YELLOW
            print(f"  {color}{det['name']:<25}{RESET} [{det['category']:<10}] conf={det['confidence']:.0%}  ({', '.join(det['evidence'][:3])})")

    # Error Pages
    ep = report.get("error_pages", {})
    ep_probes = ep.get("probes", [])
    if ep_probes:
        successful = [p for p in ep_probes if not p.get("error")]
        if successful:
            print(f"\n{BOLD}Error Page Probes:{RESET}")
            for p in successful:
                status = p.get("status", "?")
                color = GREEN if status == 200 else YELLOW if status == 403 else RED if status >= 500 else DIM
                waf_str = f"  {RED}WAF: {', '.join(p['waf_hits'])}{RESET}" if p.get("waf_hits") else ""
                print(f"  {color}[{status}]{RESET} {p['path']:<45} {DIM}{p['description']}{RESET}{waf_str}")

    # TLS Fingerprint
    tls = report.get("tls_fingerprint", {})
    if tls and not tls.get("error"):
        print(f"\n{BOLD}TLS Fingerprint Analysis:{RESET}")
        print(f"  TLS Version: {tls.get('our_tls_version', '?')}")
        print(f"  Cipher:      {tls.get('our_cipher', '?')}")
        print(f"  ALPN:        {tls.get('our_alpn', 'none')}")
        print(f"  Ciphers:     {tls.get('our_ciphers_count', '?')} offered")

        for diff in tls.get("browser_differences", []):
            print(f"  {YELLOW}[!]{RESET} {diff}")
        for rec in tls.get("recommendations", []):
            print(f"  {CYAN}[>]{RESET} {rec}")

        configs = tls.get("config_tests", [])
        if configs:
            print(f"\n  {BOLD}TLS Config Tests:{RESET}")
            for t in configs:
                status_str = f"{GREEN}accepted{RESET}" if t.get("accepted") else f"{RED}rejected{RESET}"
                if t.get("error"):
                    status_str = f"{DIM}{t['error']}{RESET}"
                sc = f" [{t.get('status_code', '?')}]" if t.get("status_code") else ""
                print(f"    {t['config']:<25} {status_str}{sc}")

    # WAF Evasion
    evasion = report.get("waf_evasion", {})
    if evasion and not evasion.get("error"):
        if evasion.get("findings") or evasion.get("ua_sensitive"):
            print(f"\n{BOLD}WAF Evasion Analysis:{RESET}")

            if evasion.get("ua_tests"):
                print(f"  {BOLD}User-Agent Tests:{RESET}")
                for t in evasion["ua_tests"]:
                    if t.get("different"):
                        color = RED if t.get("status_code") in (403, 406, 429, 503) else YELLOW
                        print(f"    {color}{t['ua_name']:<15} [{t.get('status_code', '?')}]{RESET} {DIM}{t['ua_string']}{RESET}")

            if evasion.get("encoding_tests"):
                changed = [t for t in evasion["encoding_tests"] if t.get("different")]
                if changed:
                    print(f"  {BOLD}Encoding Bypass:{RESET}")
                    for t in changed:
                        print(f"    {YELLOW}{t['name']:<25}{RESET} {t['path']:<15} [{t.get('status_code', '?')}]")

            for finding in evasion.get("findings", []):
                print(f"  {RED}[!]{RESET} {finding}")
            for rec in evasion.get("evasion_recommendations", []):
                print(f"  {CYAN}[>]{RESET} {rec}")

    # Proxy Effectiveness
    proxy_eff = report.get("proxy_effectiveness", {})
    if proxy_eff.get("proxy_results"):
        print(f"\n{BOLD}Proxy Effectiveness:{RESET}")
        bl = proxy_eff.get("baseline", {})
        if bl and not bl.get("error"):
            print(f"  Baseline: [{bl.get('status_code', '?')}] hash={bl.get('body_hash', '?')}")
        for pr in proxy_eff["proxy_results"]:
            color = GREEN if pr.get("status_changed") else DIM
            err = f" {RED}error: {pr['error']}{RESET}" if pr.get("error") else ""
            print(f"  {color}{pr['proxy']:<40} [{pr.get('status_code', '?')}] hash={pr.get('body_hash', '?')}{RESET}{err}")
        for f in proxy_eff.get("findings", []):
            print(f"  {YELLOW}[!]{RESET} {f}")

    # SSL Cert
    if report.get("cert_info"):
        cert = report["cert_info"]
        print(f"\n{BOLD}SSL Certificate:{RESET}")
        print(f"  CN:     {cert.get('common_name', '?')}")
        print(f"  Issuer: {cert.get('issuer', '?')}")
        if cert.get("is_cdn_issued"):
            print(f"  {YELLOW}Certificate issued by CDN provider{RESET}")

    # Origin candidates
    if report.get("origin_candidates"):
        print(f"\n{BOLD}{GREEN}Potential Origin IPs (subdomain leakage):{RESET}")
        for c in report["origin_candidates"]:
            asn_str = c["asn_info"].get("provider", "") if c.get("asn_info") else ""
            print(f"  {GREEN}{c['ip']:<16}{RESET} via {c['source']:<35} {asn_str}")

    # WAF Bypass
    bypass = report.get("waf_bypass", {})
    if bypass.get("findings"):
        print(f"\n{BOLD}{RED}WAF Bypass Testing:{RESET}")
        bl = bypass.get("baseline", {})
        if bl and not bl.get("error"):
            print(f"  Baseline: [{bl.get('status_code', '?')}] hash={bl.get('body_hash', '?')}")

        for f in bypass["findings"]:
            sev = f.get("severity", "info")
            color = f"{BOLD}{RED}" if sev == "critical" else RED if sev == "high" else YELLOW
            print(f"\n  {color}[{sev.upper()}]{RESET} {f['detail']}")
            if f.get("curl"):
                print(f"  {BOLD}PoC:{RESET}")
                for line in f["curl"].split("\n"):
                    print(f"    {CYAN}{line}{RESET}")
            if f.get("curl_resolve"):
                print(f"  {BOLD}PoC (--resolve):{RESET}")
                for line in f["curl_resolve"].split("\n"):
                    print(f"    {CYAN}{line}{RESET}")

    elif bypass.get("ip_tests"):
        accessible = [t for t in bypass["ip_tests"] if t.get("accessible")]
        if not accessible:
            print(f"\n{BOLD}WAF Bypass:{RESET} {GREEN}No direct IP access — origin protected{RESET}")

    # Historical
    if report.get("historical_ips"):
        print(f"\n{BOLD}Historical DNS:{RESET}")
        for rec in report["historical_ips"][:10]:
            print(f"  {rec['ip']:<16} {rec['owner']:<30} last_seen={rec['last_seen']}")

    print()


def _write_output(content, filepath):
    if filepath:
        with open(filepath, "w") as f: f.write(content)
        print(f"{GREEN}[+] Results written to {filepath}{RESET}", file=sys.stderr)
    else:
        print(content)


if __name__ == "__main__":
    main()
