"""WhatTheWAF CLI — detect WAF, CDN, technologies, and origin IPs."""

import argparse
import json
import sys
import os

from . import __version__
from .scanner import origins_scan, full_scan, full_scan_batch

# ANSI colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _load_banner():
    banner_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ascii"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "ascii"),
    ]
    for path in banner_paths:
        try:
            with open(path) as f:
                art = f.read().rstrip()
            return (
                f"{CYAN}{BOLD}{art}{RESET}\n"
                f"  {YELLOW}v{__version__}{RESET}  "
                f"{MAGENTA}WAF/CDN Detection | Tech Fingerprinting | Origin Discovery{RESET}\n"
            )
        except FileNotFoundError:
            continue
    return f"{CYAN}{BOLD}WhatTheWAF{RESET} {YELLOW}v{__version__}{RESET}\n"


def main():
    parser = argparse.ArgumentParser(
        description="WhatTheWAF - Detect WAF, CDN, technologies, and origin IPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  whatthewaf example.com
  whatthewaf example.com -m origins
  whatthewaf -l domains.txt -m alive
  whatthewaf example.com --json -o report.json
  whatthewaf example.com --history --proxy socks5://127.0.0.1:9050
  cat subs.txt | whatthewaf --stdin -m origins
        """,
    )
    parser.add_argument("targets", nargs="*", help="Domain(s), IP(s), or @file.txt")
    parser.add_argument("--stdin", action="store_true", help="Read targets from stdin")
    parser.add_argument("-l", "--list", metavar="FILE", help="Read targets from file")
    parser.add_argument(
        "-m", "--mode",
        choices=["origins", "full", "alive"],
        default="full",
        help="Scan mode: origins | full | alive (default: full)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write results to file")
    parser.add_argument("--no-subs", action="store_true", help="Skip subdomain leakage scan")
    parser.add_argument("--no-cert", action="store_true", help="Skip SSL certificate check")
    parser.add_argument("--history", action="store_true", help="Check historical DNS records")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--proxy", metavar="URL", help="HTTP/SOCKS proxy (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("--user-agent", metavar="UA", help="Custom User-Agent string")
    parser.add_argument("--delay", type=float, default=0, help="Delay between targets in seconds")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent workers for batch scanning")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    parser.add_argument("-v", "--version", action="version", version=f"WhatTheWAF {__version__}")

    args = parser.parse_args()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not args.quiet and not args.no_banner:
        print(_load_banner(), file=sys.stderr)

    targets = collect_targets(args)
    if not targets:
        parser.error("No targets specified. Provide domains, IPs, -l file, or --stdin")

    if args.mode == "origins":
        run_origins(targets, args)
    elif args.mode == "alive":
        run_alive(targets, args)
    else:
        run_full(targets, args)


def collect_targets(args):
    targets = []
    if args.stdin or not sys.stdin.isatty():
        if args.stdin or (not args.targets and not args.list):
            for line in sys.stdin:
                t = line.strip()
                if t:
                    targets.append(t)
    if args.list:
        try:
            with open(args.list) as f:
                for line in f:
                    t = line.strip()
                    if t and not t.startswith("#"):
                        targets.append(t)
        except FileNotFoundError:
            print(f"{RED}[!] File not found: {args.list}{RESET}", file=sys.stderr)
            sys.exit(1)
    for t in (args.targets or []):
        if t.startswith("@"):
            path = t[1:]
            try:
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            targets.append(line)
            except FileNotFoundError:
                print(f"{RED}[!] File not found: {path}{RESET}", file=sys.stderr)
                sys.exit(1)
        else:
            targets.append(t)
    return targets


def run_origins(targets, args):
    rows = origins_scan(targets)
    if args.json:
        _write_output(json.dumps(rows, indent=2), args.output)
        return
    print()
    print(f"{BLUE}{'Subdomain':<35} {'IP':<16} {'Provider':<45} {'Type'}{RESET}")
    print("-" * 110)
    for row in rows:
        cls = row["classification"]
        color = RED if cls == "CDN" else GREEN if cls == "ORIGIN?" else YELLOW
        parts = []
        if row.get("bgp_prefix"):
            parts.append(row["bgp_prefix"])
        parts.append(row.get("country", "??"))
        if row.get("registry"):
            parts.append(row["registry"])
        if row.get("allocated"):
            parts.append(row["allocated"])
        parts.append(row.get("provider", "unknown"))
        print(f"{YELLOW}{row['domain']:<35}{RESET} {row['ip']:<16}{color}{' | '.join(parts)} {cls:<8}{RESET}")
    print()
    if args.output:
        _write_output(json.dumps(rows, indent=2), args.output)


def run_alive(targets, args):
    from .modules.alive_check import check_alive
    results = check_alive(targets, timeout=args.timeout)
    if args.json:
        _write_output(json.dumps(results, indent=2), args.output)
        return
    alive_count = sum(1 for r in results if r["alive"])
    print()
    print(f"{BLUE}{'Target':<35} {'Status':<8} {'Code':<6} {'Title':<40} {'URL'}{RESET}")
    print("-" * 120)
    for r in results:
        color = GREEN if r["alive"] else RED
        status = "ALIVE" if r["alive"] else "DEAD"
        code = str(r["status_code"]) if r["status_code"] else "-"
        title = r.get("title", "")[:38]
        url = r.get("final_url", "") or r.get("url", "")
        print(f"{YELLOW}{r['target']:<35}{RESET} {color}{status:<8}{RESET} {code:<6} {CYAN}{title:<40}{RESET} {url}")
    print()
    print(f"{GREEN}Alive: {alive_count}{RESET} | {RED}Dead: {len(results) - alive_count}{RESET} | Total: {len(results)}")
    print()
    if args.output:
        _write_output(json.dumps(results, indent=2), args.output)


def run_full(targets, args):
    reports = []
    scan_kwargs = dict(
        timeout=args.timeout,
        scan_subs=not args.no_subs,
        check_cert=not args.no_cert,
        check_history=args.history,
        user_agent=args.user_agent,
        proxy=args.proxy,
        delay=args.delay,
    )

    if args.workers > 1 and len(targets) > 1:
        print(f"{CYAN}[*] Scanning {len(targets)} targets with {args.workers} workers...{RESET}", file=sys.stderr)
        reports = full_scan_batch(targets, max_workers=args.workers, **scan_kwargs)
        if not args.json:
            for report in reports:
                if "error" in report and "target" in report:
                    print(f"{RED}[!] Error scanning {report['target']}: {report['error']}{RESET}", file=sys.stderr)
                else:
                    print_report(report)
    else:
        for target in targets:
            print(f"{CYAN}[*] Scanning {target}...{RESET}", file=sys.stderr)
            try:
                report = full_scan(target, **scan_kwargs)
                reports.append(report)
                if not args.json:
                    print_report(report)
            except Exception as e:
                print(f"{RED}[!] Error scanning {target}: {e}{RESET}", file=sys.stderr)
                reports.append({"target": target, "error": str(e)})

    if args.json:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)
    elif args.output:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)


def print_report(report):
    print()
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}{CYAN}  Recon: {report['target']}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}Summary:{RESET} {report['summary']}")

    # HTTP Response
    http = report.get("http", {})
    if http and not http.get("error"):
        print(f"\n{BOLD}HTTP Response:{RESET}")
        print(f"  Status: {http.get('status', '?')}")
        if http.get("server"):
            print(f"  Server: {CYAN}{http['server']}{RESET}")
        if http.get("content_type"):
            print(f"  Content-Type: {http['content_type']}")
        if http.get("url"):
            print(f"  URL: {http['url']}")
        if report.get("response_hash"):
            print(f"  Body SHA256: {DIM}{report['response_hash'][:16]}...{RESET}")
    elif http.get("error"):
        print(f"\n{RED}HTTP Error: {http['error']}{RESET}")

    # Redirect chain
    chain = report.get("redirect_chain", [])
    if chain and len(chain) > 1:
        print(f"\n{BOLD}Redirect Chain:{RESET}")
        for i, hop in enumerate(chain):
            marker = "  ->" if i > 0 else "  "
            status = hop.get("status_code", "?")
            print(f"  {marker} [{status}] {hop.get('url', '?')}")

    # IPs + ASN + Geo
    if report.get("ips"):
        print(f"\n{BOLD}IP Addresses:{RESET}")
        for rec in report["ips"]:
            cls = rec["classification"]
            color = RED if cls == "CDN" else GREEN if cls == "ORIGIN?" else YELLOW
            parts = []
            if rec.get("bgp_prefix"):
                parts.append(rec["bgp_prefix"])
            parts.append(rec.get("country", "??"))
            if rec.get("registry"):
                parts.append(rec["registry"])
            if rec.get("allocated"):
                parts.append(rec["allocated"])
            parts.append(rec.get("provider", "unknown"))
            asn_str = f"AS{rec['asn']}" if rec.get("asn") else "AS?"
            geo = rec.get("geo", {})
            geo_str = ""
            if geo and geo.get("city"):
                geo_str = f" [{geo['city']}, {geo.get('region', '')}, {geo.get('country', '')}]"
            elif geo and geo.get("country"):
                geo_str = f" [{geo['country']}]"
            print(f"  {rec['ip']:<16} {color}{asn_str:<10} {' | '.join(parts)} {cls}{RESET}{geo_str}")

    # Open ports
    if report.get("open_ports"):
        print(f"\n{BOLD}Open Ports:{RESET}")
        for p in report["open_ports"]:
            print(f"  {GREEN}{p['port']:<8}{RESET} {p['service']}")

    # CNAME chain
    if report.get("cnames"):
        print(f"\n{BOLD}CNAME Chain:{RESET}")
        for cname in report["cnames"]:
            print(f"  -> {cname}")

    # DNS Deep
    dns_deep = report.get("dns_deep", {})
    if dns_deep:
        show_dns = False
        if dns_deep.get("ns_records") or dns_deep.get("mx_records") or dns_deep.get("verified_services") or dns_deep.get("spf") or dns_deep.get("dmarc"):
            show_dns = True
        if show_dns:
            print(f"\n{BOLD}DNS Intelligence:{RESET}")
            if dns_deep.get("ns_providers"):
                print(f"  NS Provider: {CYAN}{', '.join(dns_deep['ns_providers'])}{RESET}")
            if dns_deep.get("ns_records"):
                print(f"  NS Records:  {', '.join(dns_deep['ns_records'][:4])}")
            if dns_deep.get("mail_providers"):
                print(f"  Mail:        {CYAN}{', '.join(dns_deep['mail_providers'])}{RESET}")
            if dns_deep.get("mx_records"):
                print(f"  MX Records:  {', '.join(dns_deep['mx_records'][:4])}")
            if dns_deep.get("spf"):
                spf = dns_deep["spf"]
                print(f"  SPF Policy:  {spf['policy']}")
                if spf.get("includes"):
                    print(f"  SPF Include: {', '.join(spf['includes'][:5])}")
            if dns_deep.get("dmarc"):
                dmarc = dns_deep["dmarc"]
                print(f"  DMARC:       p={dmarc.get('policy', '?')} rua={dmarc.get('rua', 'none')}")
            if dns_deep.get("verified_services"):
                print(f"  Verified:    {CYAN}{', '.join(dns_deep['verified_services'])}{RESET}")

    # WHOIS
    whois = report.get("whois", {})
    if whois and whois.get("registrar"):
        print(f"\n{BOLD}WHOIS:{RESET}")
        print(f"  Registrar:  {whois['registrar']}")
        if whois.get("creation_date"):
            print(f"  Created:    {whois['creation_date']}")
        if whois.get("expiry_date"):
            print(f"  Expires:    {whois['expiry_date']}")
        if whois.get("updated_date"):
            print(f"  Updated:    {whois['updated_date']}")

    # WAF/CDN detections
    if report.get("waf"):
        print(f"\n{BOLD}WAF/CDN Detected:{RESET}")
        for det in report["waf"]:
            color = RED if det["category"] in ("WAF", "CDN/WAF") else YELLOW
            print(f"  {color}{det['name']:<25}{RESET} [{det['category']:<10}] conf={det['confidence']:.0%}  ({', '.join(det['evidence'][:3])})")

    # Technologies
    if report.get("technologies"):
        print(f"\n{BOLD}Technologies:{RESET}")
        for tech in report["technologies"]:
            version = tech.get("version", "")
            name = tech["name"]
            if version:
                visible_len = len(name) + 1 + len(version)
                pad = " " * max(35 - visible_len, 1)
                print(f"  {CYAN}{name}{RESET} {YELLOW}{version}{RESET}{pad} [{tech['category']:<12}]")
            else:
                print(f"  {CYAN}{name:<35}{RESET} [{tech['category']:<12}]")

    # Security Headers
    sec = report.get("security_headers", {})
    if sec and sec.get("grade"):
        grade = sec["grade"]
        grade_color = GREEN if grade in ("A", "B") else YELLOW if grade == "C" else RED
        print(f"\n{BOLD}Security Headers:{RESET} {grade_color}Grade {grade}{RESET} ({sec['score']}/{sec['max_score']})")
        if sec.get("present"):
            for h in sec["present"]:
                color = GREEN
                warn = ""
                if h.get("warnings"):
                    color = YELLOW
                    warn = f" {DIM}({'; '.join(h['warnings'][:1])}){RESET}"
                print(f"  {color}[+]{RESET} {h['name']}{warn}")
        if sec.get("missing"):
            for h in sec["missing"]:
                sev_color = RED if h["severity"] == "high" else YELLOW if h["severity"] == "medium" else DIM
                print(f"  {sev_color}[-]{RESET} {h['name']} {DIM}({h['severity']}){RESET}")
        if sec.get("info_leaks"):
            print(f"  {YELLOW}Info leaks:{RESET}")
            for leak in sec["info_leaks"]:
                print(f"    {leak['name']}: {leak['value']} {DIM}({leak['description']}){RESET}")

    # SSL Certificate
    if report.get("cert_info"):
        cert = report["cert_info"]
        print(f"\n{BOLD}SSL Certificate:{RESET}")
        print(f"  CN:     {cert['common_name']}")
        print(f"  Issuer: {cert['issuer']}")
        if cert.get("is_cdn_issued"):
            print(f"  {YELLOW}Certificate issued by CDN provider{RESET}")
        if cert.get("alt_names"):
            names = cert["alt_names"]
            if len(names) <= 8:
                print(f"  SANs:   {', '.join(names)}")
            else:
                print(f"  SANs:   {len(names)} entries ({', '.join(names[:5])}, ...)")

    # Robots.txt
    robots = report.get("robots", {})
    if robots and robots.get("exists"):
        print(f"\n{BOLD}robots.txt:{RESET}")
        if robots.get("interesting"):
            print(f"  {RED}Interesting paths:{RESET}")
            for p in robots["interesting"][:10]:
                print(f"    {p}")
        if robots.get("sitemaps"):
            print(f"  Sitemaps: {', '.join(robots['sitemaps'][:3])}")
        if robots.get("disallowed") and not robots.get("interesting"):
            print(f"  {len(robots['disallowed'])} disallowed paths")

    # Origin candidates
    if report.get("origin_candidates"):
        print(f"\n{BOLD}{GREEN}Potential Origin IPs (subdomain leakage):{RESET}")
        for c in report["origin_candidates"]:
            asn_str = ""
            if c.get("asn_info"):
                a = c["asn_info"]
                asn_str = f"{a.get('provider', '')} [{a.get('country', '??')}]"
            print(f"  {GREEN}{c['ip']:<16}{RESET} via {c['source']:<35} {asn_str}")

    # Historical IPs
    if report.get("historical_ips"):
        print(f"\n{BOLD}Historical DNS Records:{RESET}")
        for rec in report["historical_ips"][:10]:
            print(f"  {rec['ip']:<16} {rec['owner']:<30} last_seen={rec['last_seen']}")

    print()


def _write_output(content, filepath):
    if filepath:
        with open(filepath, "w") as f:
            f.write(content)
        print(f"{GREEN}[+] Results written to {filepath}{RESET}", file=sys.stderr)
    else:
        print(content)


if __name__ == "__main__":
    main()
