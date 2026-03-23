"""WhatTheWAF CLI — detect WAF, CDN, technologies, and origin IPs."""

import argparse
import json
import sys
import os

from . import __version__
from .scanner import origins_scan, full_scan

# ANSI colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
BOLD = "\033[1m"
RESET = "\033[0m"

def _load_banner():
    """Load ASCII banner from file next to the project root."""
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
  whatthewaf example.com --mode origins
  whatthewaf -l domains.txt --json
  cat subs.txt | whatthewaf --stdin --mode origins
  whatthewaf example.com --full --history
        """,
    )
    parser.add_argument("targets", nargs="*", help="Domain(s), IP(s), or @file.txt")
    parser.add_argument("--stdin", action="store_true", help="Read targets from stdin")
    parser.add_argument("-l", "--list", metavar="FILE", help="Read targets from file")
    parser.add_argument(
        "-m", "--mode",
        choices=["origins", "full", "alive"],
        default="full",
        help="Scan mode: origins (quick ASN) | full (deep recon) | alive (httpx probe)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write results to file")
    parser.add_argument("--no-subs", action="store_true", help="Skip subdomain leakage scan")
    parser.add_argument("--no-cert", action="store_true", help="Skip SSL certificate check")
    parser.add_argument("--history", action="store_true", help="Check historical DNS records")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    parser.add_argument("-v", "--version", action="version", version=f"WhatTheWAF {__version__}")

    args = parser.parse_args()

    # Suppress urllib3 InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not args.quiet and not args.no_banner:
        print(_load_banner(), file=sys.stderr)

    # Collect targets
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
    """Gather targets from all input sources."""
    targets = []

    # From stdin
    if args.stdin or not sys.stdin.isatty():
        if args.stdin or (not args.targets and not args.list):
            for line in sys.stdin:
                t = line.strip()
                if t:
                    targets.append(t)

    # From file (-l)
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

    # From positional args
    for t in (args.targets or []):
        if t.startswith("@"):
            # @file.txt syntax
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
    """Run origins mode — quick ASN classification."""
    rows = origins_scan(targets)

    if args.json:
        output = json.dumps(rows, indent=2)
        _write_output(output, args.output)
        return

    # Colored table output — matches the origins() shell function style
    print()
    print(
        f"{BLUE}{'Subdomain':<35} {'IP':<16} {'Provider':<45} {'Type'}{RESET}"
    )
    print("-" * 110)

    for row in rows:
        cls = row["classification"]
        if cls == "CDN":
            color = RED
        elif cls == "ORIGIN?":
            color = GREEN
        else:
            color = YELLOW

        # Build provider string like: BGP_PREFIX | CC | registry | allocated | AS_NAME, CC
        provider_parts = []
        if row.get("bgp_prefix"):
            provider_parts.append(row["bgp_prefix"])
        provider_parts.append(row.get("country", "??"))
        if row.get("registry"):
            provider_parts.append(row["registry"])
        if row.get("allocated"):
            provider_parts.append(row["allocated"])
        provider_parts.append(row.get("provider", "unknown"))
        provider_str = " | ".join(provider_parts)

        print(
            f"{YELLOW}{row['domain']:<35}{RESET} {row['ip']:<16}"
            f"{color}{provider_str} {cls:<8}{RESET}"
        )

    print()
    _write_output(json.dumps(rows, indent=2), args.output) if args.output else None


def run_alive(targets, args):
    """Run alive check using httpx."""
    from .modules.alive_check import check_alive

    results = check_alive(targets, timeout=args.timeout)

    if args.json:
        output = json.dumps(results, indent=2)
        _write_output(output, args.output)
        return

    alive_count = sum(1 for r in results if r["alive"])
    dead_count = len(results) - alive_count

    print()
    print(f"{BLUE}{'Target':<35} {'Status':<8} {'Code':<6} {'Title':<40} {'URL'}{RESET}")
    print("-" * 120)

    for r in results:
        if r["alive"]:
            color = GREEN
            status = "ALIVE"
        else:
            color = RED
            status = "DEAD"

        code = str(r["status_code"]) if r["status_code"] else "-"
        title = r.get("title", "")[:38]
        url = r.get("final_url", "") or r.get("url", "")
        redirect = f" -> {r['final_url']}" if r.get("redirect") else ""

        print(
            f"{YELLOW}{r['target']:<35}{RESET} "
            f"{color}{status:<8}{RESET} {code:<6} {CYAN}{title:<40}{RESET} {url}"
        )

    print()
    print(f"{GREEN}Alive: {alive_count}{RESET} | {RED}Dead: {dead_count}{RESET} | Total: {len(results)}")
    print()

    _write_output(json.dumps(results, indent=2), args.output) if args.output else None


def run_full(targets, args):
    """Run full recon scan."""
    reports = []

    for target in targets:
        print(f"{CYAN}[*] Scanning {target}...{RESET}", file=sys.stderr)
        try:
            report = full_scan(
                target,
                timeout=args.timeout,
                scan_subs=not args.no_subs,
                check_cert=not args.no_cert,
                check_history=args.history,
            )
            reports.append(report)

            if not args.json:
                print_report(report)
        except Exception as e:
            print(f"{RED}[!] Error scanning {target}: {e}{RESET}", file=sys.stderr)
            reports.append({"target": target, "error": str(e)})

    if args.json:
        output = json.dumps(reports, indent=2, default=str)
        _write_output(output, args.output)
    elif args.output:
        _write_output(json.dumps(reports, indent=2, default=str), args.output)


def print_report(report):
    """Pretty-print a full scan report."""
    print()
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Recon: {report['target']}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}Summary:{RESET} {report['summary']}")

    # HTTP response info
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
    elif http.get("error"):
        print(f"\n{RED}HTTP Error: {http['error']}{RESET}")

    # IPs + ASN (full origins-style output)
    if report.get("ips"):
        print(f"\n{BOLD}IP Addresses:{RESET}")
        for rec in report["ips"]:
            cls = rec["classification"]
            if cls == "CDN":
                color = RED
            elif cls == "ORIGIN?":
                color = GREEN
            else:
                color = YELLOW
            # Full Cymru-style: BGP | CC | registry | allocated | AS Name
            parts = []
            if rec.get("bgp_prefix"):
                parts.append(rec["bgp_prefix"])
            parts.append(rec.get("country", "??"))
            if rec.get("registry"):
                parts.append(rec["registry"])
            if rec.get("allocated"):
                parts.append(rec["allocated"])
            parts.append(rec.get("provider", "unknown"))
            provider_str = " | ".join(parts)
            asn_str = f"AS{rec['asn']}" if rec.get("asn") else "AS?"
            # Geo info
            geo = rec.get("geo", {})
            geo_str = ""
            if geo and geo.get("city"):
                geo_str = f" [{geo['city']}, {geo.get('region', '')}, {geo.get('country', '')}]"
            elif geo and geo.get("country"):
                geo_str = f" [{geo['country']}]"
            print(
                f"  {rec['ip']:<16} {color}{asn_str:<10} {provider_str} {cls}{RESET}{geo_str}"
            )

    # CNAME chain
    if report.get("cnames"):
        print(f"\n{BOLD}CNAME Chain:{RESET}")
        for cname in report["cnames"]:
            print(f"  -> {cname}")

    # WAF/CDN detections
    if report.get("waf"):
        print(f"\n{BOLD}WAF/CDN Detected:{RESET}")
        for det in report["waf"]:
            if det["category"] in ("WAF", "CDN/WAF"):
                color = RED
            else:
                color = YELLOW
            print(
                f"  {color}{det['name']:<25}{RESET} [{det['category']:<10}] "
                f"conf={det['confidence']:.0%}  ({', '.join(det['evidence'][:3])})"
            )

    # Technologies
    if report.get("technologies"):
        print(f"\n{BOLD}Technologies:{RESET}")
        for tech in report["technologies"]:
            version = tech.get("version", "")
            name = tech["name"]
            if version:
                # Name in cyan, version in yellow, then category
                visible_len = len(name) + 1 + len(version)
                pad = " " * max(35 - visible_len, 1)
                print(
                    f"  {CYAN}{name}{RESET} {YELLOW}{version}{RESET}{pad} [{tech['category']:<12}]"
                )
            else:
                print(
                    f"  {CYAN}{name:<35}{RESET} [{tech['category']:<12}]"
                )

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

    # Origin candidates
    if report.get("origin_candidates"):
        print(f"\n{BOLD}{GREEN}Potential Origin IPs (subdomain leakage):{RESET}")
        for c in report["origin_candidates"]:
            asn_str = ""
            if c.get("asn_info"):
                a = c["asn_info"]
                asn_str = f"{a.get('provider', '')} [{a.get('country', '??')}]"
            print(
                f"  {GREEN}{c['ip']:<16}{RESET} via {c['source']:<35} {asn_str}"
            )

    # Historical IPs
    if report.get("historical_ips"):
        print(f"\n{BOLD}Historical DNS Records:{RESET}")
        for rec in report["historical_ips"][:10]:
            print(
                f"  {rec['ip']:<16} {rec['owner']:<30} last_seen={rec['last_seen']}"
            )

    print()


def _write_output(content, filepath):
    """Write content to file or stdout."""
    if filepath:
        with open(filepath, "w") as f:
            f.write(content)
        print(f"{GREEN}[+] Results written to {filepath}{RESET}", file=sys.stderr)
    else:
        print(content)


if __name__ == "__main__":
    main()
