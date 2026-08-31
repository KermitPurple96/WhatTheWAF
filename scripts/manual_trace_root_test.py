#!/usr/bin/env python3
"""Manual root test for the Linux-only trace paths (multipath + NAT detection).

Run as root on Linux (traceroute must be installed):
    sudo python3 scripts/manual_trace_root_test.py [domain]

Exercises the real raw-socket / flow-enumeration paths that can't run on Windows.
Only imports infra_trace + nat_detect (stdlib), so no project deps are needed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from whatthewaf.modules import infra_trace, nat_detect  # noqa: E402


def status(_tag, msg):
    print(f"  [*] {msg}", flush=True)


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    root = (os.geteuid() == 0)
    print(f"== target: {domain}   euid={os.geteuid()} ({'root' if root else 'NON-root'}) ==\n")

    # ── Primary path + ECMP multipath enumeration ──
    tr = infra_trace.run_traceroute(domain, multipath=True, on_status=status)
    print(f"\nmethods: {tr.get('methods')}  error: {tr.get('error')}")
    print(f"target_ip: {tr.get('target_ip')}")

    print("\n-- primary hops --")
    for h in tr.get("hops", []):
        prov = (h.get("provider") or "").split(",")[0][:22]
        mpls = f" MPLS={[m['label'] for m in h['mpls']]}" if h.get("mpls") else ""
        print(f"  {h['hop']:>2} {h['ip']:<18} loss={h.get('loss_pct')}% "
              f"avg={h.get('rtt_ms')} AS{h.get('asn') or '-'} {prov}{mpls}")

    mp = tr.get("multipath") or {}
    print("\n-- multipath / ECMP --")
    print(f"  supported={mp.get('supported')} transport={mp.get('transport')} "
          f"flows={mp.get('flows_sent')} distinct_paths={mp.get('distinct_paths')} "
          f"divergence_hop={mp.get('divergence_hop')}")
    if mp.get("note"):
        print(f"  note: {mp['note']}")
    for ttl, entries in sorted((mp.get("branches") or {}).items()):
        print(f"  hop {ttl}: {len(entries)} next-hops (load balancer)")
        for e in entries:
            print(f"     {e['ip']:<18} AS{e.get('asn') or '-'} "
                  f"{(e.get('provider') or '')[:24]} [{e.get('role')}]")

    # ── NAT detection ──
    print("\n-- NAT detection --")
    nat = nat_detect.detect_nat(domain, on_status=status)
    print(f"  supported={nat.get('supported')} note={nat.get('note')}")
    if nat.get("supported"):
        print(f"  src_ip={nat.get('src_ip')} dst_ip={nat.get('dst_ip')} "
              f"nat_detected={nat.get('nat_detected')}")
        for h in nat.get("hops", []):
            flag = "NAT" if h.get("nat") else "   "
            print(f"  {flag} hop {h['ttl']:>2} {h['router_ip']:<18} "
                  f"sent_id={h.get('sent_ip_id')} inner_id={h.get('inner_ip_id')} "
                  f"{h.get('reason','')}")


if __name__ == "__main__":
    main()
