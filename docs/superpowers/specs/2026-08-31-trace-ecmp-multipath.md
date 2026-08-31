# Spec — ECMP / Multipath enumeration for `--trace`

Date: 2026-08-31
Status: Implemented (pending live verification)

## Goal

Make `--trace` discover **load-balanced (ECMP) paths** toward a target, not just a
single path. CDNs, WAFs and load balancers spread traffic across multiple next-hops
via ECMP; a classic traceroute only ever sees one branch and can miss alternate
edges / origin paths. This ports trippy's multipath idea onto WhatTheWAF's existing
subprocess traceroute backend — **no scapy, no raw sockets, no new dependencies.**

## Approach (subprocess-multipath, chosen over scapy)

GNU `traceroute` v2 is **Paris-consistent within a single run** (it keeps the L4
flow-id fixed, so every probe of one run follows the same ECMP branch). We enumerate
branches **Dublin-style** by running several traceroutes, each pinned to a *different*
fixed flow-id, and diffing the resulting paths.

Flow-id knob per environment:

| Environment            | Transport | Flow-id varied         | Root? |
|------------------------|-----------|------------------------|-------|
| Linux + root/setuid    | TCP:443   | source port (`--sport`) — dst stays 443 (realistic web traffic, penetrates CDN) | yes |
| Linux, no root         | UDP       | dest port (`-U -p N`)  | no    |
| Windows (`tracert`)    | —         | **unsupported** — ICMP-only, cannot set src/dst port or flow-id | — |

`--trace` runs multipath **always-on** (8 flows) for the primary domain. Direct-IP
traces (`--ip`) run single-path (`multipath=False`) to avoid an 8× blow-up per IP.

## Data model (added to `run_traceroute` result)

```
"paths":      [ {flow_id, transport, port, hops:[...]}, ... ]   # one per flow
"multipath": {
   "supported":     bool,
   "note":          str,          # when unsupported (e.g. Windows)
   "transport":     "tcp:443" | "udp",
   "flows_sent":    int,
   "distinct_paths":int,          # unique IP-per-hop signatures
   "divergence_hop":int | None,   # first TTL with >1 distinct next-hop
   "branches": { ttl: [ {ip, provider, asn, country, role, hostname, cdn_provider}, ... ] }
}
```

ASN + rDNS are looked up **once** over the union of primary-path and all-flow IPs
(one bulk Cymru query, one rDNS batch) — flows do not multiply network lookups.

## Components (all in `whatthewaf/modules/infra_trace.py`)

Parsers were lifted from nested closures to **module level** so they are unit-testable:

- `_tr_stats(rtts, timeouts)` — best/avg/worst/stddev/loss per hop.
- `_parse_mpls(text)` — GNU `-e` MPLS label stacks.
- `_parse_traceroute(text)` — GNU/BSD output (multi-probe, MPLS-aware).
- `_parse_tracert(text)` — Windows tracert (locale-independent).
- `_run_tr_cmd(cmd, parser, timeout, max_hops)` — subprocess runner.
- `_path_signature(hops)` — canonical path key (trailing timeouts trimmed).
- `_enumerate_multipath(domain, max_hops, timeout, is_root, on_status, flows)` — the flow fan-out.
- `_build_multipath_summary(paths, asn_map, rdns_map)` — divergence/branches map.

Rendering: `cli.py::_print_multipath(tr, color)` prints an "ECMP / Multipath" section
(distinct-path count, divergence hop, and per-balancer next-hop lists with ASN/role).

## Out of scope (YAGNI / not feasible via subprocess)

- **NAT detection** (Dublin proper): needs the returned IP-ID → raw sockets. Not done.
- TCP multipath on Windows. Not possible with `tracert`.

## Testing

`tests/test_trace_parsers.py` — dependency-free asserts for `_parse_traceroute`
(multi-probe + MPLS + partial/total loss), `_parse_tracert` (Spanish + `<1 ms`),
`_tr_stats`, `_path_signature`, and `_build_multipath_summary` divergence logic.
Live check: `python -m whatthewaf <domain> --trace`.
