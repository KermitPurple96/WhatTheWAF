"""Dependency-free tests for the traceroute parsers and ECMP divergence logic.

Run:  python tests/test_trace_parsers.py
Exits non-zero on the first failed assertion.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from whatthewaf.modules.infra_trace import (  # noqa: E402
    _tr_stats, _parse_traceroute, _parse_tracert, _parse_mpls,
    _path_signature, _build_multipath_summary,
)


def approx(a, b, tol=0.01):
    return a is not None and abs(a - b) <= tol


# ── _tr_stats ───────────────────────────────────────────────────────────────
def test_stats():
    s = _tr_stats([1.234, 1.111, 1.0], 0)
    assert s["sent"] == 3 and s["recv"] == 3 and s["loss_pct"] == 0.0
    assert approx(s["best_ms"], 1.0) and approx(s["worst_ms"], 1.234)
    assert approx(s["avg_ms"], 1.115) and approx(s["rtt_ms"], 1.115)

    s = _tr_stats([5.0, 6.0], 1)          # one probe timed out
    assert s["sent"] == 3 and s["recv"] == 2 and s["loss_pct"] == 33.3
    assert approx(s["best_ms"], 5.0) and approx(s["worst_ms"], 6.0)

    s = _tr_stats([], 3)                   # all timed out
    assert s["recv"] == 0 and s["loss_pct"] == 100.0 and s["rtt_ms"] is None


# ── _parse_mpls ──────────────────────────────────────────────────────────────
def test_mpls():
    labels = _parse_mpls("10.1 ms <MPLS:L=24012,E=0,S=1,T=1>  9.8 ms")
    assert labels == [{"label": 24012, "exp": 0, "s": 1, "ttl": 1}]
    assert _parse_mpls("no labels here 1.0 ms") == []


# ── _parse_traceroute (GNU/BSD) ──────────────────────────────────────────────
UNIX_OUT = """traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.111 ms  1.000 ms
 2  10.0.0.1  5.0 ms  * 6.0 ms
 3  * * *
 4  72.14.1.1  10.1 ms <MPLS:L=24012,E=0,S=1,T=1>  9.8 ms  11.2 ms
 5  93.184.216.34  20.0 ms  20.5 ms  19.5 ms
"""


def test_parse_unix():
    hops = _parse_traceroute(UNIX_OUT)
    assert [h["hop"] for h in hops] == [1, 2, 3, 4, 5]

    h1 = hops[0]
    assert h1["ip"] == "192.168.1.1" and h1["recv"] == 3 and h1["loss_pct"] == 0.0

    h2 = hops[1]
    assert h2["ip"] == "10.0.0.1" and h2["recv"] == 2 and h2["loss_pct"] == 33.3

    h3 = hops[2]
    assert h3["ip"] == "*" and h3["loss_pct"] == 100.0

    h4 = hops[3]
    assert h4["ip"] == "72.14.1.1" and h4["recv"] == 3
    assert h4.get("mpls") == [{"label": 24012, "exp": 0, "s": 1, "ttl": 1}]

    assert hops[4]["ip"] == "93.184.216.34"


# ── _parse_tracert (Windows, Spanish locale + "<1 ms") ───────────────────────
WIN_OUT = """
Traza a la direccion example.com [93.184.216.34]
sobre un maximo de 30 saltos:

  1     1 ms    <1 ms     1 ms  192.168.1.1
  2     *        *        *     Tiempo de espera agotado para esta solicitud.
  3    10 ms    11 ms    12 ms  93.184.216.34

Traza completa.
"""


def test_parse_tracert():
    hops = _parse_tracert(WIN_OUT)
    assert [h["hop"] for h in hops] == [1, 2, 3]
    assert hops[0]["ip"] == "192.168.1.1" and hops[0]["recv"] == 3
    assert hops[1]["ip"] == "*" and hops[1]["loss_pct"] == 100.0
    assert hops[2]["ip"] == "93.184.216.34" and hops[2]["recv"] == 3


# ── _path_signature ──────────────────────────────────────────────────────────
def test_signature():
    assert _path_signature([{"ip": "1.1.1.1"}, {"ip": "*"}, {"ip": "*"}]) == ("1.1.1.1",)
    assert _path_signature(
        [{"ip": "1.1.1.1"}, {"ip": "*"}, {"ip": "2.2.2.2"}]
    ) == ("1.1.1.1", "*", "2.2.2.2")


# ── _build_multipath_summary (divergence detection) ──────────────────────────
def test_multipath_summary():
    # TEST-NET public IPs; ttl 2 is the load balancer (two distinct next-hops).
    paths = [
        {"flow_id": 0, "hops": [{"hop": 1, "ip": "203.0.113.1"},
                                {"hop": 2, "ip": "198.51.100.1"},
                                {"hop": 3, "ip": "93.184.216.34"}]},
        {"flow_id": 1, "hops": [{"hop": 1, "ip": "203.0.113.1"},
                                {"hop": 2, "ip": "198.51.100.2"},
                                {"hop": 3, "ip": "93.184.216.34"}]},
    ]
    s = _build_multipath_summary(paths, asn_map={}, rdns_map={})
    assert s["flows_sent"] == 2
    assert s["distinct_paths"] == 2
    assert s["divergence_hop"] == 2
    assert set(s["branches"].keys()) == {2}
    assert [e["ip"] for e in s["branches"][2]] == ["198.51.100.1", "198.51.100.2"]

    # No divergence → no branches.
    same = [
        {"flow_id": 0, "hops": [{"hop": 1, "ip": "203.0.113.1"}]},
        {"flow_id": 1, "hops": [{"hop": 1, "ip": "203.0.113.1"}]},
    ]
    s2 = _build_multipath_summary(same, {}, {})
    assert s2["distinct_paths"] == 1 and s2["branches"] == {} and s2["divergence_hop"] is None

    # Empty.
    s3 = _build_multipath_summary([], {}, {})
    assert s3["flows_sent"] == 0 and s3["distinct_paths"] == 0


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    main()
