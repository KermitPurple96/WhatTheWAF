"""Byte-level tests for NAT detection (run on any platform; no raw sockets).

Run:  python tests/test_nat_detect.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from whatthewaf.modules.nat_detect import (  # noqa: E402
    _checksum16, _build_udp_probe, _wrap_icmp_time_exceeded,
    _parse_icmp_time_exceeded, _nat_verdict, detect_nat,
)

SRC, DST = "10.0.0.5", "93.184.216.34"


def test_checksums_valid():
    pkt, sent = _build_udp_probe(SRC, DST, ttl=5, ip_id=0x4205,
                                 sport=40000, dport=33434)
    # A valid IPv4 header checksums to zero when recomputed over itself.
    assert _checksum16(pkt[:20]) == 0
    assert sent == {"ip_id": 0x4205, "udp_checksum": sent["udp_checksum"],
                    "sport": 40000, "dport": 33434}
    assert sent["udp_checksum"] != 0


def test_roundtrip_no_nat():
    pkt, sent = _build_udp_probe(SRC, DST, ttl=5, ip_id=0x4205,
                                 sport=40000, dport=33434)
    reply = _wrap_icmp_time_exceeded("192.0.2.1", pkt)
    p = _parse_icmp_time_exceeded(reply)
    assert p is not None
    assert p["router_ip"] == "192.0.2.1"
    assert p["icmp_type"] == 11
    assert p["inner_ip_id"] == 0x4205
    assert p["inner_dst"] == DST
    assert p["inner_sport"] == 40000 and p["inner_dport"] == 33434
    assert p["inner_udp_checksum"] == sent["udp_checksum"]
    assert _nat_verdict(sent, p)["nat"] is False


def test_nat_source_port_rewrite():
    pkt, sent = _build_udp_probe(SRC, DST, ttl=5, ip_id=0x4205,
                                 sport=40000, dport=33434)
    reply = bytearray(_wrap_icmp_time_exceeded("192.0.2.1", pkt))
    # Inner probe starts at 20 (outer IP) + 8 (ICMP); UDP header 20 bytes later.
    udp_off = 20 + 8 + 20
    struct.pack_into("!H", reply, udp_off, 40001)  # NAT rewrote the source port
    p = _parse_icmp_time_exceeded(bytes(reply))
    assert p["inner_sport"] == 40001
    v = _nat_verdict(sent, p)
    assert v["nat"] is True and "source-port" in v["reason"]


def test_destination_reached():
    pkt, _ = _build_udp_probe(SRC, DST, ttl=9, ip_id=0x4209,
                              sport=40000, dport=33434)
    reply = _wrap_icmp_time_exceeded(DST, pkt, icmp_type=3, icmp_code=3)
    p = _parse_icmp_time_exceeded(reply)
    assert p is not None and p["icmp_type"] == 3


def test_non_icmp_ignored():
    pkt, _ = _build_udp_probe(SRC, DST, ttl=1, ip_id=0x4201,
                              sport=40000, dport=33434)
    reply = _wrap_icmp_time_exceeded("1.1.1.1", pkt, icmp_type=0)  # echo reply
    assert _parse_icmp_time_exceeded(reply) is None


def test_truncated_inner_no_udp():
    pkt, sent = _build_udp_probe(SRC, DST, ttl=2, ip_id=0x4202,
                                 sport=40000, dport=33434)
    reply = _wrap_icmp_time_exceeded("2.2.2.2", pkt[:20])  # only inner IP header
    p = _parse_icmp_time_exceeded(reply)
    assert p is not None and p["inner_sport"] is None
    assert p["inner_ip_id"] == 0x4202
    assert _nat_verdict(sent, p)["nat"] is False  # can't judge → not flagged


def test_detect_nat_gated():
    # On Windows / non-root this must gracefully report unsupported, never crash.
    r = detect_nat("example.com", max_hops=3)
    assert r["supported"] is False and "note" in r


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    main()
