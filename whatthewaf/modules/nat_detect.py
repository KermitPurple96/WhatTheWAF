"""Dublin-style NAT detection for the traceroute path (Linux + root only).

When a router replies with an ICMP "time exceeded" it quotes the original probe
packet (IP header + at least the first 8 bytes = the UDP header). We send UDP
probes with a *known, non-zero* IP-ID and a fixed source port, then read those
fields back out of the quoted packet. A NAT between us and a given hop rewrites
the source IP/port and recomputes the UDP checksum before the packet reaches the
router, so the quoted probe shows a different source port / UDP checksum (and
sometimes IP-ID) than what we sent — that mismatch is the NAT signal.

This needs raw sockets: Linux + root. Everywhere else `detect_nat` returns
{"supported": False, "note": ...} and the byte-level helpers remain importable
and unit-testable.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import time
from typing import Any, Dict, Optional, Tuple

_PAYLOAD = b"WTW-NAT"


# ─────────────────────────────────────────────────────────────────────────
# Byte-level helpers (pure, unit-testable on any platform)
# ─────────────────────────────────────────────────────────────────────────

def _checksum16(data: bytes) -> int:
    """Standard RFC 1071 16-bit one's-complement checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _build_udp_probe(src_ip: str, dst_ip: str, ttl: int, ip_id: int,
                     sport: int, dport: int,
                     payload: bytes = _PAYLOAD) -> Tuple[bytes, Dict[str, int]]:
    """Craft a full IPv4+UDP probe. Returns (packet_bytes, sent_fields).

    ip_id MUST be non-zero so the Linux kernel preserves it under IP_HDRINCL.
    """
    ihl_ver = (4 << 4) | 5
    total_len = 20 + 8 + len(payload)
    proto = socket.IPPROTO_UDP  # 17
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    ip_hdr = struct.pack("!BBHHHBBH4s4s", ihl_ver, 0, total_len, ip_id & 0xFFFF,
                         0, ttl, proto, 0, src, dst)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", ihl_ver, 0, total_len, ip_id & 0xFFFF,
                         0, ttl, proto, _checksum16(ip_hdr), src, dst)

    udp_len = 8 + len(payload)
    udp0 = struct.pack("!HHHH", sport, dport, udp_len, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, proto, udp_len)
    udp_csum = _checksum16(pseudo + udp0 + payload) or 0xFFFF
    udp_hdr = struct.pack("!HHHH", sport, dport, udp_len, udp_csum)

    sent = {"ip_id": ip_id & 0xFFFF, "udp_checksum": udp_csum,
            "sport": sport, "dport": dport}
    return ip_hdr + udp_hdr + payload, sent


def _wrap_icmp_time_exceeded(router_ip: str, inner_packet: bytes,
                             icmp_type: int = 11, icmp_code: int = 0) -> bytes:
    """Build an ICMP time-exceeded (or dest-unreachable) reply quoting a probe.

    Used to simulate a router response for unit tests and as the inverse of
    `_parse_icmp_time_exceeded`.
    """
    src = socket.inet_aton(router_ip)
    dst = socket.inet_aton("10.0.0.99")  # us; not inspected by the parser
    icmp = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0) + inner_packet
    icmp = struct.pack("!BBHI", icmp_type, icmp_code, _checksum16(icmp), 0) + inner_packet
    total_len = 20 + len(icmp)
    ip = struct.pack("!BBHHHBBH4s4s", (4 << 4) | 5, 0, total_len, 0, 0,
                     64, socket.IPPROTO_ICMP, 0, src, dst)
    ip = struct.pack("!BBHHHBBH4s4s", (4 << 4) | 5, 0, total_len, 0, 0,
                     64, socket.IPPROTO_ICMP, _checksum16(ip), src, dst)
    return ip + icmp


def _parse_icmp_time_exceeded(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse a raw ICMP reply, extracting the quoted inner probe's fields.

    Returns None if the packet is not an ICMP type 11 (time exceeded) or type 3
    (dest unreachable — destination reached). Inner UDP fields are None when the
    router quoted fewer than 8 bytes of the original datagram.
    """
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    outer_ihl = (data[0] & 0x0F) * 4
    if len(data) < outer_ihl + 8:
        return None
    router_ip = socket.inet_ntoa(data[12:16])
    icmp_type, icmp_code = data[outer_ihl], data[outer_ihl + 1]
    if icmp_type not in (11, 3):
        return None

    inner = data[outer_ihl + 8:]
    if len(inner) < 20 or (inner[0] >> 4) != 4:
        return None
    inner_ihl = (inner[0] & 0x0F) * 4
    inner_ip_id = struct.unpack("!H", inner[4:6])[0]
    inner_dst = socket.inet_ntoa(inner[16:20])

    out: Dict[str, Any] = {
        "router_ip": router_ip, "icmp_type": icmp_type, "icmp_code": icmp_code,
        "inner_ip_id": inner_ip_id, "inner_dst": inner_dst,
        "inner_sport": None, "inner_dport": None, "inner_udp_checksum": None,
    }
    if len(inner) >= inner_ihl + 8:
        sport, dport, _ulen, ucsum = struct.unpack("!HHHH", inner[inner_ihl:inner_ihl + 8])
        out.update(inner_sport=sport, inner_dport=dport, inner_udp_checksum=ucsum)
    return out


def _nat_verdict(sent: Dict[str, int], parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Decide whether the quoted probe shows NAT rewriting.

    Source-port or UDP-checksum rewrite is a strong NAT signal; an IP-ID change
    alone is weak (some middleboxes touch it) and is reported but not decisive.
    """
    reasons = []
    if parsed.get("inner_sport") is not None and parsed["inner_sport"] != sent["sport"]:
        reasons.append("source-port rewritten")
    if (parsed.get("inner_udp_checksum") is not None
            and parsed["inner_udp_checksum"] != sent["udp_checksum"]):
        reasons.append("udp-checksum rewritten")
    if parsed.get("inner_ip_id") is not None and parsed["inner_ip_id"] != sent["ip_id"]:
        reasons.append("ip-id rewritten")
    strong = any(("port" in r or "checksum" in r) for r in reasons)
    return {"nat": strong, "reason": ", ".join(reasons)}


# ─────────────────────────────────────────────────────────────────────────
# Raw-socket probe loop (Linux + root)
# ─────────────────────────────────────────────────────────────────────────

def _local_ip_for(dst_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 33434))
        return s.getsockname()[0]
    finally:
        s.close()


def _recv_match(recv_sock, deadline: float, dst_ip: str, dport: int):
    """Read ICMP replies until one quotes our probe (by inner dst+dport) or timeout."""
    while time.time() < deadline:
        try:
            recv_sock.settimeout(max(0.05, deadline - time.time()))
            data, _addr = recv_sock.recvfrom(2048)
        except socket.timeout:
            return None
        except OSError:
            return None
        parsed = _parse_icmp_time_exceeded(data)
        if parsed and parsed["inner_dst"] == dst_ip and parsed.get("inner_dport") in (dport, None):
            return parsed
    return None


def detect_nat(domain: str, max_hops: int = 30, timeout: int = 2,
               dport: int = 33434, on_status=None) -> Dict[str, Any]:
    """Probe the path and flag hops where a NAT rewrote our packets.

    Linux + root only (raw sockets). Returns:
      {supported, note?, src_ip, nat_detected, hops:[{ttl,router_ip,nat,reason,...}],
       nat_hops:[...]}
    """
    _status = on_status or (lambda *a: None)

    if not sys.platform.startswith("linux"):
        return {"supported": False,
                "note": "NAT detection needs Linux raw sockets"}
    if getattr(os, "geteuid", lambda: 1)() != 0:
        return {"supported": False,
                "note": "NAT detection needs root (raw sockets)"}

    try:
        dst_ip = socket.gethostbyname(domain)
    except OSError:
        return {"supported": False, "note": f"cannot resolve {domain}"}

    try:
        src_ip = _local_ip_for(dst_ip)
        send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv.bind(("", 0))
    except OSError as e:
        return {"supported": False, "note": f"raw socket error: {e}"}

    _status("trace", f"NAT detection ({max_hops} hops, Dublin IP-ID)")
    sport = 0x8000 | (os.getpid() & 0x7FFF)
    ip_id_base = 0x4200

    hops = []
    nat_hops = []
    consecutive_miss = 0
    seen_real = False
    try:
        for ttl in range(1, max_hops + 1):
            ip_id = (ip_id_base + ttl) & 0xFFFF
            pkt, sent = _build_udp_probe(src_ip, dst_ip, ttl, ip_id, sport, dport)
            try:
                send.sendto(pkt, (dst_ip, 0))
            except OSError:
                break
            parsed = _recv_match(recv, time.time() + timeout, dst_ip, dport)
            if not parsed:
                hops.append({"ttl": ttl, "router_ip": "*", "nat": None, "reason": ""})
                consecutive_miss += 1
                # Targets that drop our UDP (CDNs, most web hosts) never send the
                # final port-unreachable, so stop once the path clearly ended.
                if seen_real and consecutive_miss >= 5:
                    break
                continue
            consecutive_miss = 0
            seen_real = True
            verdict = _nat_verdict(sent, parsed)
            rec = {"ttl": ttl, "router_ip": parsed["router_ip"],
                   "nat": verdict["nat"], "reason": verdict["reason"],
                   "sent_ip_id": ip_id, "inner_ip_id": parsed["inner_ip_id"]}
            hops.append(rec)
            if verdict["nat"]:
                nat_hops.append(rec)
            if parsed["icmp_type"] == 3:  # destination reached (port unreachable)
                break
    finally:
        send.close()
        recv.close()

    return {"supported": True, "src_ip": src_ip, "dst_ip": dst_ip,
            "nat_detected": bool(nat_hops), "hops": hops, "nat_hops": nat_hops}
