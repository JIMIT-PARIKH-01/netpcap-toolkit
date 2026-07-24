"""
PCAP analyzer (standard library only).

Parses a classic libpcap (.pcap) capture file by hand -- global header, packet
records, and Ethernet/IPv4/TCP/UDP headers -- and summarises protocols, top
talkers and top ports. Fully offline; no capturing (so no admin needed).
"""

from __future__ import annotations

import socket
import struct
from collections import Counter
from dataclasses import dataclass, field

_ETH_IPV4, _ETH_IPV6, _ETH_ARP = 0x0800, 0x86DD, 0x0806
_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 89: "OSPF"}


@dataclass
class PcapSummary:
    packets: int = 0
    total_bytes: int = 0
    l3: Counter = field(default_factory=Counter)      # IPv4 / IPv6 / ARP / other
    l4: Counter = field(default_factory=Counter)      # TCP / UDP / ICMP / ...
    talkers: Counter = field(default_factory=Counter)  # src IP -> count
    dst_ports: Counter = field(default_factory=Counter)

    def as_text(self) -> str:
        lines = [
            "=== PCAP summary ===",
            f"Packets      : {self.packets}",
            f"Total bytes  : {self.total_bytes}",
            f"L3 protocols : " + ", ".join(f"{k}={v}" for k, v in self.l3.most_common()),
            f"L4 protocols : " + ", ".join(f"{k}={v}" for k, v in self.l4.most_common()),
            "Top talkers (src IP):",
        ]
        for ip, n in self.talkers.most_common(8):
            lines.append(f"  {ip:<18} {n}")
        lines.append("Top destination ports:")
        for port, n in self.dst_ports.most_common(8):
            lines.append(f"  {port:<6} {n}")
        return "\n".join(lines)


def _parse_ipv4(data: bytes, summ: PcapSummary) -> None:
    if len(data) < 20:
        return
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    summ.talkers[src] += 1
    summ.l4[_PROTO.get(proto, str(proto))] += 1
    if proto in (6, 17) and len(data) >= ihl + 4:      # TCP/UDP -> dst port
        dport = struct.unpack(">H", data[ihl + 2:ihl + 4])[0]
        summ.dst_ports[dport] += 1


def analyze_bytes(blob: bytes) -> PcapSummary:
    if len(blob) < 24:
        raise ValueError("file too small to be a pcap")
    magic = blob[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("not a libpcap file (bad magic number)")

    link_type = struct.unpack(endian + "I", blob[20:24])[0]
    summ = PcapSummary()
    off = 24
    while off + 16 <= len(blob):
        _ts, _tu, incl, _orig = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        pkt = blob[off:off + incl]
        off += incl
        if len(pkt) < incl:
            break
        summ.packets += 1
        summ.total_bytes += incl

        payload, ethertype = pkt, None
        if link_type == 1 and len(pkt) >= 14:          # Ethernet
            ethertype = struct.unpack(">H", pkt[12:14])[0]
            payload = pkt[14:]
        if ethertype == _ETH_IPV4 or (link_type != 1 and payload[:1]
                                      and (payload[0] >> 4) == 4):
            summ.l3["IPv4"] += 1
            _parse_ipv4(payload, summ)
        elif ethertype == _ETH_IPV6:
            summ.l3["IPv6"] += 1
        elif ethertype == _ETH_ARP:
            summ.l3["ARP"] += 1
        else:
            summ.l3["other"] += 1
    return summ


def analyze_file(path: str) -> PcapSummary:
    with open(path, "rb") as fh:
        return analyze_bytes(fh.read())
