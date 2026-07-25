"""Offline tests for the Net/PCAP Toolkit."""

import socket
import struct

from netpcap import pcap_analyze, lanscan


def _make_pcap(n=3):
    gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    eth = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack(">H", 0x0800)
    ipv4 = bytes([0x45, 0, 0, 40]) + b"\x00" * 5 + bytes([6]) + b"\x00\x00" \
        + socket.inet_aton("10.0.0.5") + socket.inet_aton("10.0.0.9")
    tcp = struct.pack(">HH", 12345, 443) + b"\x00" * 16
    pkt = eth + ipv4 + tcp
    rec = struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    return gh + rec * n


def test_pcap_parses_packets():
    s = pcap_analyze.analyze_bytes(_make_pcap(3))
    assert s.packets == 3
    assert s.l3["IPv4"] == 3 and s.l4["TCP"] == 3
    assert s.talkers["10.0.0.5"] == 3
    assert s.dst_ports[443] == 3


def test_pcap_rejects_non_pcap():
    import pytest
    with pytest.raises(ValueError):
        pcap_analyze.analyze_bytes(b"not a pcap file at all!!")


def test_arp_line_regex():
    m = lanscan._ARP_LINE.search("  192.168.1.1   00-11-22-33-44-55   dynamic")
    assert m and m.group(1) == "192.168.1.1"
