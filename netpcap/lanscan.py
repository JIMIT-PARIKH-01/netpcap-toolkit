"""
LAN device scanner (standard library only).

Ping-sweeps a subnet (concurrently) and reads the system ARP table to map live
IPs to MAC addresses. Uses the OS `ping`/`arp` commands, so no admin/raw sockets.

Scan only networks you own or are authorized to assess.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

_IS_WINDOWS = platform.system().lower().startswith("win")
_ARP_LINE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")


@dataclass
class LanResult:
    cidr: str
    hosts: list = field(default_factory=list)      # (ip, mac_or_None)

    def as_text(self) -> str:
        lines = [f"LAN scan of {self.cidr}: {len(self.hosts)} host(s) up"]
        for ip, mac in self.hosts:
            lines.append(f"  {ip:<16} {mac or '(mac unknown)'}")
        if not self.hosts:
            lines.append("  (no hosts responded)")
        return "\n".join(lines)


def _ping(ip: str, timeout_ms: int = 600) -> bool:
    if _IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 2)
        return res.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def read_arp_table() -> dict:
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=8).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    table = {}
    for line in out.splitlines():
        m = _ARP_LINE.search(line)
        if m:
            table[m.group(1)] = m.group(2).replace("-", ":").lower()
    return table


def scan(cidr: str, workers: int = 64) -> LanResult:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        alive = [ip for ip, up in zip(hosts, pool.map(_ping, hosts)) if up]
    arp = read_arp_table()
    return LanResult(cidr=str(net), hosts=[(ip, arp.get(ip)) for ip in sorted(
        alive, key=lambda x: tuple(int(o) for o in x.split(".")))])
