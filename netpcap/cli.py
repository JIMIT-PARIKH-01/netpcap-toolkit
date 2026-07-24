"""
Net/PCAP Toolkit command line.

    python -m netpcap pcap capture.pcap
    python -m netpcap lan  192.168.1.0/24

Scan only networks you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import sys

from . import pcap_analyze, lanscan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netpcap", description="PCAP file analysis and LAN device discovery.")
    sub = p.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("pcap", help="Summarize a .pcap capture file.")
    pc.add_argument("file")

    ln = sub.add_parser("lan", help="Ping-sweep a subnet + read ARP table.")
    ln.add_argument("cidr", help="e.g. 192.168.1.0/24")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "pcap":
            print(pcap_analyze.analyze_file(args.file).as_text())
        elif args.command == "lan":
            print(lanscan.scan(args.cidr).as_text())
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
