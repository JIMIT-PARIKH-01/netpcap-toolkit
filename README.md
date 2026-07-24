# Net / PCAP Toolkit

Network analysis tools — **dependency-free**, GUI + CLI.

1. **PCAP analyzer** — parses a `.pcap` capture by hand (Ethernet/IPv4/TCP/UDP) and
   summarises protocols, top talkers, and top destination ports. **Fully offline, no admin.**
2. **LAN scanner** — concurrent ping-sweep of a subnet + ARP-table lookup to map live
   IPs to MAC addresses (uses the OS `ping`/`arp`, so no raw sockets/admin).

Standard library only (`struct`, `socket`, `subprocess`, `ipaddress`). Python 3.8+.

## ⚠️ Authorized networks only
Scan only subnets you own or are permitted to assess.

## Run
```powershell
python netpcap/gui.py             # GUI (tabs: PCAP / LAN scan), or run.bat

python -m netpcap pcap capture.pcap
python -m netpcap lan  192.168.1.0/24
```

## Layout
```
netpcap-toolkit/
└── netpcap/
    ├── pcap_analyze.py   # offline libpcap parser + summary
    ├── lanscan.py        # ping-sweep + ARP LAN discovery
    ├── cli.py  gui.py  run.bat
```

MIT — see [LICENSE](./LICENSE).
