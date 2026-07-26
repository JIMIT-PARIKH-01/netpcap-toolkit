# Net / PCAP Toolkit

[![CI](https://github.com/JIMIT-PARIKH-01/netpcap-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/JIMIT-PARIKH-01/netpcap-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

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

## ⬇️ Download & Install

**This is a public tool — download and use it on your device for free.**

```bash
# 1) Clone it
git clone https://github.com/JIMIT-PARIKH-01/netpcap-toolkit.git
cd netpcap-toolkit

# 2) ...or download a ZIP (no git needed)
#    https://github.com/JIMIT-PARIKH-01/netpcap-toolkit/archive/refs/heads/main.zip

# 3) ...or install the command straight from GitHub
pip install git+https://github.com/JIMIT-PARIKH-01/netpcap-toolkit.git
```

Then run it as shown in the usage section above (CLI `python -m ...`, or launch
the GUI via `run.bat`).

<details>
<summary><b>🔒 Requesting access to a private tool</b></summary>

Public tools install with the commands above. If a tool is **private**, access
is granted by the owner through GitHub — a static link cannot unlock private
code, only GitHub can:

1. **Request access** — open an [access request](https://github.com/JIMIT-PARIKH-01/JIMIT-PARIKH-01/issues/new?template=tool-access-request.md&title=Access+request:+netpcap-toolkit) or message on
   [LinkedIn](https://www.linkedin.com/in/jimit-devangkumar-parikh/).
2. The owner reviews it and, if approved, **adds you as a collaborator** on the
   private repository.
3. GitHub then lets you clone / download it with your own account. Access is
   revoked the moment the owner removes you as a collaborator.

</details>

