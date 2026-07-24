"""Entry point:  python -m netpcap <pcap|lan> ..."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
