"""
Tkinter GUI for the Net/PCAP Toolkit (standard library only).
Tabs: PCAP analysis · LAN scan. Work runs on a background thread.
"""

from __future__ import annotations

import queue
import threading

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    from netpcap import pcap_analyze, lanscan
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from netpcap import pcap_analyze, lanscan


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Net / PCAP Toolkit")
        self.geometry("820x620")
        self.minsize(680, 500)
        self.ui_queue: "queue.Queue" = queue.Queue()
        self.after(60, self._drain)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        nb.add(PcapTab(nb, self), text="  PCAP  ")
        nb.add(LanTab(nb, self), text="  LAN scan  ")
        self.status = ttk.Label(self, relief="sunken", anchor="w",
                                text="Authorized networks only.")
        self.status.pack(fill="x", side="bottom")

    def set_status(self, m): self.status.configure(text=m)

    def _drain(self):
        try:
            while True:
                cb = self.ui_queue.get_nowait()
                try:
                    cb()
                except Exception:  # noqa: BLE001
                    self.set_status("A UI update failed.")
        except queue.Empty:
            pass
        self.after(60, self._drain)

    def run_async(self, work, tab):
        tab.btn.configure(state="disabled"); self.set_status("Working…")

        def worker():
            try:
                res = work()
            except Exception as exc:  # noqa: BLE001
                res = f"Error: {exc}"

            def finish():
                tab.out.configure(state="normal"); tab.out.delete("1.0", "end")
                tab.out.insert("1.0", res); tab.out.configure(state="disabled")
                tab.btn.configure(state="normal"); self.set_status("Done.")
            self.ui_queue.put(finish)

        threading.Thread(target=worker, daemon=True).start()


class _Base(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1); self.rowconfigure(3, weight=1)
        self.out = None


class PcapTab(_Base):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="PCAP file").grid(row=0, column=0, sticky="w")
        self.path = tk.StringVar()
        ttk.Entry(self, textvariable=self.path).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Button(ctl, text="Browse…", command=self._browse).pack(side="left")
        self.btn = ttk.Button(ctl, text="Analyze", command=self.run); self.btn.pack(side="right")
        self.out = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10),
                                             state="disabled")
        self.out.grid(row=3, column=0, sticky="nsew", pady=(8, 0))

    def _browse(self):
        f = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap *.cap"), ("All", "*.*")])
        if f:
            self.path.set(f)

    def run(self):
        p = self.path.get().strip()
        if not p:
            messagebox.showinfo("No file", "Choose a .pcap file."); return
        self.app.run_async(lambda: pcap_analyze.analyze_file(p).as_text(), self)


class LanTab(_Base):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Subnet (CIDR), e.g. 192.168.1.0/24").grid(row=0, column=0, sticky="w")
        self.cidr = tk.StringVar()
        ttk.Entry(self, textvariable=self.cidr).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        self.btn = ttk.Button(ctl, text="Scan", command=self.run); self.btn.pack(side="right")
        self.out = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10),
                                             state="disabled")
        self.out.grid(row=3, column=0, sticky="nsew", pady=(8, 0))

    def run(self):
        c = self.cidr.get().strip()
        if not c:
            messagebox.showinfo("No subnet", "Enter a CIDR like 192.168.1.0/24."); return
        self.app.run_async(lambda: lanscan.scan(c).as_text(), self)


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
