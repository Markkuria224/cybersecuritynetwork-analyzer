#!/usr/bin/env python3
"""
Cybersecurity Network Packet Analyzer

Windows-focused, Tkinter-based GUI that captures live traffic via Scapy in a
background thread, displays packets in a table with filters and search,
generates security alerts, provides a live packets-per-second graph, and
exports to CSV/TXT/PCAP. Multi-interface selection supported.

Notes:
- On Windows, install Npcap (with WinPcap-compatible API) for capture.
- You may need to run as Administrator to access raw capture devices.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import datetime
import csv
import json
from collections import defaultdict, deque
import ctypes

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list


class NetworkAnalyzer:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Cybersecurity Network Analyzer")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 650)

        # State
        self.running = False
        self.capture_thread: threading.Thread | None = None
        self.packet_queue: queue.Queue = queue.Queue()
        self.packets: list[dict] = []
        self.alert_count = 0
        self.syn_flood_sources: dict[str, list[datetime.datetime]] = defaultdict(list)
        self.packet_times: deque[datetime.datetime] = deque(maxlen=120)

        # Config and UI variables
        self._load_config()
        self.selected_protocol = tk.StringVar(value="All")
        self.selected_interface = tk.StringVar()
        self.search_var = tk.StringVar()
        self.current_theme = "dark"
        self.interfaces = get_if_list() or []
        if self.interfaces:
            self.selected_interface.set(self.interfaces[0])

        # UI
        self._build_ui()
        self._apply_theme()

        # Main GUI loop updater
        self._tick_gui()

    # --------------------------- Config ---------------------------
    def _load_config(self) -> None:
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

        self.suspicious_ips: list[str] = cfg.get("suspicious_ips", [])
        self.suspicious_ports: list[int] = cfg.get("suspicious_ports", [4444, 31337])
        self.syn_flood_threshold: int = cfg.get("syn_flood_threshold", 10)
        self.credential_keywords: list[str] = cfg.get(
            "credential_keywords",
            ["user=", "pass=", "Authorization:", "password=", "login="]
        )
        thresholds = cfg.get("alert_thresholds", {})
        self.large_packet_size: int = int(thresholds.get("large_packet_size", 1500))

    # ---------------------------- UI ------------------------------
    def _build_ui(self) -> None:
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export to CSV", command=self._export_csv)
        file_menu.add_command(label="Export to PCAP", command=self._export_pcap)
        file_menu.add_command(label="Export to TXT", command=self._export_txt)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme", command=self._toggle_theme)
        view_menu.add_command(label="Clear Packets", command=self._clear_packets)
        view_menu.add_command(label="Clear Alerts", command=self._clear_alerts)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

        # Top controls
        controls = ttk.Frame(self.root)
        controls.pack(fill=tk.X, padx=8, pady=(6, 2))

        title = ttk.Label(controls, text="🔍 Network Packet Analyzer", font=("Segoe UI", 14, "bold"))
        title.pack(anchor=tk.W, pady=(0, 6))

        row = ttk.Frame(controls)
        row.pack(fill=tk.X)

        self.start_btn = ttk.Button(row, text="▶ Start", command=self._start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_btn = ttk.Button(row, text="⏹ Stop", command=self._stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        ttk.Label(row, text="  Interface:").pack(side=tk.LEFT, padx=(12, 4))
        self.if_combo = ttk.Combobox(row, textvariable=self.selected_interface, values=self.interfaces, width=28, state="readonly")
        self.if_combo.pack(side=tk.LEFT)

        ttk.Label(row, text="  Protocol:").pack(side=tk.LEFT, padx=(12, 4))
        self.proto_combo = ttk.Combobox(row, textvariable=self.selected_protocol, values=["All", "TCP", "UDP", "ICMP", "ARP"], width=10, state="readonly")
        self.proto_combo.pack(side=tk.LEFT)
        self.proto_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_filters_and_refresh())

        search_row = ttk.Frame(controls)
        search_row.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(search_row, text="Search:").pack(side=tk.LEFT, padx=(0, 6))
        self.search_entry = ttk.Entry(search_row, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<KeyRelease>", lambda _e: self._apply_filters_and_refresh())

        # Main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Packets tab
        pkt_tab = ttk.Frame(self.notebook)
        self.notebook.add(pkt_tab, text="📦 Packets")

        columns = ("Time", "Source", "Destination", "Protocol", "Length", "Info", "Payload")
        self.tree = ttk.Treeview(pkt_tab, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            # keep payload narrower to avoid horizontal overflow
            default_width = 120 if col == "Time" else (220 if col == "Info" else 150)
            if col == "Payload":
                default_width = 240
            self.tree.column(col, width=default_width)
        self.tree.column("Protocol", width=80)
        self.tree.column("Length", width=80)
        self.tree.column("Info", width=260)

        yscroll = ttk.Scrollbar(pkt_tab, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(pkt_tab, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree.bind("<Double-1>", self._open_details)

        # Stats tab (graph)
        stats_tab = ttk.Frame(self.notebook)
        self.notebook.add(stats_tab, text="📊 Statistics")
        self.fig = Figure(figsize=(8, 3), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Packets/s")
        self.canvas = FigureCanvasTkAgg(self.fig, stats_tab)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Alerts panel
        alerts_frame = ttk.Frame(self.root)
        alerts_frame.pack(fill=tk.BOTH, padx=8, pady=(0, 8))
        ttk.Label(alerts_frame, text="⚠️ Security Alerts", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W)
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=7, font=("Consolas", 9))
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
        self._append_alert("Monitoring for suspicious activity...")

        # Status bar
        self.status = ttk.Label(self.root, text="Ready", anchor=tk.W, relief=tk.SUNKEN)
        self.status.pack(fill=tk.X)

    def _apply_theme(self) -> None:
        if self.current_theme == "dark":
            bg = "#1e1e1e"
            fg = "white"
            self.root.configure(bg=bg)
            self.alerts_text.configure(bg="#2e2e2e", fg=fg, insertbackground=fg)
        else:
            self.root.configure(bg="#f6f6f6")
            self.alerts_text.configure(bg="white", fg="black", insertbackground="black")

    # ------------------------- Capture ----------------------------
    def _start_capture(self) -> None:
        if self.running:
            return
        iface = self.selected_interface.get()
        if not iface:
            messagebox.showwarning("No Interface", "Please select a network interface.")
            return

        self.running = True
        self.packets.clear()
        self.tree.delete(*self.tree.get_children())
        self.packet_times.clear()
        self.alert_count = 0

        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.if_combo.configure(state="disabled")

        # Start capturing in a background thread
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        self._append_alert(f"Capturing on interface: {iface}")

        # Warn if not admin (Windows)
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            if not is_admin:
                messagebox.showwarning(
                    "Permission",
                    "Packet capture may require Administrator privileges on Windows.\n"
                    "If capture shows no packets, run as Administrator."
                )
        except Exception:
            pass

    def _stop_capture(self) -> None:
        self.running = False
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.if_combo.configure(state="readonly")
        self._append_alert("Capture stopped.")

    def _bpf_for_protocol(self) -> str | None:
        proto = self.selected_protocol.get()
        if proto == "TCP":
            return "tcp"
        if proto == "UDP":
            return "udp"
        if proto == "ICMP":
            return "icmp"
        if proto == "ARP":
            return "arp"
        return None

    def _capture_loop(self) -> None:
        try:
            iface = self.selected_interface.get()
            bpf = self._bpf_for_protocol()

            sniff(
                iface=iface,
                store=False,
                filter=bpf if bpf else None,
                prn=self._on_packet,
                stop_filter=lambda p: not self.running,
            )
        except Exception as e:
            self._append_alert(f"Capture error: {e}")
            self.root.after(0, self._stop_capture)

    # ---------------------- Processing/GUI ------------------------
    def _on_packet(self, pkt) -> None:
        if not self.running:
            return
        try:
            info = self._extract_info(pkt)
            self.packet_queue.put(info)
            self._analyze_security(pkt, info)
        except Exception:
            # Skip malformed packet
            pass

    def _extract_info(self, pkt) -> dict:
        now = datetime.datetime.now()
        info: dict = {
            "timestamp": now,
            "raw": pkt,
            "length": len(pkt),
            "protocol": "Unknown",
            "source": "Unknown",
            "destination": "Unknown",
            "flags": "",
            "payload": "",
            "summary": "",
        }

        if IP in pkt:
            ip = pkt[IP]
            info["source"] = ip.src
            info["destination"] = ip.dst
            info["protocol"] = str(ip.proto)

            if TCP in pkt:
                tcp = pkt[TCP]
                info["protocol"] = "TCP"
                info["source"] = f"{ip.src}:{tcp.sport}"
                info["destination"] = f"{ip.dst}:{tcp.dport}"
                info["flags"] = str(tcp.flags)
                info["summary"] = f"TCP {tcp.sport} → {tcp.dport} [{tcp.flags}]"
            elif UDP in pkt:
                udp = pkt[UDP]
                info["protocol"] = "UDP"
                info["source"] = f"{ip.src}:{udp.sport}"
                info["destination"] = f"{ip.dst}:{udp.dport}"
                info["summary"] = f"UDP {udp.sport} → {udp.dport}"
            elif ICMP in pkt:
                icmp = pkt[ICMP]
                info["protocol"] = "ICMP"
                info["summary"] = f"ICMP type {icmp.type}"
        elif ARP in pkt:
            arp = pkt[ARP]
            info["protocol"] = "ARP"
            info["source"] = arp.psrc
            info["destination"] = arp.pdst
            info["summary"] = f"ARP op {arp.op}"

        # Payload
        if hasattr(pkt, "load") and pkt.load:
            try:
                info["payload"] = bytes(pkt.load).decode("utf-8", errors="ignore")
            except Exception:
                info["payload"] = str(pkt.load)

        return info

    def _tick_gui(self) -> None:
        # Drain queue and update table with filters applied
        try:
            updated = False
            while not self.packet_queue.empty():
                p = self.packet_queue.get_nowait()
                self.packets.append(p)
                self.packet_times.append(datetime.datetime.now())
                if self._passes_filters(p):
                    self._insert_row(p)
                updated = True

            if self.running and updated:
                self._update_graph()

            self._update_status()
        except Exception:
            pass

        self.root.after(100, self._tick_gui)

    def _passes_filters(self, p: dict) -> bool:
        proto = self.selected_protocol.get()
        if proto != "All" and p.get("protocol") != proto:
            return False
        s = self.search_var.get().strip().lower()
        if not s:
            return True
        blob = " ".join([
            str(p.get("source", "")),
            str(p.get("destination", "")),
            str(p.get("summary", "")),
            str(p.get("payload", "")),
        ]).lower()
        return s in blob

    def _apply_filters_and_refresh(self) -> None:
        # Rebuild table from filtered packets
        self.tree.delete(*self.tree.get_children())
        for p in self.packets:
            if self._passes_filters(p):
                self._insert_row(p)

    def _insert_row(self, p: dict) -> None:
        ts = p["timestamp"].strftime("%H:%M:%S.%f")[:-3]
        payload = (p.get("payload") or "").replace("\r", " ").replace("\n", " ")
        if len(payload) > 120:
            payload = payload[:117] + "..."
        self.tree.insert(
            "",
            tk.END,
            values=(ts, p["source"], p["destination"], p["protocol"], p["length"], p["summary"], payload),
        )

    def _update_graph(self) -> None:
        # Calculate packets/second over last 30s
        now = datetime.datetime.now()
        cutoff = now - datetime.timedelta(seconds=30)
        while self.packet_times and self.packet_times[0] < cutoff:
            self.packet_times.popleft()
        rate = len(self.packet_times) / 30.0

        self.ax.clear()
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Packets/s")
        self.ax.plot([0, 30], [rate, rate], color="lime", linewidth=2)
        self.ax.set_xlim(0, 30)
        self.ax.set_ylim(0, max(rate * 1.5, 5))
        self.canvas.draw()

    def _update_status(self) -> None:
        duration = ""
        if self.packets:
            first = self.packets[0]["timestamp"]
            duration = str(datetime.datetime.now() - first).split(".")[0]
        status = f"Packets: {len(self.packets)} | Protocol: {self.selected_protocol.get()} | Alerts: {self.alert_count} | Duration: {duration or '00:00:00'}"
        self.status.configure(text=status)

    # ---------------------- Security/Alerts -----------------------
    def _analyze_security(self, pkt, info: dict) -> None:
        try:
            # Suspicious IP watchlist
            src_ip = str(info.get("source", "")).split(":")[0]
            dst_ip = str(info.get("destination", "")).split(":")[0]
            if src_ip in self.suspicious_ips:
                self._append_alert(f"Watchlist source IP observed: {src_ip}")
            if dst_ip in self.suspicious_ips:
                self._append_alert(f"Watchlist destination IP observed: {dst_ip}")

            # Suspicious ports
            dport = None
            try:
                if TCP in pkt:
                    dport = int(pkt[TCP].dport)
                elif UDP in pkt:
                    dport = int(pkt[UDP].dport)
            except Exception:
                dport = None
            if dport and dport in self.suspicious_ports:
                self._append_alert(f"Suspicious port {dport} from {info.get('source')}")

            # Cleartext credential keywords
            payload = info.get("payload", "")
            low = payload.lower()
            for kw in self.credential_keywords:
                if kw.lower() in low:
                    self._append_alert(f"Possible credentials in payload ('{kw.strip()}') from {info.get('source')}")
                    break

            # DNS amplification (oversized UDP 53)
            if UDP in pkt and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53) and info.get("length", 0) > 512:
                self._append_alert("Potential DNS amplification (large UDP:53 packet)")

            # Large packet
            if info.get("length", 0) > self.large_packet_size:
                self._append_alert(f"Large packet {info['length']} bytes from {info.get('source')}")

            # SYN flood (many SYNs from same IP within 1 second)
            if TCP in pkt and str(pkt[TCP].flags) == 'S':
                now = datetime.datetime.now()
                self.syn_flood_sources[src_ip].append(now)
                self.syn_flood_sources[src_ip] = [t for t in self.syn_flood_sources[src_ip] if (now - t).total_seconds() <= 1]
                if len(self.syn_flood_sources[src_ip]) > self.syn_flood_threshold:
                    self._append_alert(f"SYN flood pattern from {src_ip}")
        except Exception:
            pass

    def _append_alert(self, text: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.alerts_text.insert(tk.END, f"[{ts}] {text}\n")
        self.alerts_text.see(tk.END)
        self.alert_count += 1

    # ------------------------ Details/Export ----------------------
    def _open_details(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        ts = values[0]
        target = None
        for p in self.packets:
            if p["timestamp"].strftime("%H:%M:%S.%f")[:-3] == ts:
                target = p
                break
        if not target:
            return

        win = tk.Toplevel(self.root)
        win.title("Packet Details")
        win.geometry("900x650")

        txt = scrolledtext.ScrolledText(win, font=("Consolas", 10))
        txt.pack(fill=tk.BOTH, expand=True)

        hex_dump = ""
        try:
            hex_dump = bytes(target["raw"]).hex()
        except Exception:
            pass

        details = (
            f"Timestamp: {target['timestamp']}\n"
            f"Length: {target['length']}\n"
            f"Protocol: {target['protocol']}\n"
            f"Source: {target['source']}\n"
            f"Destination: {target['destination']}\n"
            f"Flags: {target['flags']}\n\n"
            f"Scapy decode:\n{target['raw'].show(dump=True)}\n\n"
            f"Payload (utf-8 best-effort):\n{target['payload']}\n\n"
            f"Hex (raw bytes):\n{hex_dump}\n"
        )
        txt.insert(tk.END, details)
        txt.configure(state=tk.DISABLED)

    def _export_csv(self) -> None:
        if not self.packets:
            messagebox.showinfo("Export", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp", "Source", "Destination", "Protocol", "Length", "Info", "Payload"])
                for p in self.packets:
                    w.writerow([
                        p["timestamp"], p["source"], p["destination"], p["protocol"], p["length"], p["summary"], p["payload"]
                    ])
            messagebox.showinfo("Export", f"Exported {len(self.packets)} packets to CSV.")
        except Exception as e:
            messagebox.showerror("Export", f"CSV export failed: {e}")

    def _export_txt(self) -> None:
        if not self.packets:
            messagebox.showinfo("Export", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for p in self.packets:
                    f.write(f"[{p['timestamp']}] {p['source']} -> {p['destination']} {p['protocol']} len={p['length']}\n")
                    if p['summary']:
                        f.write(f"  Info: {p['summary']}\n")
                    if p['payload']:
                        safe = p['payload'].replace('\r', ' ').replace('\n', '\\n')
                        f.write(f"  Payload: {safe}\n")
                    try:
                        f.write(f"  Hex: {bytes(p['raw']).hex()}\n")
                    except Exception:
                        pass
                    f.write("\n")
            messagebox.showinfo("Export", f"Exported {len(self.packets)} packets to TXT.")
        except Exception as e:
            messagebox.showerror("Export", f"TXT export failed: {e}")

    def _export_pcap(self) -> None:
        if not self.packets:
            messagebox.showinfo("Export", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
        if not path:
            return
        try:
            from scapy.utils import wrpcap
            wrpcap(path, [p["raw"] for p in self.packets])
            messagebox.showinfo("Export", f"Exported {len(self.packets)} packets to PCAP.")
        except Exception as e:
            messagebox.showerror("Export", f"PCAP export failed: {e}")

    # ------------------------ Utilities --------------------------
    def _clear_packets(self) -> None:
        self.packets.clear()
        self.tree.delete(*self.tree.get_children())
        self.packet_times.clear()
        self.alert_count = 0
        self._append_alert("Cleared packets.")

    def _clear_alerts(self) -> None:
        self.alerts_text.delete("1.0", tk.END)
        self.alerts_text.insert(tk.END, "Monitoring for suspicious activity...\n")
        self.alert_count = 0

    def _toggle_theme(self) -> None:
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self._apply_theme()

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About",
            "Cybersecurity Network Analyzer\n\n"
            "- Real-time capture with Scapy\n"
            "- Filters, search, alerts, graph\n"
            "- Exports to CSV/TXT/PCAP\n"
            "- Windows-focused (Npcap required)"
        )


def main() -> None:
    root = tk.Tk()
    app = NetworkAnalyzer(root)
    root.mainloop()


if __name__ == "__main__":
    main()

 