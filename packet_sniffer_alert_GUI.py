#!/usr/bin/env python3
"""
Network Packet Sniffer with Alert System (NO EMAIL) + GUI + Database Logging
Author: Sneha H (Cybersecurity Student)
Dependencies: scapy, tkinter, sqlite3
Run as root/Administrator for live capture
"""

import threading
import queue
import time
import csv
import html
import sqlite3
from datetime import datetime
from scapy.all import sniff, Packet
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from collections import defaultdict
import os

# ========================================
# Detection Configuration
# ========================================
WINDOW = 10          # seconds between each anomaly check
THRESHOLD = 5        # packets per WINDOW per source IP (lower for testing)

# ========================================
# Database Setup (SQLite)
# ========================================
DB_NAME = "packets.db"
conn = sqlite3.connect(DB_NAME, check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS packets (
    time TEXT,
    src TEXT,
    dst TEXT,
    proto TEXT,
    length INTEGER
)
""")
conn.commit()

def log_packet_to_db(pkt_info):
    cursor.execute("INSERT INTO packets VALUES (?, ?, ?, ?, ?)", 
                   (pkt_info['time'], pkt_info['src'], pkt_info['dst'], pkt_info['proto'], pkt_info['len']))
    conn.commit()

# ========================================
# Alert System (NO EMAIL)
# ========================================
packet_count = defaultdict(int)
last_check = time.time()

def check_anomalies(pkt_info):
    """Detect potential floods or scans (with debug + test trigger)"""
    global last_check
    src = pkt_info.get("src", "N/A")
    packet_count[src] += 1

    # Debug: print packet counts in terminal
    print(f"[DEBUG] Packet from {src} | Count so far: {packet_count[src]}")

    # Force one quick test alert (when any IP reaches 5 packets) for visibility
    if packet_count[src] == 5:
        log_alert(f"TEST ALERT: 5 packets received from {src} (debug trigger)")

    # Every WINDOW seconds, check for anomalies
    if time.time() - last_check > WINDOW:
        print("[DEBUG] Checking for anomalies...")
        for ip, count in packet_count.items():
            print(f"[DEBUG] {ip} sent {count} packets in last {WINDOW}s")
            if ip != "N/A" and count > THRESHOLD:
                alert_msg = f"⚠️ Possible flood/scan detected from {ip} ({count} packets/{WINDOW}s)"
                log_alert(alert_msg)
        packet_count.clear()
        last_check = time.time()

def log_alert(message):
    """Log alert to file and print. (Email removed)"""
    try:
        with open("alerts.log", "a") as f:
            f.write(f"{datetime.now()} - {message}\n")
    except Exception as e:
        print(f"[!] Failed to write alerts.log: {e}")

    print(message)
    # NOTE: Email functionality intentionally removed.

# ========================================
# Packet Formatting
# ========================================
def format_packet_info(pkt: Packet):
    ts = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S")
    src = "N/A"
    dst = "N/A"
    if pkt.haslayer("IP"):
        src = pkt["IP"].src
        dst = pkt["IP"].dst
    elif pkt.haslayer("IPv6"):
        src = pkt["IPv6"].src
        dst = pkt["IPv6"].dst
    proto = pkt.lastlayer().name if pkt.lastlayer() else "N/A"
    length = len(pkt)
    summary = pkt.summary()
    return {"time": ts, "src": src, "dst": dst, "proto": proto, "len": length, "summary": summary, "raw": pkt}

# ========================================
# Sniffer Thread
# ========================================
class SnifferThread(threading.Thread):
    def __init__(self, pkt_queue: queue.Queue, stop_event: threading.Event, interface=None, bpf_filter=""):
        super().__init__(daemon=True)
        self.pkt_queue = pkt_queue
        self.stop_event = stop_event
        self.iface = interface
        self.filter = bpf_filter

    def run(self):
        def _stop_filter(pkt):
            return self.stop_event.is_set()

        try:
            sniff(iface=self.iface, filter=self.filter if self.filter else None,
                  prn=lambda p: self._handle_packet(p),
                  stop_filter=_stop_filter, store=False)
        except Exception as e:
            self.pkt_queue.put(("__error__", str(e)))

    def _handle_packet(self, pkt):
        info = format_packet_info(pkt)
        log_packet_to_db(info)           # Save to DB
        check_anomalies(info)            # Check anomalies
        self.pkt_queue.put(("packet", info))  # Push to GUI

# ========================================
# GUI
# ========================================
class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        root.title("Network Packet Sniffer with Alert & DB")
        root.geometry("1000x600")

        self.pkt_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.sniffer_thread = None
        self.captured = []

        self._build_ui()
        self.root.after(200, self._poll_queue)

    def _build_ui(self):
        ctrl = ttk.Frame(self.root)
        ctrl.pack(fill="x", padx=8, pady=6)

        ttk.Label(ctrl, text="Interface:").pack(side="left")
        self.iface_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self.iface_var, width=12).pack(side="left", padx=4)

        ttk.Label(ctrl, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self.filter_var, width=30).pack(side="left", padx=4)

        self.start_btn = ttk.Button(ctrl, text="Start", command=self.start_sniffing)
        self.start_btn.pack(side="left", padx=6)
        self.stop_btn = ttk.Button(ctrl, text="Stop", command=self.stop_sniffing, state="disabled")
        self.stop_btn.pack(side="left")

        ttk.Button(ctrl, text="Export CSV", command=self.export_csv).pack(side="right", padx=4)
        ttk.Button(ctrl, text="Export HTML", command=self.export_html).pack(side="right")

        columns = ("#", "time", "src", "dst", "proto", "len", "summary")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120 if col != "summary" else 300)
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.detail_text = tk.Text(self.root, height=10)
        self.detail_text.pack(fill="x", padx=8, pady=4)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x")

    def start_sniffing(self):
        iface = self.iface_var.get().strip() or None
        filt = self.filter_var.get().strip() or ""
        self.stop_event.clear()
        self.sniffer_thread = SnifferThread(self.pkt_queue, self.stop_event, iface, filt)
        self.sniffer_thread.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set(f"Sniffing... (Interface: {iface or 'default'})")

    def stop_sniffing(self):
        self.stop_event.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set(f"Stopped. Captured {len(self.captured)} packets.")

    def _poll_queue(self):
        try:
            while True:
                item = self.pkt_queue.get_nowait()
                if item[0] == "packet":
                    info = item[1]
                    self._add_packet(info)
                elif item[0] == "__error__":
                    messagebox.showerror("Error", item[1])
                self.pkt_queue.task_done()
        except queue.Empty:
            pass
        self.root.after(200, self._poll_queue)

    def _add_packet(self, info):
        idx = len(self.captured) + 1
        self.captured.append(info)
        self.tree.insert("", "end", values=(idx, info["time"], info["src"], info["dst"], info["proto"], info["len"], info["summary"]))

    def on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(self.tree.item(sel[0], "values")[0]) - 1
        pkt = self.captured[idx]["raw"]
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", pkt.show(dump=True))

    def export_csv(self):
        if not self.captured:
            messagebox.showinfo("No Data", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "time", "src", "dst", "proto", "len", "summary"])
            for i, p in enumerate(self.captured, start=1):
                writer.writerow([i, p["time"], p["src"], p["dst"], p["proto"], p["len"], p["summary"]])
        messagebox.showinfo("Exported", f"Saved CSV to {path}")

    def export_html(self):
        if not self.captured:
            messagebox.showinfo("No Data", "No packets to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write("<html><head><title>Packet Report</title></head><body>")
            f.write("<h2>Packet Capture Report</h2><table border='1'>")
            f.write("<tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Length</th><th>Summary</th></tr>")
            for i, p in enumerate(self.captured, start=1):
                f.write(f"<tr><td>{i}</td><td>{p['time']}</td><td>{p['src']}</td><td>{p['dst']}</td><td>{p['proto']}</td><td>{p['len']}</td><td>{html.escape(p['summary'])}</td></tr>")
            f.write("</table></body></html>")
        messagebox.showinfo("Exported", f"Saved HTML to {path}")

# ========================================
# Main Entry
# ========================================
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
