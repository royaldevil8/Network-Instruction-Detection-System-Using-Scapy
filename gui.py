
import tkinter as tk
from tkinter import ttk, filedialog
from collections import Counter
from scapy.all import wrpcap, Ether
import os
from shared import packet_queue


class NIDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NIDS-Monitor")
        self.root.geometry("1400x800")

        self.packet_map = {}
        self.all_packets = []
        self.total = 0
        self.protocol_counter = Counter()

        self.blink = False
        self.alert_items = set()

        self.auto_scroll = tk.BooleanVar(value=True)

        # 🔍 Search
        self.filter_text = tk.StringVar()
        tk.Entry(root, textvariable=self.filter_text).pack(fill="x")

        # 🔥 FILTER BAR
        filter_frame = tk.Frame(root)
        filter_frame.pack(fill="x")

        self.proto_filter = tk.StringVar(value="ALL")
        self.status_filter = tk.StringVar(value="ALL")

        tk.Label(filter_frame, text="Protocol:").pack(side="left")
        tk.OptionMenu(filter_frame, self.proto_filter, "ALL", "TCP", "UDP", "ICMP").pack(side="left")

        tk.Label(filter_frame, text="Status:").pack(side="left")
        tk.OptionMenu(filter_frame, self.status_filter, "ALL", "OK", "ALERT").pack(side="left")

        tk.Checkbutton(filter_frame, text="Auto Scroll", variable=self.auto_scroll).pack(side="left")

        # 📊 TABLE
        table_frame = tk.Frame(root)
        table_frame.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(table_frame)
        scrollbar.pack(side="right", fill="y")

        columns = ("SRC", "DST", "PROTO", "LEN", "STATUS", "COUNTRY")

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            yscrollcommand=scrollbar.set
        )

        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c, False))
            self.tree.column(col, anchor="center", width=120)

        self.tree.column("COUNTRY", width=200)

        self.tree.pack(fill="both", expand=True)
        scrollbar.config(command=self.tree.yview)

        # EVENTS
        self.tree.bind("<<TreeviewSelect>>", self.show_details)
        self.tree.bind("<Motion>", self.on_hover)

        # DETAILS
        self.details = tk.Text(root, height=10, bg="#0d1117", fg="lightgreen")
        self.details.pack(fill="x")

        # BUTTONS
        btn_frame = tk.Frame(root)
        btn_frame.pack()

        tk.Button(btn_frame, text="Export PCAP", command=self.export_pcap).pack(side="left")
        tk.Button(btn_frame, text="Analysis", command=self.show_analysis).pack(side="left")
        tk.Button(btn_frame, text="Block IP", command=self.block_selected_ip).pack(side="left")
        tk.Button(btn_frame, text="Unblock IP", command=self.unblock_selected_ip).pack(side="left")

        # COLORS
        self.tree.tag_configure("tcp", foreground="cyan")
        self.tree.tag_configure("udp", foreground="orange")
        self.tree.tag_configure("icmp", foreground="black")
        self.tree.tag_configure("normal", foreground="lightgreen")

        self.tree.tag_configure("alert_on", background="#ff1a1a", foreground="white")
        self.tree.tag_configure("alert_off", background="#660000", foreground="white")

        self.tree.tag_configure("hover", background="#2c3e50")

        self.update_gui()
        self.blink_alerts()

    # FLAG
    def flag(self, code):
        try:
            return "".join(chr(127397 + ord(c)) for c in code)
        except:
            return ""

    # BLOCK
    def block_selected_ip(self):
        selected = self.tree.focus()
        if not selected:
            return

        pkt = self.packet_map.get(selected)
        if not pkt:
            return

        ip = pkt["src"]
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

    # UNBLOCK
    def unblock_selected_ip(self):
        selected = self.tree.focus()
        if not selected:
            return

        pkt = self.packet_map.get(selected)
        if not pkt:
            return

        ip = pkt["src"]
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")

    # HOVER
    def on_hover(self, event):
        row = self.tree.identify_row(event.y)

        for item in self.tree.get_children():
            tags = list(self.tree.item(item, "tags"))
            if "hover" in tags:
                tags.remove("hover")
                self.tree.item(item, tags=tags)

        if row:
            tags = list(self.tree.item(row, "tags"))
            if "hover" not in tags:
                tags.append("hover")
            self.tree.item(row, tags=tags)

    # SORT
    def sort_column(self, col, reverse):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]

        try:
            data.sort(key=lambda t: int(t[0]), reverse=reverse)
        except:
            data.sort(reverse=reverse)

        for index, (_, k) in enumerate(data):
            self.tree.move(k, '', index)

    # MAIN LOOP
    def update_gui(self):
        is_at_bottom = self.tree.yview()[1] >= 0.98

        while not packet_queue.empty():
            data = packet_queue.get()

            self.all_packets.append(data)
            self.total += 1
            self.protocol_counter[data["proto"]] += 1

            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(data["proto"], "OTHER")

            # FILTERS
            if self.filter_text.get() and self.filter_text.get() not in data["src"]:
                continue
            if self.proto_filter.get() != "ALL" and proto_name != self.proto_filter.get():
                continue
            if self.status_filter.get() != "ALL" and data["status"] != self.status_filter.get():
                continue

            # COUNTRY FIX
            code = data.get("country_code", "??")
            name = data.get("country_name", "")

            if not name:
                name = "Local"

            if code == "??" or len(code) != 2:
                flag_icon = ""
            else:
                flag_icon = self.flag(code)

            country = f"{flag_icon} {code} - {name}"

            # TAG
            if data["status"] == "ALERT":
                tag = "alert_on"
            elif data["proto"] == 6:
                tag = "tcp"
            elif data["proto"] == 17:
                tag = "udp"
            elif data["proto"] == 1:
                tag = "icmp"
            else:
                tag = "normal"

            item = self.tree.insert(
                "",
                "end",
                values=(
                    data["src"],
                    data["dst"],
                    data["proto"],
                    data["len"],
                    data["status"],
                    country
                ),
                tags=(tag,)
            )

            if data["status"] == "ALERT":
                self.alert_items.add(item)

            self.packet_map[item] = data

        if self.auto_scroll.get() and is_at_bottom:
            self.tree.yview_moveto(1.0)

        self.root.after(200, self.update_gui)

    # BLINK
    def blink_alerts(self):
        self.blink = not self.blink

        for item in list(self.alert_items):
            if not self.tree.exists(item):
                self.alert_items.remove(item)
                continue

            tags = list(self.tree.item(item, "tags"))
            tags = [t for t in tags if t not in ("alert_on", "alert_off")]
            tags.append("alert_on" if self.blink else "alert_off")

            self.tree.item(item, tags=tags)

        self.root.after(400, self.blink_alerts)

    # DETAILS
    def show_details(self, event):
        selected = self.tree.focus()
        if not selected:
            return

        pkt = self.packet_map.get(selected)
        if not pkt:
            return

        text = f"""
SRC: {pkt['src']}
DST: {pkt['dst']}
PROTO: {pkt['proto']}
LEN: {pkt['len']}
STATUS: {pkt['status']}
"""

        self.details.delete("1.0", tk.END)
        self.details.insert(tk.END, text)

    # EXPORT
    def export_pcap(self):
        file = filedialog.asksaveasfilename(defaultextension=".pcap")
        if not file:
            return

        packets = []
        for pkt in self.all_packets:
            try:
                packets.append(Ether(bytes.fromhex(pkt.get("raw", ""))))
            except:
                pass

        wrpcap(file, packets)

    # ANALYSIS
    def show_analysis(self):
        top_ip = Counter([p["src"] for p in self.all_packets]).most_common(1)

        text = f"""
Total Packets: {self.total}
Top Attacker: {top_ip}
Protocol Stats: {dict(self.protocol_counter)}
"""

        self.details.delete("1.0", tk.END)
        self.details.insert(tk.END, text)


def start_gui():
    root = tk.Tk()
    app = NIDSGUI(root)
    root.mainloop()
