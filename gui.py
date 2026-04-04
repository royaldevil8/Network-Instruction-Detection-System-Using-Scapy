import tkinter as tk
from tkinter import ttk
import queue
from collections import deque
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

packet_queue = queue.Queue()

def push_packet(data):
    packet_queue.put(data)


class NIDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NIDS - Live Monitor")
        self.root.geometry("1000x500")

        self.filter_mode = "ALL"

        # stats
        self.total = 0
        self.alerts = 0

        # buttons
        frame = tk.Frame(self.root)
        frame.pack()

        tk.Button(frame, text="ALL", command=lambda: self.set_filter("ALL")).pack(side="left")
        tk.Button(frame, text="ALERT", command=lambda: self.set_filter("ALERT")).pack(side="left")
        tk.Button(frame, text="TCP", command=lambda: self.set_filter("TCP")).pack(side="left")
        tk.Button(frame, text="ICMP", command=lambda: self.set_filter("ICMP")).pack(side="left")

        # table
        columns = ("SRC", "DST", "PROTO", "LEN", "STATUS")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)

        self.tree.pack(fill="both", expand=True)

        # color tags
        self.tree.tag_configure("normal", foreground="green")
        self.tree.tag_configure("alert", foreground="red")
        self.tree.tag_configure("tcp", foreground="blue")
        self.tree.tag_configure("udp", foreground="orange")
        self.tree.tag_configure("icmp", foreground="yellow")

        # graph
        self.packet_counts = deque(maxlen=50)

        fig, ax = plt.subplots()
        self.line, = ax.plot(self.packet_counts)

        canvas = FigureCanvasTkAgg(fig, master=self.root)
        canvas.get_tk_widget().pack()
        self.canvas = canvas
        self.ax = ax

        # label
        self.label = tk.Label(self.root, text="Total: 0 | Alerts: 0")
        self.label.pack()

        self.update_gui()

    def set_filter(self, mode):
        self.filter_mode = mode

    def update_gui(self):
        while not packet_queue.empty():
            data = packet_queue.get()

            if self.filter_mode == "ALERT" and data["status"] != "ALERT":
                continue
            if self.filter_mode == "TCP" and data["proto"] != 6:
                continue
            if self.filter_mode == "ICMP" and data["proto"] != 1:
                continue

            self.total += 1
            if data["status"] == "ALERT":
                self.alerts += 1

            if data["status"] == "ALERT":
                tag = "alert"
            elif data["proto"] == 6:
                tag = "tcp"
            elif data["proto"] == 17:
                tag = "udp"
            elif data["proto"] == 1:
                tag = "icmp"
            else:
                tag = "normal"

            self.tree.insert("", "end",
                values=(data["src"], data["dst"], data["proto"], data["len"], data["status"]),
                tags=(tag,)
            )

        self.label.config(text=f"Total: {self.total} | Alerts: {self.alerts}")

        # graph update
        if not hasattr(self, "last_total"):
            self.last_total = 0

        diff = self.total - self.last_total
        self.last_total = self.total

        self.packet_counts.append(diff)
        self.line.set_ydata(self.packet_counts)
        self.line.set_xdata(range(len(self.packet_counts)))

        self.ax.relim()
        self.ax.autoscale_view()
        self.canvas.draw()

        self.root.after(200, self.update_gui)


def start_gui():
    root = tk.Tk()
    app = NIDSGUI(root)
    root.mainloop()
