import tkinter as tk
from tkinter import ttk
import queue

packet_queue = queue.Queue()

def push_packet(data):
    packet_queue.put(data)


class NIDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NIDS - Live Monitor")
        self.root.geometry("1000x500")

        # stats
        self.total = 0
        self.alerts = 0

        # table
        columns = ("SRC", "DST", "PROTO", "LEN", "STATUS")

        self.tree = ttk.Treeview(root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)

        self.tree.pack(fill="both", expand=True)

        # color tags
        self.tree.tag_configure("normal", foreground="green")
        self.tree.tag_configure("alert", foreground="red")

        # stats label
        self.label = tk.Label(root, text="Total: 0 | Alerts: 0")
        self.label.pack()

        self.update_gui()

    def update_gui(self):
        while not packet_queue.empty():
            data = packet_queue.get()

            self.total += 1
            if data["status"] == "ALERT":
                self.alerts += 1

            self.tree.insert(
                "", "end",
                values=(
                    data["src"],
                    data["dst"],
                    data["proto"],
                    data["len"],
                    data["status"]
                ),
                tags=("alert" if data["status"] == "ALERT" else "normal",)
            )

            # limit rows
            if len(self.tree.get_children()) > 100:
                self.tree.delete(self.tree.get_children()[0])

        self.label.config(text=f"Total: {self.total} | Alerts: {self.alerts}")

        self.root.after(200, self.update_gui)


def start_gui():
    root = tk.Tk()
    app = NIDSGUI(root)
    root.mainloop()
