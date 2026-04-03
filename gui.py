import tkinter as tk

def start_gui():
    root = tk.Tk()
    root.title("NIDS Dashboard")

    label = tk.Label(root, text="NIDS Running...", font=("Arial", 16))
    label.pack(pady=20)

    root.mainloop()