import threading
from sniffer import start_sniffing
from gui import start_gui

if __name__ == "__main__":
    t1 = threading.Thread(target=start_sniffing)
    t1.daemon = True
    t1.start()

    start_gui()