from dashboard import run_dashboard
import threading
from sniffer import start_sniffing
from gui import start_gui


if __name__ == "__main__":
    t1 = threading.Thread(target=start_sniffing)
    t1.daemon = True
    t1.start()

    t2 = threading.Thread(target=run_dashboard)
    t2.daemon = True
    t2.start()

    start_gui()
