import threading
from sniffer import start_sniffing
from gui import start_gui
from geoip_utils import init_geoip   # 👈 ADD

if __name__ == "__main__":

    init_geoip()   # 👈 👈 IMPORTANT (1 बार call)

    t1 = threading.Thread(target=start_sniffing)
    t1.daemon = True
    t1.start()

    start_gui()
