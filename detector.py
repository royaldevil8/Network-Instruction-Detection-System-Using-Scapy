from scapy.all import IP, TCP
from ml_model import predict_anomaly
from logger import log_alert
from gui import push_packet   # 👈 IMPORTANT

scan_dict = {}
syn_count = {}

def analyze_packet(pkt):

    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    length = len(pkt)

    status = "OK"

    # --- Port Scan Detection ---
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport

        if src not in scan_dict:
            scan_dict[src] = set()

        scan_dict[src].add(dport)

        if len(scan_dict[src]) > 20:
            status = "ALERT"
            msg = f"[ALERT] Port Scan from {src}"
            print(msg)
            log_alert(msg)

    # --- SYN Flood ---
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        syn_count[src] = syn_count.get(src, 0) + 1

        if syn_count[src] > 50:
            status = "ALERT"
            msg = f"[ALERT] SYN Flood from {src}"
            print(msg)
            log_alert(msg)

    # --- ML Detection ---
    if predict_anomaly(pkt):
        status = "ALERT"
        msg = f"[ML ALERT] Suspicious packet from {src}"
        print(msg)
        log_alert(msg)

    # --- GUI PUSH (CRITICAL) ---
    push_packet({
        "src": src,
        "dst": dst,
        "proto": proto,
        "len": length,
        "status": status
    })
