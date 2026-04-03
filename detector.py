from scapy.all import IP, TCP
from ml_model import predict_anomaly
from logger import log_alert

scan_dict = {}
syn_count = {}

def analyze_packet(pkt):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        
        # --- Port Scan Detection ---
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            
            if src not in scan_dict:
                scan_dict[src] = set()
            scan_dict[src].add(dport)

            if len(scan_dict[src]) > 20:
                msg = f"[ALERT] Port Scan from {src}"
                print(msg)
                log_alert(msg)

        # --- SYN Flood ---
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            syn_count[src] = syn_count.get(src, 0) + 1
            
            if syn_count[src] > 50:
                msg = f"[ALERT] SYN Flood from {src}"
                print(msg)
                log_alert(msg)

        # --- ML Detection ---
        if predict_anomaly(pkt):
            msg = f"[ML ALERT] Suspicious packet from {src}"
            print(msg)
            log_alert(msg)