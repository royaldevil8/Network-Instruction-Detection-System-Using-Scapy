from scapy.all import IP, TCP
from ml_model import predict_anomaly
from logger import log_alert
from gui import push_packet
from dashboard import add_packet

import os
import time

# ------------------ TRACKING ------------------
scan_dict = {}
syn_count = {}
icmp_count = {}

blocked_ips = set()
block_time = {}
BLOCK_DURATION = 60   # seconds (test के लिए, बाद में 300 कर सकते हो)

# ------------------ BLOCK FUNCTIONS ------------------
def block_ip(ip):
    if ip not in blocked_ips:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)
        block_time[ip] = time.time()
        print(f"[BLOCKED] {ip}")

def unblock_ip(ip):
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    blocked_ips.discard(ip)
    block_time.pop(ip, None)
    print(f"[UNBLOCKED] {ip}")

# ------------------ MAIN ANALYSIS ------------------
def analyze_packet(pkt):

    # --- AUTO UNBLOCK CHECK ---
    current_time = time.time()
    for ip in list(blocked_ips):
        if current_time - block_time.get(ip, 0) > BLOCK_DURATION:
            unblock_ip(ip)

    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    length = len(pkt)

    status = "OK"

    # ------------------ PORT SCAN ------------------
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

    # ------------------ SYN FLOOD ------------------
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        syn_count[src] = syn_count.get(src, 0) + 1

        if syn_count[src] > 50:
            status = "ALERT"
            msg = f"[ALERT] SYN Flood from {src}"
            print(msg)
            log_alert(msg)

            # SMART BLOCK
            if syn_count[src] > 100:
                block_ip(src)

    # ------------------ ICMP FLOOD ------------------
    if proto == 1:
        icmp_count[src] = icmp_count.get(src, 0) + 1

        if icmp_count[src] > 30:
            status = "ALERT"
            msg = f"[ALERT] ICMP Flood from {src}"
            print(msg)
            log_alert(msg)

            # SMART BLOCK
            if icmp_count[src] > 80:
                block_ip(src)

    # ------------------ ML DETECTION ------------------
    if False:
        status = "ALERT"
        msg = f"[ML ALERT] Suspicious packet from {src}"
        print(msg)
        log_alert(msg)

    # ------------------ GUI PUSH ------------------
    data = {
        "src": src,
        "dst": dst,
        "proto": proto,
        "len": length,
        "status": status
    }

    push_packet(data)   # GUI
    add_packet(data)    # WEB DASHBOARD


