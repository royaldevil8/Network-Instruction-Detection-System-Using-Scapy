from scapy.all import IP, TCP
from logger import log_alert
from shared import packet_queue
from geoip_utils import init_geoip, get_country_info

# OPTIONAL dashboard
try:
    from dashboard import add_packet
except:
    add_packet = None

import os
import time
import ipaddress

# ------------------ INIT GEOIP ------------------
init_geoip()

# ------------------ TRACKING ------------------
scan_dict = {}
syn_count = {}
icmp_count = {}
last_seen = {}

blocked_ips = set()
block_time = {}

BLOCK_DURATION = 60
RESET_TIME = 30


# ------------------ HELPERS ------------------
def is_private(ip):
    try:
        return not ipaddress.ip_address(ip).is_global
    except:
        return True


def get_public_ip(src, dst):
    """
    Pick correct IP for GeoIP
    """
    if not is_private(src):
        return src
    if not is_private(dst):
        return dst
    return src   # fallback


# ------------------ BLOCK ------------------
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


# ------------------ RESET ------------------
def reset_if_needed(src):
    now = time.time()
    if src in last_seen and now - last_seen[src] > RESET_TIME:
        syn_count[src] = 0
        icmp_count[src] = 0
        scan_dict[src] = set()
    last_seen[src] = now


# ------------------ MAIN ------------------
def analyze_packet(pkt):

    # AUTO UNBLOCK
    now = time.time()
    for ip in list(blocked_ips):
        if now - block_time.get(ip, 0) > BLOCK_DURATION:
            unblock_ip(ip)

    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    length = len(pkt)

    reset_if_needed(src)

    status = "OK"

    # ------------------ PORT SCAN ------------------
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        scan_dict.setdefault(src, set()).add(dport)

        if len(scan_dict[src]) > 20:
            status = "ALERT"
            msg = f"[ALERT] Port Scan from {src}"
            print(msg)
            log_alert(msg)

    # ------------------ SYN FLOOD ------------------
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags

        if flags & 0x02:  # SYN
            syn_count[src] = syn_count.get(src, 0) + 1

            if syn_count[src] > 50:
                status = "ALERT"
                log_alert(f"[ALERT] SYN Flood from {src}")

            if syn_count[src] > 120:
                block_ip(src)

    # ------------------ ICMP FLOOD ------------------
    if proto == 1:
        icmp_count[src] = icmp_count.get(src, 0) + 1

        if icmp_count[src] > 50:
            status = "ALERT"
            log_alert(f"[ALERT] ICMP Flood from {src}")

        if icmp_count[src] > 120:
            block_ip(src)

    # ------------------ GEOIP FIX (MAIN CHANGE) ------------------
    ip_for_geo = get_public_ip(src, dst)
    code, name = get_country_info(ip_for_geo)

    # ------------------ SAFE RAW HEX ------------------
    try:
        raw_data = bytes(pkt)[:100].hex()
    except:
        raw_data = "N/A"

    # ------------------ DATA ------------------
    data = {
        "src": src,
        "dst": dst,
        "proto": proto,
        "len": length,
        "status": status,
        "raw": raw_data,
        "country_code": code,     # 👈 IMPORTANT
        "country_name": name      # 👈 IMPORTANT
    }

    # ------------------ OUTPUT ------------------
    packet_queue.put(data)

    if add_packet:
        add_packet(data)
