from scapy.all import sniff, IP, TCP
from detector import analyze_packet

def process_packet(pkt):
    if pkt.haslayer(IP):
        analyze_packet(pkt)

def start_sniffing():
    sniff(prn=process_packet, store=False)