from scapy.all import sniff
from detector import analyze_packet

def process_packet(pkt):
    print(pkt.summary())
    analyze_packet(pkt)

def start_sniffing():
    sniff(prn=process_packet, store=False)
