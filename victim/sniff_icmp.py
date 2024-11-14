
from scapy.all import *

def sniff_icmp(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        hidden_data = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
        print(f"Received hidden data: {hidden_data}")

if __name__ == "__main__":
    sniff(filter="icmp", prn=sniff_icmp)
