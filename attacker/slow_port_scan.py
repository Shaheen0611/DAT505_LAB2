
import time
import random
from scapy.all import *

target_ip = "192.168.1.10"
ports = [22, 80, 443, 8080, 3306]

def slow_port_scan():
    for port in ports:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(random.uniform(0.5, 2.0))

if __name__ == "__main__":
    slow_port_scan()
