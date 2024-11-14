
from scapy.all import *

target_ip = "192.168.1.10"
target_port = 80

def obfuscate_payload():
    ip_layer = IP(dst=target_ip)
    tcp_layer = TCP(dport=target_port, flags="PA")
    http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    payload = Raw(load=http_request + "MALICIOUS_PAYLOAD")
    pkt = ip_layer / tcp_layer / payload
    send(pkt, verbose=False)

if __name__ == "__main__":
    obfuscate_payload()
