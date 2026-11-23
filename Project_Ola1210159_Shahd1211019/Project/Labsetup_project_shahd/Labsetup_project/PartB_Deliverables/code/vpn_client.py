#!/usr/bin/env python3

import fcntl
import struct
import os
import select
import socket
import ssl
import sys
from scapy.all import IP

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

# -------------------------------------------------
# Server name must come from the command line
# -------------------------------------------------
if len(sys.argv) != 2:
    print("Usage: {} <server-name>".format(sys.argv[0]))
    sys.exit(1)

server_name = sys.argv[1]
server_port = 9090

# Resolve the same server name that will be
# checked against the TLS certificate
server_ip = socket.gethostbyname(server_name)

print("Server name:", server_name)
print("Resolved IP:", server_ip)


# -------------------------------------------------
# Create and configure TUN interface
# -------------------------------------------------
tun = os.open("/dev/net/tun", os.O_RDWR)

ifr = struct.pack(
    '16sH',
    b'refai%d',
    IFF_TUN | IFF_NO_PI
)

ifname_bytes = fcntl.ioctl(
    tun,
    TUNSETIFF,
    ifr
)

ifname = (
    ifname_bytes
    .decode("UTF-8")[:16]
    .strip("\x00")
)

print("Interface Name:", ifname)

os.system(
    "ip addr add 192.168.53.99/24 dev {}".format(ifname)
)

os.system(
    "ip link set dev {} up".format(ifname)
)


# -------------------------------------------------
# TCP framing
# -------------------------------------------------
def recv_exact(sock, number_of_bytes):
    data = b""

    while len(data) < number_of_bytes:
        chunk = sock.recv(number_of_bytes - len(data))

        if not chunk:
            return None

        data += chunk

    return data


def recv_packet(sock):
    header = recv_exact(sock, 4)

    if header is None:
        return None

    packet_length = struct.unpack("!I", header)[0]

    if packet_length <= 0 or packet_length > 65535:
        raise ValueError("Invalid packet length")

    return recv_exact(sock, packet_length)


def send_packet(sock, packet):
    header = struct.pack("!I", len(packet))
    sock.sendall(header + packet)


# -------------------------------------------------
# TLS client configuration
# -------------------------------------------------
context = ssl.SSLContext(
    ssl.PROTOCOL_TLS_CLIENT
)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_2
# Trust only our project's CA
context.load_verify_locations(
    cafile="/volumes/certs/ca/ca.crt"
)

# Require a valid trusted certificate
context.verify_mode = ssl.CERT_REQUIRED

# Verify that the certificate identity matches
# the server name supplied on the command line
context.check_hostname = True


# -------------------------------------------------
# Connect using TCP
# -------------------------------------------------
raw_sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

raw_sock.connect(
    (server_ip, server_port)
)


# -------------------------------------------------
# Wrap TCP connection with TLS
# server_hostname triggers hostname verification
# -------------------------------------------------
tls_sock = context.wrap_socket(
    raw_sock,
    server_hostname=server_name
)

print("TLS handshake successful")
print("TLS version:", tls_sock.version())
print("Cipher:", tls_sock.cipher())

peer_cert = tls_sock.getpeercert()

print(
    "Server certificate subject:",
    peer_cert.get("subject")
)


# -------------------------------------------------
# Forward packets in both directions
# -------------------------------------------------
try:
    while True:

        if tls_sock.pending() > 0:
            ready = [tls_sock]
        else:
            ready, _, _ = select.select(
                [tls_sock, tun],
                [],
                []
            )

        for fd in ready:

            # TLS -> TUN
            if fd is tls_sock:

                data = recv_packet(tls_sock)

                if data is None:
                    print("VPN server disconnected")
                    raise SystemExit

                pkt = IP(data)

                print(
                    "From TLS  <==: {} --> {}".format(
                        pkt.src,
                        pkt.dst
                    )
                )

                os.write(tun, data)

            # TUN -> TLS
            if fd == tun:

                packet = os.read(
                    tun,
                    65535
                )

                pkt = IP(packet)

                print(
                    "From tun  ==>: {} --> {}".format(
                        pkt.src,
                        pkt.dst
                    )
                )

                send_packet(
                    tls_sock,
                    packet
                )

finally:
    tls_sock.close()
    os.close(tun)
