#!/usr/bin/env python3

import fcntl
import struct
import os
import select
import socket
import ssl
import spwd
import crypt
from scapy.all import IP

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

# -------------------------------------------------
# Create and configure the TUN interface
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
    "ip addr add 192.168.53.11/24 dev {}".format(ifname)
)

os.system(
    "ip link set dev {} up".format(ifname)
)

# -------------------------------------------------
# TLS server settings
# -------------------------------------------------
SERVER_IP = "0.0.0.0"
SERVER_PORT = 9090

CERT_FILE = "/volumes/certs/server/server.crt"
KEY_FILE  = "/volumes/certs/server/server.key"


# -------------------------------------------------
# TCP framing functions
# TCP is a byte stream, so each IP packet is
# preceded by a 4-byte packet length.
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
# Create TCP listening socket
# -------------------------------------------------
listen_sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

listen_sock.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

listen_sock.bind(
    (SERVER_IP, SERVER_PORT)
)

listen_sock.listen(5)


# -------------------------------------------------
# Create TLS context and load server identity
# -------------------------------------------------
context = ssl.SSLContext(
    ssl.PROTOCOL_TLS_SERVER
)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(
    certfile=CERT_FILE,
    keyfile=KEY_FILE
)

print(
    "VPN TLS server listening on port {}".format(
        SERVER_PORT
    )
)


# -------------------------------------------------
# Wait for VPN client
# -------------------------------------------------
raw_conn, client_address = listen_sock.accept()

print(
    "TCP connection from:",
    client_address
)

tls_sock = context.wrap_socket(
    raw_conn,
    server_side=True
)

print("TLS handshake successful")
print("TLS version:", tls_sock.version())
print("Cipher:", tls_sock.cipher())
# Bonus 1: authenticate client using /etc/shadow
def authenticate_user(username, password):
    try:
        shadow_entry = spwd.getspnam(username)
        stored_hash = shadow_entry.sp_pwdp

        if not stored_hash or stored_hash.startswith("!") or stored_hash.startswith("*"):
            return False

        return crypt.crypt(password, stored_hash) == stored_hash

    except KeyError:
        return False


username_data = recv_packet(tls_sock)
password_data = recv_packet(tls_sock)

if username_data is None or password_data is None:
    print("Authentication data missing")
    tls_sock.close()
    raise SystemExit

username = username_data.decode("utf-8")
password = password_data.decode("utf-8")

if authenticate_user(username, password):
    print("Client authentication successful for:", username)
    send_packet(tls_sock, b"AUTH_OK")
else:
    print("Client authentication failed for:", username)
    send_packet(tls_sock, b"AUTH_FAIL")
    tls_sock.close()
    raise SystemExit

# -------------------------------------------------
# Forward traffic in both directions
# -------------------------------------------------
try:
    while True:

        # SSL may already have decrypted data buffered.
        if tls_sock.pending() > 0:
            ready = [tls_sock]
        else:
            ready, _, _ = select.select(
                [tls_sock, tun],
                [],
                []
            )

        for fd in ready:

            # TLS tunnel -> TUN
            if fd is tls_sock:

                data = recv_packet(tls_sock)

                if data is None:
                    print("VPN client disconnected")
                    raise SystemExit

                pkt = IP(data)

                print(
                    "From TLS  <==: {} --> {}".format(
                        pkt.src,
                        pkt.dst
                    )
                )

                os.write(tun, data)

            # TUN -> TLS tunnel
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
    listen_sock.close()
    os.close(tun)
