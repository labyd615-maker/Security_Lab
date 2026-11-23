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

SERVER_IP = "0.0.0.0"
SERVER_PORT = 9090

CERT_FILE = "/volumes/certs/server/server.crt"
KEY_FILE  = "/volumes/certs/server/server.key"


# -------------------------------------------------
# TLS packet framing
# -------------------------------------------------
def recv_exact(sock, n):
    data = b""

    while len(data) < n:
        chunk = sock.recv(n - len(data))

        if not chunk:
            return None

        data += chunk

    return data


def recv_packet(sock):
    header = recv_exact(sock, 4)

    if header is None:
        return None

    length = struct.unpack("!I", header)[0]

    if length <= 0 or length > 65535:
        raise ValueError("Invalid packet length")

    return recv_exact(sock, length)


def send_packet(sock, data):
    sock.sendall(
        struct.pack("!I", len(data)) + data
    )


# -------------------------------------------------
# Pipe framing
# -------------------------------------------------
def pipe_write(fd, data):
    message = struct.pack("!I", len(data)) + data
    sent = 0

    while sent < len(message):
        n = os.write(fd, message[sent:])
        sent += n


def pipe_read_exact(fd, n):
    data = b""

    while len(data) < n:
        chunk = os.read(fd, n - len(data))

        if not chunk:
            return None

        data += chunk

    return data


def pipe_read(fd):
    header = pipe_read_exact(fd, 4)

    if header is None:
        return None

    length = struct.unpack("!I", header)[0]

    return pipe_read_exact(fd, length)


# -------------------------------------------------
# Bonus 1 authentication
# -------------------------------------------------
def authenticate_user(username, password):
    try:
        shadow_entry = spwd.getspnam(username)
        stored_hash = shadow_entry.sp_pwdp

        if (
            not stored_hash
            or stored_hash.startswith("!")
            or stored_hash.startswith("*")
        ):
            return False

        return crypt.crypt(
            password,
            stored_hash
        ) == stored_hash

    except KeyError:
        return False


# -------------------------------------------------
# Child process: owns one TLS tunnel
# -------------------------------------------------
def handle_client(
    raw_conn,
    client_address,
    parent_pipe_write,
    child_pipe_read,
    context,
    tun_fd
):

    # Child must not directly access the shared TUN.
    os.close(tun_fd)

    tls_sock = None

    try:
        tls_sock = context.wrap_socket(
            raw_conn,
            server_side=True
        )

        print(
            "[Child {}] TLS connected from {}".format(
                os.getpid(),
                client_address
            )
        )

        print(
            "[Child {}] TLS version: {}".format(
                os.getpid(),
                tls_sock.version()
            )
        )

        # Authentication
        username_data = recv_packet(tls_sock)
        password_data = recv_packet(tls_sock)

        if username_data is None or password_data is None:
            raise SystemExit

        username = username_data.decode("utf-8")
        password = password_data.decode("utf-8")

        if authenticate_user(username, password):
            print(
                "[Child {}] Authentication successful for: {}".format(
                    os.getpid(),
                    username
                )
            )
            send_packet(tls_sock, b"AUTH_OK")

        else:
            print(
                "[Child {}] Authentication failed for: {}".format(
                    os.getpid(),
                    username
                )
            )
            send_packet(tls_sock, b"AUTH_FAIL")
            raise SystemExit

        # Receive this client's TUN IP
        registration = recv_packet(tls_sock)

        if registration is None:
            raise SystemExit

        registration = registration.decode("utf-8")

        if not registration.startswith("REGISTER:"):
            raise ValueError("Missing client registration")

        tun_ip = registration.split(":", 1)[1]

        print(
            "[Child {}] Registered client TUN IP: {}".format(
                os.getpid(),
                tun_ip
            )
        )

        # Tell parent which virtual address belongs to this child.
        pipe_write(
            parent_pipe_write,
            ("REGISTER:" + tun_ip).encode("utf-8")
        )

        # Forward data between TLS and parent pipe.
        while True:

            ready, _, _ = select.select(
                [tls_sock, child_pipe_read],
                [],
                []
            )

            for fd in ready:

                # Client -> TLS -> child -> pipe -> parent
                if fd is tls_sock:

                    data = recv_packet(tls_sock)

                    if data is None:
                        print(
                            "[Child {}] Client disconnected".format(
                                os.getpid()
                            )
                        )
                        return

                    pkt = IP(data)

                    print(
                        "[Child {}] TLS -> Parent: {} -> {}".format(
                            os.getpid(),
                            pkt.src,
                            pkt.dst
                        )
                    )

                    pipe_write(
                        parent_pipe_write,
                        b"PACKET:" + data
                    )

                # Parent -> pipe -> child -> TLS -> client
                elif fd == child_pipe_read:

                    data = pipe_read(child_pipe_read)

                    if data is None:
                        return

                    pkt = IP(data)

                    print(
                        "[Child {}] Parent -> TLS: {} -> {}".format(
                            os.getpid(),
                            pkt.src,
                            pkt.dst
                        )
                    )

                    send_packet(
                        tls_sock,
                        data
                    )

    except Exception as e:
        print(
            "[Child {}] Error: {}".format(
                os.getpid(),
                e
            )
        )

    finally:
        if tls_sock is not None:
            tls_sock.close()

        os.close(parent_pipe_write)
        os.close(child_pipe_read)


# -------------------------------------------------
# Create server TUN interface
# Parent process owns this interface.
# -------------------------------------------------
tun = os.open(
    "/dev/net/tun",
    os.O_RDWR
)

ifr = struct.pack(
    "16sH",
    b"refai%d",
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

print("Server TUN interface:", ifname)

os.system(
    "ip addr add 192.168.53.11/24 dev {}".format(
        ifname
    )
)

os.system(
    "ip link set dev {} up".format(
        ifname
    )
)


# -------------------------------------------------
# TLS context
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


# -------------------------------------------------
# Listening socket
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

listen_sock.listen(10)

print(
    "Multi-client TLS VPN server listening on port",
    SERVER_PORT
)


# -------------------------------------------------
# Parent state
#
# pipe_read_fds:
#   child-to-parent pipe descriptors
#
# tun_to_child:
#   maps virtual TUN IP -> parent-to-child pipe
# -------------------------------------------------
pipe_read_fds = []

child_info = {}

tun_to_child = {}


# -------------------------------------------------
# Parent event loop
# -------------------------------------------------
while True:

    watch_list = [
        listen_sock,
        tun
    ] + pipe_read_fds

    ready, _, _ = select.select(
        watch_list,
        [],
        []
    )

    for fd in ready:

        # -----------------------------------------
        # New client: create one child + two pipes
        # -----------------------------------------
        if fd is listen_sock:

            raw_conn, client_address = listen_sock.accept()

            # child -> parent
            c2p_read, c2p_write = os.pipe()

            # parent -> child
            p2c_read, p2c_write = os.pipe()

            pid = os.fork()

            if pid == 0:
                # Child
                listen_sock.close()

                os.close(c2p_read)
                os.close(p2c_write)

                handle_client(
                    raw_conn,
                    client_address,
                    c2p_write,
                    p2c_read,
                    context,
                    tun
                )

                os._exit(0)

            else:
                # Parent
                raw_conn.close()

                os.close(c2p_write)
                os.close(p2c_read)

                pipe_read_fds.append(
                    c2p_read
                )

                child_info[c2p_read] = {
                    "pid": pid,
                    "write_fd": p2c_write,
                    "tun_ip": None
                }

                print(
                    "[Parent] Created child {} for {}".format(
                        pid,
                        client_address
                    )
                )

        # -----------------------------------------
        # Packet returned from private network
        # Parent reads TUN and chooses child based
        # on the inner destination IP.
        # -----------------------------------------
        elif fd == tun:

            packet = os.read(
                tun,
                65535
            )

            pkt = IP(packet)

            destination = pkt.dst

            print(
                "[Parent] TUN packet: {} -> {}".format(
                    pkt.src,
                    destination
                )
            )

            child_pipe = tun_to_child.get(
                destination
            )

            if child_pipe is None:
                print(
                    "[Parent] No tunnel registered for",
                    destination
                )
                continue

            print(
                "[Parent] Dispatching {} to correct child pipe".format(
                    destination
                )
            )

            pipe_write(
                child_pipe,
                packet
            )

        # -----------------------------------------
        # Message from one child
        # -----------------------------------------
        else:

            message = pipe_read(fd)

            if message is None:
                print(
                    "[Parent] Child pipe closed"
                )

                info = child_info.pop(
                    fd,
                    None
                )

                if info is not None:

                    if info["tun_ip"] in tun_to_child:
                        del tun_to_child[
                            info["tun_ip"]
                        ]

                    os.close(
                        info["write_fd"]
                    )

                pipe_read_fds.remove(fd)
                os.close(fd)

                continue

            # Child registration
            if message.startswith(b"REGISTER:"):

                tun_ip = (
                    message
                    .decode("utf-8")
                    .split(":", 1)[1]
                )

                child_info[fd]["tun_ip"] = tun_ip

                tun_to_child[tun_ip] = (
                    child_info[fd]["write_fd"]
                )

                print(
                    "[Parent] Registered {} -> child PID {}".format(
                        tun_ip,
                        child_info[fd]["pid"]
                    )
                )

            # Packet from client side
            elif message.startswith(b"PACKET:"):

                packet = message[
                    len(b"PACKET:"):
                ]

                pkt = IP(packet)

                print(
                    "[Parent] Child packet: {} -> {}".format(
                        pkt.src,
                        pkt.dst
                    )
                )

                os.write(
                    tun,
                    packet
                )
