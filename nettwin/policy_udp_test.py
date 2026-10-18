
"""NetTwin UDP echo server and client helpers."""

import json
import socket
import sys


def server(address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, port))

    try:
        while True:
            data, peer = sock.recvfrom(4096)
            sock.sendto(data, peer)
    finally:
        sock.close()


def client(source_ip, destination_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    try:
        sock.bind((source_ip, 0))

        payload = b"NETTWIN_UDP_TEST"
        sock.sendto(payload, (destination_ip, port))

        response, _ = sock.recvfrom(4096)

        print(json.dumps({
            "allowed": response == payload,
            "response_received": True,
            "response_matches": response == payload,
        }))

    except socket.timeout:
        print(json.dumps({
            "allowed": False,
            "response_received": False,
            "response_matches": False,
        }))

    finally:
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python3 -m nettwin.policy_udp_test server|client ...")

    mode = sys.argv[1]

    if mode == "server" and len(sys.argv) == 4:
        server(sys.argv[2], int(sys.argv[3]))

    elif mode == "client" and len(sys.argv) == 5:
        client(sys.argv[2], sys.argv[3], int(sys.argv[4]))

    else:
        raise SystemExit("Invalid arguments")
