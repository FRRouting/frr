#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nexthop AI
# Authored by Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""BGP speaker that stops reading once the session is up.

It opens the connection with a small receive buffer, sends its OPEN and then
a KEEPALIVE every second, and never reads anything. The router reaches
Established, its UPDATEs fill the connection, and its output stalls while
the speaker's KEEPALIVEs keep the hold timer happy, which is exactly the
condition the SendHoldTimer (RFC 9687) exists for.

The speaker exits once the router closes the connection, or after
RUN_TIME seconds.
"""

import socket
import struct
import sys
import time

ROUTER_IP = "10.0.0.1"
LOCAL_IP = "10.0.0.2"
LOCAL_AS = 65001
HOLD_TIME = 3
PORT = 179
RECV_BUFFER = 4096
CONNECT_TIME = 60
RUN_TIME = 120

MARKER = b"\xff" * 16
HEADER_LEN = 19
OPEN = 1
KEEPALIVE = 4


def log(fmt, *args):
    sys.stderr.write("stalledpeer: " + (fmt % args) + "\n")
    sys.stderr.flush()


def message(kind, body=b""):
    return MARKER + struct.pack("!HB", HEADER_LEN + len(body), kind) + body


def capability(code, value=b""):
    return struct.pack("!BB", code, len(value)) + value


def open_message():
    caps = capability(1, struct.pack("!HBB", 1, 0, 1))  # MP-BGP, IPv4 unicast
    caps += capability(65, struct.pack("!I", LOCAL_AS))  # 4-octet AS
    opt = struct.pack("!BB", 2, len(caps)) + caps
    body = struct.pack("!BHH", 4, LOCAL_AS, HOLD_TIME)
    body += socket.inet_aton(LOCAL_IP)
    body += struct.pack("!B", len(opt)) + opt
    return message(OPEN, body)


def connect():
    deadline = time.monotonic() + CONNECT_TIME
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set before connect(), so the advertised window stays small.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECV_BUFFER)
        try:
            sock.connect((ROUTER_IP, PORT))
            return sock
        except OSError as err:
            sock.close()
            if time.monotonic() > deadline:
                raise
            log("connect failed (%s), retrying", err)
            time.sleep(1)


def main():
    sock = connect()
    log("connected")
    sock.sendall(open_message())

    deadline = time.monotonic() + RUN_TIME
    try:
        while time.monotonic() < deadline:
            sock.sendall(message(KEEPALIVE))
            time.sleep(1)
    except OSError as err:
        log("router closed the connection (%s)", err)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
