#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026, Cisco Systems, Inc.
# Nageswara Soma <nsoma@cisco.com>

"""Hold a BGP zserv session open until the test releases it.

This models bgpd's synchronous label-manager client: ZEBRA_ROUTE_BGP,
session_id != 0, and no graceful-restart capability. The test watches
`show zebra client` and then creates the release file so this process
exits and zebra sees the disconnect.
"""

import os
import socket
import struct
import sys

# lib/zclient.h: ZEBRA_HEADER_MARKER, ZSERV_VERSION, ZEBRA_HELLO.
ZEBRA_HEADER_MARKER = 254
ZSERV_VERSION = 6
ZEBRA_HEADER_SIZE = 10
ZEBRA_HELLO = 19

# lib/route_types.txt order. ZEBRA_ROUTE_BGP is the redist_default bgpd
# puts on the label-manager zclient.
ZEBRA_ROUTE_BGP = 10


def zebra_hello(session_id):
    """Build one synchronous BGP ZEBRA_HELLO for session_id."""
    body = struct.pack("!BHIB", ZEBRA_ROUTE_BGP, 0, session_id, 1)
    length = ZEBRA_HEADER_SIZE + len(body)
    header = struct.pack(
        "!HBBIH",
        length,
        ZEBRA_HEADER_MARKER,
        ZSERV_VERSION,
        0,
        ZEBRA_HELLO,
    )
    return header + body


def main():
    sock_path, session_id, ready_path, release_path = sys.argv[1:5]
    message = zebra_hello(int(session_id))

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(sock_path)
        sock.sendall(message)
        with open(ready_path, "w", encoding="ascii") as ready:
            ready.write("ready\n")
            ready.flush()
            os.fsync(ready.fileno())
        # Block in the kernel until the test publishes the release file.
        # Polling from Python keeps the socket open without a busy read.
        while not os.path.exists(release_path):
            sock.settimeout(0.2)
            try:
                data = sock.recv(1)
            except socket.timeout:
                continue
            if not data:
                sys.stderr.write("zebra closed the session before release\n")
                return 1
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
