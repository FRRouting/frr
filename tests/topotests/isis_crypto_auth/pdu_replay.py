#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
Capture an IS-IS PDU off a link.

    pdu_replay.py capture <interface> <source MAC> <PDU type> <timeout> [<hex>]
        print the first matching frame received on interface, in hex; with
        <hex>, only a frame that contains these bytes
"""

import binascii
import select
import socket
import sys
import time

ETH_P_ALL = 0x0003
PDU = 14 + 3  # the IS-IS PDU follows the 802.3 header and the LLC


def capture(ifname, src_mac, pdu_type, timeout, marker=b""):
    src = binascii.unhexlify(src_mac.replace(":", ""))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((ifname, 0))
    end = time.time() + timeout
    while time.time() < end:
        if not select.select([sock], [], [], 0.5)[0]:
            continue
        frame = sock.recv(65535)
        if frame[6:12] == src and frame[14:17] == b"\xfe\xfe\x03":
            if frame[PDU + 4] & 0x1F == pdu_type and marker in frame:
                print(binascii.hexlify(frame).decode())
                return 0
    return 1


if __name__ == "__main__":
    if sys.argv[1] == "capture":
        sys.exit(
            capture(
                sys.argv[2],
                sys.argv[3],
                int(sys.argv[4]),
                float(sys.argv[5]),
                binascii.unhexlify(sys.argv[6]) if len(sys.argv) > 6 else b"",
            )
        )
