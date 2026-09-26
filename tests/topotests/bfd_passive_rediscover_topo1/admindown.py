#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Send BFD Control packets in State AdminDown from an existing session.

RFC 5880 Section 6.8.16 says a system SHOULD keep transmitting them for a
Detection Time after going AdminDown. bfdd sends one, so the rest are sent
from here, with the session's own discriminators.

admindown.py SRC DST MY_DISC YOUR_DISC COUNT
"""
import socket
import struct
import sys
import time

src, dst = sys.argv[1], sys.argv[2]
my_disc, your_disc, count = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])

# Version 1, diag 7 (Administratively Down), State 0 (AdminDown), mult 3,
# length 24, 1 s intervals.
pkt = struct.pack(
    "!BBBBIIIII", (1 << 5) | 7, 0, 3, 24, my_disc, your_disc, 1000000, 1000000, 0
)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
sock.bind((src, 49999))
for _ in range(count):
    sock.sendto(pkt, (dst, 3784))
    time.sleep(1)
