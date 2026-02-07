#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
# Copyright (c) 2025 by David Lamparter for NetDEF, Inc.

# minimal tool to receive IPv6 RAs and check for PREF64 option
# usage:
#   python3 rx_ipv6_ra_8781.py eth123 64:ff9b::/64 1200 5
# LIFETIME (first number) is the value expected in the packet
# TIMEOUT (second number) is how long to wait for a matching packet

import sys
import socket
import time

from scapy.config import conf
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_RA,
    ICMPv6NDOptPREF64,
)

assert len(sys.argv) == 5, "required arguments: IFNAME PREF64 LIFETIME TIMEOUT"

sock = conf.L2socket(iface=sys.argv[1])

pref64str, masklenstr = sys.argv[2].split("/")
pref64 = socket.inet_pton(socket.AF_INET6, pref64str)
masklen = int(masklenstr)
# lifetime is 13 bits with a *8
lifetime = int(sys.argv[3]) // 8

timeout = float(sys.argv[4])

deadline = time.time() + timeout

while time.time() < deadline:
    pkts = sock.sniff(timeout=min(deadline - time.time(), 0.25))
    for pkt in pkts:
        ra = pkt.getlayer(ICMPv6ND_RA)
        if not ra:
            continue

        ra.show()

        pl = ra.payload
        while pl:
            cur, pl = pl, pl.payload
            if isinstance(cur, ICMPv6NDOptPREF64):
                cmp_pref64 = socket.inet_pton(socket.AF_INET6, cur.prefix)
                cmp_masklen = int(cur.sprintf("%plc%")[1:])
                if pref64 != cmp_pref64:
                    print(f"prefix mismatch {pref64!r} != {cmp_pref64!r}")
                    continue
                if masklen != cmp_masklen:
                    print(f"prefixlen mismatch {masklen!r} != {cmp_masklen!r}")
                    continue
                if lifetime != cur.scaledlifetime:
                    print(
                        f"lifetime mismatch {lifetime*8!r} != {cur.scaledlifetime*8!r}"
                    )
                    continue

                print("MATCH - exiting successfully")
                sys.exit(0)

print("no matching packet received - exiting with failure")
sys.exit(1)
