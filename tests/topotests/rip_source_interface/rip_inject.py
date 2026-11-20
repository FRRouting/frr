#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# rip_inject.py
#
"""Send crafted RIPv2 RESPONSE packets for test_rip_source_interface.py.

Builds plain (unauthenticated), RFC 2082 MD5 and simple-password RIPv2
RESPONSE packets.  The MD5 layout mirrors ripd's own send/receive path
(ripd/ripd.c rip_auth_md5_*): the packet length field covers header +
authentication RTE + route RTEs, the trailer starts at that offset, and
the digest covers packet[0 : packet_len + 4] plus the 16-byte key, i.e.
it includes the trailer's family/type words.
"""

import argparse
import hashlib
import struct
import time

from scapy.all import IP, UDP, Raw, conf, send

conf.verb = 0

RIP_PORT = 520


def rte(addr, mask, metric, tag, nh):
    return struct.pack(
        "!HH4s4s4sI",
        2,
        tag,
        bytes(int(x) for x in addr.split(".")),
        bytes(int(x) for x in mask.split(".")),
        bytes(int(x) for x in nh.split(".")),
        metric,
    )


def response(rtes, auth, key):
    pkt = struct.pack("!BBH", 2, 2, 0)
    if auth == "md5":
        plen = 24 + len(rtes)  # header + auth RTE + route RTEs, no trailer
        pkt += struct.pack("!HHHBBIII", 0xFFFF, 3, plen, 1, 16, 0, 0, 0)
    elif auth == "simple":
        pw = key.encode()[:16].ljust(16, b"\0")
        pkt += struct.pack("!HH", 0xFFFF, 2) + pw
    pkt += rtes
    if auth == "md5":
        pkt += struct.pack("!HH", 0xFFFF, 1)
        keyp = key.encode()[:16].ljust(16, b"\0")
        pkt += hashlib.md5(pkt + keyp).digest()
    return pkt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--mask", default="255.255.255.0")
    parser.add_argument("--metric", type=int, default=2)
    parser.add_argument("--nexthop", default="0.0.0.0")
    parser.add_argument("--auth", choices=["none", "md5", "simple"],
                        default="none")
    parser.add_argument("--key", default="")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--spacing", type=float, default=1.0)
    args = parser.parse_args()

    rtes = rte(args.prefix, args.mask, args.metric, 0, args.nexthop)
    pkt = response(rtes, args.auth, args.key)
    for _ in range(args.count):
        send(
            IP(src=args.src, dst=args.dst)
            / UDP(sport=RIP_PORT, dport=RIP_PORT)
            / Raw(pkt),
            iface=args.iface,
            verbose=0,
        )
        time.sleep(args.spacing)


if __name__ == "__main__":
    main()
