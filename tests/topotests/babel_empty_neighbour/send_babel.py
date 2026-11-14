#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_babel.py
#
"""Crafted Babel packet sender for test_babel_empty_neighbour.py.

Runs on host h1 and injects raw Babel packets on its interface.  All
packets share the Babel multicast destination, so every Babel speaker on
the bridge receives them; the spoofed link-local source addresses make
each phantom source a distinct neighbour candidate on the receivers.
"""

import argparse
import sys
import time

from scapy.all import Ether, IPv6, Raw, UDP, conf, sendp

conf.verb = 0

BABEL_MCAST = "ff02::1:6"
BABEL_MCAST_MAC = "33:33:00:00:01:06"


def wrap(body, src):
    load = bytes([42, 2]) + len(body).to_bytes(2, "big") + body
    return (
        Ether(dst=BABEL_MCAST_MAC)
        / IPv6(src=src, dst=BABEL_MCAST)
        / UDP(sport=6696, dport=6696)
        / Raw(load=load)
    )


def hello(src, seqno, interval, mandatory=False):
    body = (
        bytes([4, 6])
        + b"\x00\x00"
        + seqno.to_bytes(2, "big")
        + interval.to_bytes(2, "big")
    )
    if mandatory:
        body = (
            bytes([4, 9])
            + b"\x00\x00"
            + seqno.to_bytes(2, "big")
            + interval.to_bytes(2, "big")
            + bytes([0x80, 0x01, 0x00])
        )
    return wrap(body, src)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument(
        "--kind",
        required=True,
        choices=[
            "empty",
            "padn",
            "unknown",
            "ignoredhello",
            "badmagic",
            "badversion",
            "truncated",
            "ihu",
            "update",
            "validhello",
        ],
    )
    parser.add_argument("--src", required=True, help="base link-local source")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--rate", type=float, default=0.0, help="packets/s")
    args = parser.parse_args()

    base = int(args.src.split("::")[-1], 16)
    gap = 1.0 / args.rate if args.rate > 0 else 0

    for i in range(args.count):
        # fan out the source only for the stateless-flooding kinds; the
        # neighbour-associated kinds reuse the single --src address
        if args.kind in ("empty", "padn", "unknown"):
            src = "fe80::{:x}".format(base + i)
        else:
            src = args.src
        if args.kind == "empty":
            pkt = wrap(b"", src)
        elif args.kind == "padn":
            pkt = wrap(bytes([1, 4, 0, 0, 0, 0]), src)
        elif args.kind == "unknown":
            pkt = wrap(bytes([200, 2, 0xAA, 0xBB]), src)
        elif args.kind == "ignoredhello":
            pkt = hello(src, 1, 400, mandatory=True)
        elif args.kind == "badmagic":
            pkt = wrap(b"", src)
            pkt[Raw].load = bytes([43, 2, 0, 0])
        elif args.kind == "badversion":
            pkt = wrap(b"", src)
            pkt[Raw].load = bytes([42, 3, 0, 0])
        elif args.kind == "truncated":
            pkt = wrap(b"", src)
            pkt[Raw].load = bytes([42, 2, 0, 100])
        elif args.kind == "ihu":
            body = (
                bytes([5, 6, 0, 0])
                + (100).to_bytes(2, "big")
                + (400).to_bytes(2, "big")
            )
            pkt = wrap(body, src)
        elif args.kind == "update":
            rid = bytes([6, 10, 0, 0]) + bytes([0, 0, 0, 0, 0, 0, 0x12, 0x34])
            upd = (
                bytes([8, 18, 2, 0, 64, 0])
                + (400).to_bytes(2, "big")
                + (1).to_bytes(2, "big")
                + (128).to_bytes(2, "big")
                + bytes([0x20, 0x01, 0x0D, 0xB8, 0x00, 0x63, 0x00, 0x00])
            )
            pkt = wrap(rid + upd, src)
        elif args.kind == "validhello":
            pkt = hello(src, i + 1, 400)
        sendp(pkt, iface=args.iface, verbose=False)
        if gap:
            time.sleep(gap)

    print("sent {} x {}".format(args.count, args.kind))


if __name__ == "__main__":
    sys.exit(main())
