#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_babel.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Crafted Babel packet sender for test_babel_source_refcount.py.

Runs on host h1 and injects raw Babel packets on its interface.  All
packets share the Babel multicast destination, so every Babel speaker on
the bridge receives them.  The flood kind carries batches of
Next Hop + Update TLV pairs that create many routes for one source
(router-id, prefix): same seqno, same refmetric, one distinct next-hop
per route, so each Update retains the shared source once.
"""

import argparse
import sys
import time

from scapy.all import Ether, IPv6, Raw, UDP, conf, sendp

conf.verb = 0

BABEL_MCAST = "ff02::1:6"
BABEL_MCAST_MAC = "33:33:00:00:01:06"

RID_TLV = bytes([6, 10, 0, 0]) + bytes([0, 0, 0, 0, 0, 0, 0xBB, 0x03])


def wrap(body, src):
    load = bytes([42, 2]) + len(body).to_bytes(2, "big") + body
    return (
        Ether(dst=BABEL_MCAST_MAC)
        / IPv6(src=src, dst=BABEL_MCAST)
        / UDP(sport=6696, dport=6696)
        / Raw(load=load)
    )


def hello_tlv(seqno, interval=400):
    return bytes([4, 6]) + b"\x00\x00" + seqno.to_bytes(2, "big") + interval.to_bytes(2, "big")


def nh_tlv(i):
    # MESSAGE_NH is type 7; AE=3 next-hop: the parser takes the low
    # 8 bytes onto fe80::/64
    return bytes([7, 10, 3, 0]) + (0x10000 + i).to_bytes(8, "big")


def upd_tlv(prefix, seqno, metric, interval=65535):
    return (
        bytes([8, 18, 2, 0, 64, 0])
        + interval.to_bytes(2, "big")
        + seqno.to_bytes(2, "big")
        + metric.to_bytes(2, "big")
        + prefix
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--kind", required=True,
                        choices=["hello", "routes", "retract", "flood"])
    parser.add_argument("--src", required=True)
    parser.add_argument("--prefix", default="20010db800630000",
                        help="8 prefix bytes as hex (AE=2, plen 64)")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--seqno", type=int, default=100)
    parser.add_argument("--metric", type=int, default=1)
    parser.add_argument("--hseq", type=int, default=0)
    parser.add_argument("--per", type=int, default=40)
    parser.add_argument("--gap", type=float, default=0.03)
    args = parser.parse_args()

    prefix = bytes.fromhex(args.prefix)

    if args.kind == "hello":
        for i in range(args.count):
            sendp(wrap(hello_tlv(i + 1), args.src), iface=args.iface, verbose=False)
            time.sleep(0.3)
    elif args.kind == "routes":
        # one packet: Hello(hseq) + Router-ID + count x (NextHop + Update)
        body = b""
        if args.hseq > 0:
            body += hello_tlv(args.hseq)
        body += RID_TLV
        for i in range(args.start, args.start + args.count):
            body += nh_tlv(i) + upd_tlv(prefix, args.seqno, args.metric)
        assert len(body) <= 1400, len(body)
        sendp(wrap(body, args.src), iface=args.iface, verbose=False)
    elif args.kind == "retract":
        body = RID_TLV + nh_tlv(args.start) + upd_tlv(prefix, args.seqno, 65535)
        sendp(wrap(body, args.src), iface=args.iface, verbose=False)
    elif args.kind == "flood":
        sent = 0
        hseq = 0
        while sent < args.count:
            n = min(args.per, args.count - sent)
            hseq += 1
            body = hello_tlv(hseq) + RID_TLV
            for i in range(sent, sent + n):
                body += nh_tlv(i) + upd_tlv(prefix, args.seqno, args.metric)
            assert len(body) <= 1400, len(body)
            sendp(wrap(body, args.src), iface=args.iface, verbose=False)
            sent += n
            time.sleep(args.gap)
        print("flood: {} routes in {} packets".format(sent, hseq), flush=True)

    print("sent {} x {}".format(args.count, args.kind), flush=True)
    sys.exit(0)


if __name__ == "__main__":
    sys.exit(main())
