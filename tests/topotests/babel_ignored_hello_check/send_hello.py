#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_hello.py
#
# Copyright (c) 2026 Bing Shui
#
"""Send scripted Babel Hello packets for test_babel_ignored_hello_check.py.

Kinds:
  ignored   Hello, interval=1, with unknown mandatory sub-TLV 80 01 00
            (RFC 8966 sec.4.4: the whole Hello TLV must be silently ignored)
  valid400  plain legal Hello with the normal 4s interval (valid control)
  valid1    plain legal Hello with interval=1 (deadline-pull control)
  garbage   Babel version 3 packet, dropped by babel_packet_examin()
"""

import argparse
import sys
import time

from scapy.all import conf, Ether, IPv6, Raw, sendp, UDP

conf.verb = 0

def hello(seqno, interval, mandatory):
    body = bytes([4, 6]) + b"\x00\x00" + seqno.to_bytes(2, "big") + interval.to_bytes(2, "big")
    if mandatory:
        body = (bytes([4, 9]) + b"\x00\x00" + seqno.to_bytes(2, "big")
                + interval.to_bytes(2, "big") + bytes([0x80, 0x01, 0x00]))
    return body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src", required=True)
    parser.add_argument("--kind", required=True,
                        choices=["ignored", "valid400", "valid1", "garbage"])
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--rate", type=float, default=0.0, help="packets/s, 0 = once")
    args = parser.parse_args()

    if args.kind == "ignored":
        body = hello(1, 1, True)
    elif args.kind == "valid400":
        body = hello(4000, 400, False)
    elif args.kind == "valid1":
        body = hello(1, 1, False)
    else:
        # babel version 3: rejected before any TLV handling
        load = bytes([42, 3, 0, 2, 4, 6, 0, 0, 0, 1, 0, 1])
        pkt = (Ether(dst="33:33:00:00:01:06")
               / IPv6(src=args.src, dst="ff02::1:6")
               / UDP(sport=6696, dport=6696)
               / Raw(load=load))
        gap = 1.0 / args.rate if args.rate > 0 else 0
        for _ in range(args.count):
            sendp(pkt, iface=args.iface, verbose=0)
            if gap:
                time.sleep(gap)
        print("sent {} x garbage".format(args.count))
        return

    load = bytes([42, 2]) + len(body).to_bytes(2, "big") + body
    pkt = (Ether(dst="33:33:00:00:01:06")
           / IPv6(src=args.src, dst="ff02::1:6")
           / UDP(sport=6696, dport=6696)
           / Raw(load=load))

    gap = 1.0 / args.rate if args.rate > 0 else 0
    for _ in range(args.count):
        sendp(pkt, iface=args.iface, verbose=0)
        if gap:
            time.sleep(gap)
    print("sent {} x {}".format(args.count, args.kind))


if __name__ == "__main__":
    main()
