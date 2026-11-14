#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_mh_request.py
#
# Copyright (c) 2026
# Bing Shui
#
"""Send crafted Babel Seqno Request (MH Request) TLVs.

Used by test_babel_default_seqno_request.py to inject Seqno Requests with a
chosen (AE, prefix, seqno, router-id, hop count) from the attacker host.
"""

import argparse
import time

from scapy.all import Ether, IPv6, Raw, UDP, conf, sendp

conf.verb = 0


def mh_request(src, ae, prefix4, plen, seqno, hop, router_id):
    """One Babel packet holding a single Seqno Request TLV (RFC 8966
    s4.6.11): AE, Plen, Seqno, Hop Count, Reserved, Router-Id, Prefix."""
    pb = (plen + 7) // 8
    pbytes = bytes(int(x) for x in prefix4.split("."))[:pb]
    body = (
        bytes([10, 14 + pb, ae, plen])
        + seqno.to_bytes(2, "big")
        + bytes([hop, 0])
        + router_id
        + pbytes
    )
    load = bytes([42, 2]) + len(body).to_bytes(2, "big") + body
    return (
        Ether(dst="33:33:00:00:01:06")
        / IPv6(src=src, dst="ff02::1:6")
        / UDP(sport=6696, dport=6696)
        / Raw(load=load)
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src", required=True)
    parser.add_argument("--ae", type=int, required=True)
    parser.add_argument("--prefix", required=True, help="IPv4 prefix, e.g. 10.99.0.1")
    parser.add_argument("--plen", type=int, required=True)
    parser.add_argument("--seqno", type=int, required=True)
    parser.add_argument("--hop", type=int, required=True)
    parser.add_argument(
        "--router-id", required=True, help="8 bytes, colon-hex, e.g. 00:11:22:33:44:55:66:77"
    )
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--gap", type=float, default=0.0, help="seconds between packets")
    args = parser.parse_args()

    router_id = bytes(int(x, 16) for x in args.router_id.split(":"))
    if len(router_id) != 8:
        raise SystemExit("router-id must have exactly 8 bytes")

    pkt = mh_request(args.src, args.ae, args.prefix, args.plen, args.seqno, args.hop, router_id)
    for _ in range(args.count):
        sendp(pkt, iface=args.iface, verbose=0)
        if args.gap:
            time.sleep(args.gap)
    print(
        "sent {} x seqno-request ae={} {}/{} seqno={} hop={} id={}".format(
            args.count, args.ae, args.prefix, args.plen, args.seqno, args.hop, args.router_id
        )
    )


if __name__ == "__main__":
    main()
