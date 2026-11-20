#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_nh_update.py
#
# Copyright (c) 2026
# Bing Shui
#
"""Send one crafted Babel packet mixing Next Hop and Update TLVs.

Used by test_babel_nexthop_parser_state.py to inject, from the attacker
host, packets whose Next Hop TLV carries an unknown mandatory sub-TLV
(0xE0 0x00), an unknown optional sub-TLV (0x1F 0x00), or no sub-TLV.
"""

import argparse
import time

from scapy.all import Ether, IPv6, Raw, UDP, conf, sendp
from socket import AF_INET6, inet_aton, inet_pton

conf.verb = 0

NH_A = "10.13.0.3"
NH_B = "10.13.0.5"
NH_B6 = "fe80::b6"
RID = bytes.fromhex("000000000000aabb")
MAND = bytes([0xE0, 0x00])  # unknown sub-TLV, mandatory bit set
OPT = bytes([0x1F, 0x00])  # unknown sub-TLV, mandatory bit clear


def tlv(t, body):
    return bytes([t, len(body)]) + body


def router_id():
    return tlv(6, b"\x00\x00" + RID)


def nh_v4(addr, sub=b""):
    return tlv(7, bytes([1, 0]) + inet_aton(addr) + sub)


def nh_v6(addr, sub=b""):
    # AE=3 wire format: 8 octets, fe80::/64 implied (RFC 8966 s4.1.4)
    return tlv(7, bytes([3, 0]) + inet_pton(AF_INET6, addr)[8:] + sub)


def hello(seqno, interval):
    return tlv(4, b"\x00\x00" + seqno.to_bytes(2, "big") + interval.to_bytes(2, "big"))


def ihu(txcost, interval):
    return tlv(5, bytes([0, 0]) + txcost.to_bytes(2, "big") + interval.to_bytes(2, "big"))


def update(pfx, plen, seqno, metric=100, interval=3000):
    pb = (plen + 7) // 8
    if ":" in pfx:
        pbytes = inet_pton(AF_INET6, pfx)[:pb]
        ae = 2
    else:
        pbytes = inet_aton(pfx)[:pb]
        ae = 1
    body = (
        bytes([ae, 0x80, plen, 0])
        + interval.to_bytes(2, "big")
        + seqno.to_bytes(2, "big")
        + metric.to_bytes(2, "big")
        + pbytes
    )
    return tlv(8, body)


# every scenario packet carries hello+ihu with an increasing seqno, so the
# attacker neighbour keeps finite rxcost/txcost and r1 re-advertises the
# injected routes to r2 (reach decays ~1 bit per hello interval; a
# repeated seqno does not count)
HELLO_SEQ = {
    "S1-legit": 201,
    "S2-multi-nh": 202,
    "S3-single-v4": 203,
    "S4-single-v6": 204,
    "C1-optional": 205,
    "C2-malformed": 206,
    "C3-no-explicit": 207,
    "C4-legit-v6": 208,
}


def scenario_body(name):
    if name == "S1-legit":
        return router_id() + nh_v4(NH_A) + update("10.99.1.0", 24, 101)
    if name == "S2-multi-nh":
        return router_id() + nh_v4(NH_A) + nh_v4(NH_B, MAND) + update("10.99.2.0", 24, 102)
    if name == "S3-single-v4":
        return router_id() + nh_v4(NH_B, MAND) + update("10.99.3.0", 24, 103)
    if name == "S4-single-v6":
        return router_id() + nh_v6(NH_B6, MAND) + update("2001:db8:99:4::", 64, 104)
    if name == "C1-optional":
        return router_id() + nh_v4(NH_B, OPT) + update("10.99.5.0", 24, 105)
    if name == "C2-malformed":
        return router_id() + tlv(7, bytes([0, 0]) + inet_aton(NH_B)) + update("10.99.6.0", 24, 106)
    if name == "C3-no-explicit":
        return router_id() + update("2001:db8:99:7::", 64, 107)
    if name == "C4-legit-v6":
        return router_id() + nh_v6(NH_B6) + update("2001:db8:99:8::", 64, 108)
    if name == "warmup":
        # three hellos so the initial reach covers 0xC000 (finite rxcost on
        # a wired interface), plus ihu for txcost
        return hello(1, 3000) + hello(2, 3000) + hello(3, 3000) + ihu(96, 1200)
    raise SystemExit("unknown scenario {}".format(name))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--count", type=int, default=2)
    parser.add_argument("--gap", type=float, default=0.3)
    args = parser.parse_args()

    if args.scenario == "warmup":
        body = scenario_body(args.scenario)
    else:
        body = (
            hello(HELLO_SEQ[args.scenario], 3000)
            + ihu(96, 1200)
            + scenario_body(args.scenario)
        )
    load = bytes([42, 2]) + len(body).to_bytes(2, "big") + body
    pkt = (
        Ether(dst="33:33:00:00:01:06")
        / IPv6(src=args.src, dst="ff02::1:6")
        / UDP(sport=6696, dport=6696)
        / Raw(load=load)
    )
    for _ in range(args.count):
        sendp(pkt, iface=args.iface, verbose=0)
        if args.gap:
            time.sleep(args.gap)
    print("sent {} x {}".format(args.count, args.scenario))


if __name__ == "__main__":
    main()
