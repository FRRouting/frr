#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# babel_send.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Send crafted Babel packets for test_babel_infinite_seqno_request.py.

Modes:
  r3-forge  send one Update for an IPv4 prefix, spoofing r3's link-local
            address, with an arbitrary seqno/metric (creates a route whose
            source table seqno is higher than r3's real seqno, so r3's
            genuine later advertisement is unfeasible)
  req       send one or more multicast MH Seqno Requests

All packets are Babel v2, UDP port 6696, multicast to ff02::1:6, sent on
the given interface.
"""

import sys
import time

from scapy.all import Ether, IPv6, Raw, UDP, sendp

BABEL_MCAST = "ff02::1:6"
BABEL_MCAST_MAC = "33:33:00:00:01:06"


def wrap(body):
    load = bytes([42, 2]) + len(body).to_bytes(2, "big") + body
    return (
        Ether(dst=BABEL_MCAST_MAC)
        / IPv6(src=src_addr, dst=BABEL_MCAST)
        / UDP(sport=6696, dport=6696)
        / Raw(load=load)
    )


def nh_tlv(v4):
    # Next-Hop TLV, AE=1 (IPv4)
    return bytes([7, 6, 1, 0]) + bytes(int(x) for x in v4.split("."))


def rid_tlv(rid):
    # Router-ID TLV: 2 reserved bytes + 8 byte router-id
    return bytes([6, 10, 0, 0]) + rid


def update_tlv(seqno, metric, prefix):
    # Update TLV: AE=1, flags=0x80 (full prefix), Plen=32, Omitted=0,
    # Interval=1600 (matches the default update interval encoding)
    pb = bytes(int(x) for x in prefix.split("."))
    return (
        bytes([8, 14, 1, 0x80, 32, 0])
        + (1600).to_bytes(2, "big")
        + seqno.to_bytes(2, "big")
        + metric.to_bytes(2, "big")
        + pb
    )


def mh_request(seqno, hop, rid, prefix):
    # MH Seqno Request TLV: AE=1, Plen=32, Seqno, HopCount, Reserved,
    # Router-Id (8), Prefix (4)
    pb = bytes(int(x) for x in prefix.split("."))
    return (
        bytes([10, 18, 1, 32])
        + seqno.to_bytes(2, "big")
        + bytes([hop, 0])
        + rid
        + pb
    )


def main():
    global src_addr
    mode, src_addr, iface = sys.argv[1], sys.argv[2], sys.argv[3]

    if mode == "r3-forge":
        # args: seqno metric prefix nh ridhex
        seqno, metric = int(sys.argv[4]), int(sys.argv[5])
        prefix, nh, rid = sys.argv[6], sys.argv[7], bytes.fromhex(sys.argv[8])
        pkt = wrap(nh_tlv(nh) + rid_tlv(rid) + update_tlv(seqno, metric, prefix))
        sendp(pkt, iface=iface, verbose=0)
        print("sent r3-forge seqno=%d metric=%d" % (seqno, metric))
    elif mode == "req":
        # args: seqno hop ridhex prefix [count]
        seqno, hop = int(sys.argv[4]), int(sys.argv[5])
        rid, prefix = bytes.fromhex(sys.argv[6]), sys.argv[7]
        count = int(sys.argv[8]) if len(sys.argv) > 8 else 1
        for _ in range(count):
            sendp(wrap(mh_request(seqno, hop, rid, prefix)), iface=iface, verbose=0)
            time.sleep(0.2)
        print("sent %d req seqno=%d hop=%d" % (count, seqno, hop))
    else:
        sys.exit("unknown mode " + mode)


if __name__ == "__main__":
    main()
