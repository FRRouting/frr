#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_hello.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Send scripted Babel Hello TLVs from a router namespace.

Used by test_babel_late_hello_churn.py to replay a (late) Hello with a
seqno the receiver has already seen, which takes the late-hello branch of
update_neighbour().

--plan takes seqno:interval[:gap_before_send] triples; the interval is the
raw Hello TLV interval field (centiseconds), identical for every packet of
a sequence so the late-hello branch (not the interval-increase branch) is
exercised.
"""

import argparse
import time

from scapy.all import conf, sendp
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

conf.verb = 0


def hello(seqno, interval):
    body = bytes([4, 6, 0, 0]) + seqno.to_bytes(2, "big") + interval.to_bytes(2, "big")
    load = bytes([42, 2]) + len(body).to_bytes(2, "big") + body
    return (
        Ether(dst="33:33:00:00:01:06")
        / IPv6(src=args.src, dst="ff02::1:6")
        / UDP(sport=6696, dport=6696)
        / Raw(load=load)
    )


def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--iface", required=True)
    parser.add_argument(
        "--plan",
        required=True,
        nargs="+",
        help="seqno:interval[:gap] triples, e.g. 100:4000:0 106:4000:1 107:4000:1",
    )
    args = parser.parse_args()

    for item in args.plan:
        parts = item.split(":")
        seqno, interval = int(parts[0]), int(parts[1])
        gap = float(parts[2]) if len(parts) > 2 else 0.0
        if gap:
            time.sleep(gap)
        sendp(hello(seqno, interval), iface=args.iface, verbose=False)
        print("sent hello seqno={} interval={}".format(seqno, interval), flush=True)


if __name__ == "__main__":
    main()
