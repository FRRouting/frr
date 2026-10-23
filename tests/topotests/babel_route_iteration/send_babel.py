#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_babel.py
#
# Copyright (c) 2026
# Bing Shui
#
"""Send crafted Babel packets (Hello, IHU, Router-Id, Next-Hop, Update,
wildcard retraction) from the attacker host.

Used by test_babel_route_iteration.py.  Each job argument is a
comma-separated tuple:

  hello,<count>                       <count> Hello TLVs, seqno 1..count
  ihu,<txcost>                        one wildcard IHU TLV (AE=0)
  routes,<rid>,<pfx4>,<plen>,<seqA>,<metA>,<seqB>,<metB>
                                      Router-Id + NH(.2) + Update(A) +
                                      Router-Id + NH(.3) + Update(B)
  route,<rid>,<pfx4>,<plen>,<seq>,<metric>,<nh>
                                      one Update with an explicit v4 NH
  retract,<rid>,<pfx4>,<plen>,<seq>,<nh>
                                      one Update with metric INFINITY
  wildcard                            one wildcard retraction Update
                                      (AE=0, Plen=0, Omitted=0,
                                      Metric=INFINITY, RFC 8966 s4.6.9)

Packet and TLV layouts follow babeld/message.c: Babel v2 header
[42, 2, bodylen(2)], then TLVs of [type, len, body...].
"""

import sys
import time

from scapy.all import Ether, IPv6, Raw, UDP, conf, sendp

conf.verb = 0


def rid_bytes(rid_hex):
    rid = bytes(int(x, 16) for x in rid_hex.split(":"))
    if len(rid) != 8:
        raise SystemExit("router-id must have exactly 8 bytes: %s" % rid_hex)
    return rid


def pkt(tlvs):
    body = b"".join(tlvs)
    load = bytes([42, 2]) + len(body).to_bytes(2, "big") + body
    return (
        Ether(dst="33:33:00:00:01:06")
        / IPv6(src="fe80::a1", dst="ff02::1:6")
        / UDP(sport=6696, dport=6696)
        / Raw(load=load)
    )


def hello(seqno, interval=4000):
    return bytes([4, 6, 0, 0]) + seqno.to_bytes(2, "big") + interval.to_bytes(2, "big")


def ihu(txcost, interval=100):
    return bytes([5, 6, 0, 0]) + txcost.to_bytes(2, "big") + interval.to_bytes(2, "big")


def router_id(rid):
    return bytes([6, 10, 0, 0]) + rid_bytes(rid)


def nh4(addr):
    return bytes([7, 6, 1, 0]) + bytes(int(x) for x in addr.split("."))


def update4(prefix4, plen, seqno, interval, metric):
    pb = (plen + 7) // 8
    pbytes = bytes(int(x) for x in prefix4.split("."))[:pb]
    return (
        bytes([8, 10 + pb, 1, 0, plen, 0])
        + interval.to_bytes(2, "big")
        + seqno.to_bytes(2, "big")
        + metric.to_bytes(2, "big")
        + pbytes
    )


def wildcard_retract(interval=100):
    return (
        bytes([8, 10, 0, 0, 0, 0])
        + interval.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (65535).to_bytes(2, "big")
    )


def build(job):
    parts = job.split(",")
    kind = parts[0]
    if kind == "hello":
        return pkt([hello(i + 1) for i in range(int(parts[1]))])
    if kind == "ihu":
        return pkt([ihu(int(parts[1]))])
    if kind == "routes":
        rid, prefix4, plen = parts[1], parts[2], int(parts[3])
        seq_a, met_a, seq_b, met_b = (int(x) for x in parts[4:8])
        return pkt(
            [
                router_id(rid),
                nh4("10.13.0.2"),
                update4(prefix4, plen, seq_a, 100, met_a),
                router_id(rid),
                nh4("10.13.0.3"),
                update4(prefix4, plen, seq_b, 100, met_b),
            ]
        )
    if kind == "route":
        rid, prefix4, plen = parts[1], parts[2], int(parts[3])
        seq, metric, nh = int(parts[4]), int(parts[5]), parts[6]
        return pkt([router_id(rid), nh4(nh), update4(prefix4, plen, seq, 100, metric)])
    if kind == "retract":
        rid, prefix4, plen = parts[1], parts[2], int(parts[3])
        seq, nh = int(parts[4]), parts[5]
        return pkt(
            [router_id(rid), nh4(nh), update4(prefix4, plen, seq, 100, 65535)]
        )
    if kind == "wildcard":
        return pkt([wildcard_retract()])
    raise SystemExit("unknown job %s" % job)


def main():
    if len(sys.argv) < 3:
        raise SystemExit("usage: send_babel.py <iface> <job> [job ...]")
    iface = sys.argv[1]
    for job in sys.argv[2:]:
        sendp(build(job), iface=iface, verbose=0)
        print("sent %s" % job, flush=True)
        time.sleep(0.05)


if __name__ == "__main__":
    main()
