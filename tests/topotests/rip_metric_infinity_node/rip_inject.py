#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# rip_inject.py - send RIPv2 RESPONSE packets built from a JSON spec.
#
# Usage: rip_inject.py IFACE DST_JSON
#   IFACE     egress interface (e.g. r2-eth0)
#   DST_JSON  JSON list of [prefix, metric] pairs; prefixes are /24
#             ("198.18.0.0" style), sent as RIPv2 RESPONSE RTEs,
#             chunked to 25 RTEs per packet.
#
# Runs inside the injector router's namespace via Topogen .run().

import json
import socket
import struct
import sys
import time

from scapy.all import IP, UDP, Raw, conf, send

RIP_PORT = 520


def rte(prefix, metric):
    return struct.pack(
        "!HH4s4s4sI",
        2,
        0,
        bytes(int(x) for x in prefix.split(".")),
        bytes([255, 255, 255, 0]),
        bytes(4),
        metric,
    )


def main():
    iface = sys.argv[1]
    entries = json.loads(sys.argv[2])
    conf.verb = 0
    # A bound socket keeps the kernel from answering with ICMP port
    # unreachable when updates arrive at udp/520.
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sink.bind(("", RIP_PORT))
    sent = 0
    for off in range(0, len(entries), 25):
        chunk = entries[off:off + 25]
        pkt = struct.pack("!BBH", 2, 2, 0) + b"".join(
            rte(p, m) for p, m in chunk
        )
        send(
            IP(dst="10.0.0.1") / UDP(sport=RIP_PORT, dport=RIP_PORT) / Raw(pkt),
            iface=iface,
            verbose=0,
        )
        sent += 1
        time.sleep(0.2)
    print("sent {} packets".format(sent))


if __name__ == "__main__":
    main()
