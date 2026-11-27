#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Send a bounded sequence of hand-crafted RIPv2 RESPONSE packets.
# Used by test_rip_nexthop_timeout.py; runs on the attacker host.

import json
import socket
import struct
import sys
import time

from scapy.all import IP, UDP, Raw, conf, send

RIP_PORT = 520


def rte(prefix, mask, metric, tag, nexthop):
    return struct.pack(
        "!HH4s4s4sI", 2, tag,
        bytes(int(x) for x in prefix.split(".")),
        bytes(int(x) for x in mask.split(".")),
        bytes(int(x) for x in nexthop.split(".")),
        metric,
    )


def run(cfg):
    conf.verb = 0
    # A bound socket keeps the kernel from answering with ICMP port
    # unreachable when responses arrive at udp/520.
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sink.bind(("", RIP_PORT))
    epoch = time.time()
    for index, spec in enumerate(cfg["packets"]):
        if spec.get("at") is not None:
            delay = spec["at"] - (time.time() - epoch)
            if delay > 0:
                time.sleep(delay)
        elif index:
            time.sleep(cfg.get("spacing", 3.0))
        pkt = struct.pack("!BBH", 2, 2, 0) + rte(
            spec["prefix"], spec.get("mask", "255.255.255.0"),
            spec["metric"], spec.get("tag", 0),
            spec.get("nexthop", "0.0.0.0"))
        send(IP(src=spec.get("src", cfg["src"]), dst=cfg["dst"])
             / UDP(sport=RIP_PORT, dport=RIP_PORT) / Raw(pkt),
             iface=cfg["iface"], verbose=0)
    print("RIP_SEND_DONE")


if __name__ == "__main__":
    run(json.load(open(sys.argv[1])))
