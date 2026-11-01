#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Send a bounded sequence of hand-crafted RIPv1/RIPv2 RESPONSE packets.
# Used by test_rip_noncontiguous_mask.py; runs on the attacker host.

import json
import socket
import struct
import sys
import time

from scapy.all import IP, UDP, Raw, conf, send

RIP_PORT = 520


def rte_v2(prefix, mask, metric, tag, nexthop):
    return struct.pack(
        "!HH4s4s4sI", 2, tag,
        bytes(int(x) for x in prefix.split(".")),
        bytes(int(x) for x in mask.split(".")),
        bytes(int(x) for x in nexthop.split(".")),
        metric,
    )


def rte_v1(prefix, metric):
    return struct.pack(
        "!HH4s4s4sI", 2, 0,
        bytes(int(x) for x in prefix.split(".")),
        bytes(4), bytes(4), metric,
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
        version = spec.get("version", 2)
        body = rte_v1(spec["prefix"], spec["metric"]) if version == 1 \
            else rte_v2(spec["prefix"], spec.get("mask", "255.255.255.0"),
                        spec["metric"], spec.get("tag", 0),
                        spec.get("nexthop", "0.0.0.0"))
        pkt = struct.pack("!BBH", 2, version, 0) + body
        send(IP(src=spec.get("src", cfg["src"]), dst=cfg["dst"])
             / UDP(sport=RIP_PORT, dport=RIP_PORT) / Raw(pkt),
             iface=cfg["iface"], verbose=0)
    print("RIP_SEND_DONE")


if __name__ == "__main__":
    run(json.load(open(sys.argv[1])))
