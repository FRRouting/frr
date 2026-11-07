#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# rip_packet_inject.py
#
"""Send crafted RIP packets for test_rip_bad_packet_peer.py.

Runs inside the r2 network namespace.  Packet kinds mirror the runtime
confirmation script (test/manul/rip_bad_packet_peer.py in topo-fuzz):

  bad_length     UDP payload shorter than RIP_PACKET_MINSIZ (4), fails the
                 length check in rip_read() before any header parsing
  bad_version    version 0 with an otherwise well-formed body
  bad_command    unknown command 99, passes length/version/running gates
                 (no auth configured) and dies at the command switch
  request_full   RIPv2 REQUEST, family 0 / metric 16 (whole table)
  response_empty RIPv2 RESPONSE with zero RTEs
  response_v1    RIPv1 RESPONSE with one RTE
  response_v2    RIPv2 RESPONSE with one RTE; "auth" adds a leading
                 simple-password authentication RTE (empty string = no
                 auth RTE)

The spec is a JSON file: {"iface": ..., "dst": ..., "spacing": <sec>,
"packets": [{"src": ..., "kind": ..., "route": ..., "auth": ...}, ...]}.
"""

import json
import socket
import struct
import sys
import time

from scapy.all import IP, UDP, Raw, conf, send

RIP_PORT = 520


def rte(family, addr, mask, metric, tag=0, nh="0.0.0.0"):
    return struct.pack(
        "!HH4s4s4sI",
        family,
        tag,
        bytes(int(x) for x in addr.split(".")),
        bytes(int(x) for x in mask.split(".")),
        bytes(int(x) for x in nh.split(".")),
        metric,
    )


def build(spec):
    kind = spec["kind"]
    if kind == "bad_length":
        return b"\x01\x02"
    if kind == "bad_version":
        return struct.pack("!BBH", 1, 0, 0) + rte(
            2, "198.18.99.0", "255.255.255.0", 2
        )
    if kind == "bad_command":
        return struct.pack("!BBH", 99, 2, 0) + rte(
            2, "198.18.99.0", "255.255.255.0", 2
        )
    if kind == "request_full":
        return struct.pack("!BBH", 1, 2, 0) + rte(0, "0.0.0.0", "0.0.0.0", 16)
    if kind == "response_empty":
        return struct.pack("!BBH", 2, 2, 0)
    if kind == "response_v1":
        return struct.pack("!BBH", 2, 1, 0) + rte(2, "198.18.99.0", "0.0.0.0", 2)
    if kind == "response_v2":
        rtes = [rte(2, spec["route"], "255.255.255.0", 2)]
        if spec.get("auth") is not None:
            pw = spec["auth"].encode()[:16].ljust(16, b"\x00")
            rtes = [struct.pack("!HH", 0xFFFF, 2) + pw] + rtes
        return struct.pack("!BBH", 2, 2, 0) + b"".join(rtes)
    raise ValueError(kind)


def main():
    conf.verb = 0
    with open(sys.argv[1]) as fp:
        cfg = json.load(fp)
    # A bound socket keeps the kernel from answering with ICMP port
    # unreachable when responses arrive at udp/520.
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sink.bind(("", RIP_PORT))
    for index, spec in enumerate(cfg["packets"]):
        if index:
            time.sleep(cfg.get("spacing", 0.1))
        pkt = build(spec)
        send(
            IP(src=spec["src"], dst=cfg["dst"])
            / UDP(sport=RIP_PORT, dport=RIP_PORT)
            / Raw(pkt),
            iface=cfg["iface"],
            verbose=0,
        )
    print("INJECT_JSON=" + json.dumps({"sent": len(cfg["packets"])}))


if __name__ == "__main__":
    main()
