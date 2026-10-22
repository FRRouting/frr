#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_hello.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#
"""Craft one OSPF Hello, send it on the wire, and prove transmission.

Used by test_ospf_hello_neighbor_identity.py to inject forged Hellos
from the peer's namespace.  The packet is built with scapy's OSPF
layers (so length and checksum are computed the same way a router
would), optionally corrupted at the OSPF checksum, wrapped in a raw
Ethernet/IP frame, and sent once.  A capture on the sending interface
must observe the exact payload once; the matching packets are written
to a pcap as evidence that the trigger reached the wire.

Runs inside the peer router's network namespace; the pcap path must be
visible from the host (use the test's logdir).
"""

import argparse
import json
import sys
import time

from scapy.all import AsyncSniffer, Ether, IP, Raw, conf, sendp, wrpcap
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

conf.verb = 0

ALL_SPF_ROUTERS = "224.0.0.5"
ALL_SPF_ROUTERS_MAC = "01:00:5e:00:00:05"
OSPF_PROTO = 89


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--dst-ip", default=ALL_SPF_ROUTERS)
    parser.add_argument("--packet-rid", required=True)
    parser.add_argument("--area", default="0.0.0.0")
    parser.add_argument("--mask", default="255.255.255.0")
    parser.add_argument("--hello-interval", type=int, default=1)
    parser.add_argument("--dead-interval", type=int, default=4)
    parser.add_argument("--priority", type=int, default=0)
    parser.add_argument("--dr", default="0.0.0.0")
    parser.add_argument("--bdr", default="0.0.0.0")
    parser.add_argument(
        "--neighbors",
        default="",
        help="comma-separated router IDs listed in the Hello neighbor field",
    )
    parser.add_argument(
        "--corrupt-checksum",
        action="store_true",
        help="flip a bit in the OSPF checksum after building the packet",
    )
    parser.add_argument("--pcap", required=True)
    args = parser.parse_args()

    neighbor_rids = [n for n in args.neighbors.split(",") if n]
    hello = OSPF_Hdr(
        version=2, type=1, src=args.packet_rid, area=args.area
    ) / OSPF_Hello(
        mask=args.mask,
        hellointerval=args.hello_interval,
        options=0x02,
        prio=args.priority,
        deadinterval=args.dead_interval,
        router=args.dr,
        backup=args.bdr,
        neighbors=neighbor_rids,
    )
    payload = bytearray(bytes(hello))
    if args.corrupt_checksum:
        payload[12] ^= 0x01
    payload = bytes(payload)

    frame = (
        Ether(src=args.src_mac, dst=ALL_SPF_ROUTERS_MAC)
        / IP(src=args.src_ip, dst=args.dst_ip, ttl=1, proto=OSPF_PROTO)
        / Raw(payload)
    )

    sniffer = AsyncSniffer(
        iface=args.iface,
        filter="ip proto %d and src host %s and dst host %s"
        % (OSPF_PROTO, args.src_ip, args.dst_ip),
        store=True,
    )
    sniffer.start()
    time.sleep(0.2)
    sendp(frame, iface=args.iface, count=1, verbose=False)
    time.sleep(0.3)
    packets = list(sniffer.stop())

    matching = [
        packet
        for packet in packets
        if packet.haslayer(IP) and bytes(packet[IP].payload) == payload
    ]
    wrpcap(args.pcap, matching)
    print(
        "B4_SEND_JSON="
        + json.dumps(
            {
                "sent": 1,
                "captured": len(matching),
                "packet_router_id": args.packet_rid,
                "neighbor_rids": neighbor_rids,
                "corrupt_checksum": args.corrupt_checksum,
                "pcap": args.pcap,
            },
            sort_keys=True,
        )
    )
    if len(matching) != 1:
        sys.exit(1)


if __name__ == "__main__":
    main()
