#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_burst.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#
"""Craft OSPF Hellos with attacker-chosen DR/BDR/priority fields, send
them on the wire at a fixed spacing, and prove transmission.

Used by test_ospf_election_churn.py to inject forged Hellos from the
peer's namespace.  Every packet is built with scapy's OSPF layers (so
length and checksum are computed the same way a router would), wrapped
in a raw Ethernet/IP frame, and sent with a fixed spacing.  A capture on
the sending interface must observe each exact payload; the matching
packets are written to a pcap as evidence that the trigger reached the
wire.

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

OSPF_PROTO = 89


def build_hello(args, fields, corrupt):
    hello = OSPF_Hdr(
        version=2, type=1, src=args.packet_rid, area=args.area
    ) / OSPF_Hello(
        mask=args.mask,
        hellointerval=args.hello_interval,
        options=0x02,
        prio=fields["priority"],
        deadinterval=args.dead_interval,
        router=fields["dr"],
        backup=fields["bdr"],
        neighbors=args.neighbor_rids.split(",") if args.neighbor_rids else [],
    )
    payload = bytearray(bytes(hello))
    if corrupt:
        payload[12] ^= 0x01
    return bytes(payload)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--packet-rid", required=True)
    parser.add_argument("--neighbors", dest="neighbor_rids", default="")
    parser.add_argument("--area", default="0.0.0.0")
    parser.add_argument("--mask", default="255.255.255.0")
    parser.add_argument("--hello-interval", type=int, default=30)
    parser.add_argument("--dead-interval", type=int, default=40)
    parser.add_argument("--mode", choices=("burst", "invalid"), required=True)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--spacing", type=float, default=0.0)
    parser.add_argument("--tail", type=float, default=1.0)
    parser.add_argument(
        "--variants-json",
        required=True,
        help="path to a JSON list of {dr, bdr, priority} objects",
    )
    parser.add_argument("--pcap", required=True)
    args = parser.parse_args()

    with open(args.variants_json) as variantf:
        variants = json.load(variantf)

    sent = []
    payloads = []
    sniffer = AsyncSniffer(
        iface=args.iface,
        filter="ip proto %d and src host %s and dst host %s"
        % (OSPF_PROTO, args.src_ip, args.dst_ip),
        store=True,
    )
    sniffer.start()
    time.sleep(0.3)
    epoch = time.time()
    try:
        count = 1 if args.mode == "invalid" else args.count
        for index in range(count):
            if index:
                time.sleep(args.spacing)
            fields = variants[0] if args.mode == "invalid" else variants[index % 2]
            corrupt = args.mode == "invalid"
            payload = build_hello(args, fields, corrupt)
            frame = (
                Ether(src=args.src_mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src=args.src_ip, dst=args.dst_ip, ttl=1, proto=OSPF_PROTO)
                / Raw(payload)
            )
            sendp(frame, iface=args.iface, count=1, verbose=False)
            sent.append(
                {
                    "time": round(time.time() - epoch, 6),
                    "index": index,
                    **fields,
                    "corrupt_checksum": corrupt,
                }
            )
            payloads.append(payload)
        time.sleep(args.tail)
    finally:
        packets = list(sniffer.stop())

    matching = []
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        raw = bytes(packet[IP].payload)
        if raw in payloads:
            matching.append(raw)
    wrpcap(args.pcap, packets)
    print(
        "B7_SEND_JSON="
        + json.dumps(
            {
                "sent": sent,
                "captured_matching": len(matching),
                "pcap": args.pcap,
            },
            sort_keys=True,
        )
    )
    if len(matching) != len(sent):
        sys.exit(1)


if __name__ == "__main__":
    main()
