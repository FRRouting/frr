#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_burst.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#
"""Craft OSPFv3 Hellos with attacker-chosen DR/BDR/priority fields, send
them on the wire at a fixed spacing, and prove transmission.

Used by test_ospf6_election_churn.py to inject forged Hellos from the
peer's namespace.  Every packet is built as raw bytes (OSPFv3 header with
the IPv6 pseudo-header checksum, as RFC 5340 A.3 requires and FRR's
in_cksum_with_ph6 computes), wrapped in a raw Ethernet/IPv6 frame, and
sent with a fixed spacing.  A capture on the sending interface must
observe each exact payload; the matching packets are written to a pcap as
evidence that the trigger reached the wire.

Runs inside the peer router's network namespace; the pcap path must be
visible from the host (use the test's logdir).
"""

import argparse
import json
import socket
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, IPv6, Raw, conf, sendp, wrpcap

conf.verb = 0

OSPF_PROTO = 89


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv6_ph_checksum(src, dst, payload):
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
        + struct.pack("!I", len(payload))
        + b"\x00\x00\x00"
        + bytes((OSPF_PROTO,))
    )
    return internet_checksum(pseudo + payload)


def build_hello(args, fields, corrupt):
    neighbors = (
        [socket.inet_aton(rid) for rid in args.neighbor_rids.split(",")]
        if args.neighbor_rids
        else []
    )
    body = struct.pack(
        "!IB3sHH4s4s",
        args.ifindex,
        fields["priority"],
        bytes((0x00, 0x00, 0x13)),
        args.hello_interval,
        args.dead_override if args.dead_override else args.dead_interval,
        socket.inet_aton(fields["dr"]),
        socket.inet_aton(fields["bdr"]),
    ) + b"".join(neighbors)
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHBB",
            3,
            1,
            16 + len(body),
            socket.inet_aton(args.packet_rid),
            socket.inet_aton(args.area),
            0,
            0,
            0,
        )
        + body
    )
    struct.pack_into(
        "!H",
        packet,
        12,
        ipv6_ph_checksum(args.src_ll, args.dst_ll, bytes(packet)),
    )
    if corrupt:
        packet[12] ^= 0x5A
    return bytes(packet)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--src-ll", required=True)
    parser.add_argument("--dst-ll", required=True)
    parser.add_argument("--packet-rid", required=True)
    parser.add_argument("--ifindex", type=int, required=True)
    parser.add_argument("--neighbors", dest="neighbor_rids", default="")
    parser.add_argument("--area", default="0.0.0.0")
    parser.add_argument("--hello-interval", type=int, default=30)
    parser.add_argument("--dead-interval", type=int, default=40)
    parser.add_argument(
        "--dead-override",
        type=int,
        default=0,
        help="if nonzero, put this value in the RouterDeadInterval field",
    )
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
        filter="ip6 proto %d and src host %s and dst host %s"
        % (OSPF_PROTO, args.src_ll, args.dst_ll),
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
                Ether(src=args.src_mac, dst="33:33:00:00:00:05")
                / IPv6(src=args.src_ll, dst=args.dst_ll, hlim=1, nh=OSPF_PROTO)
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
        if not packet.haslayer(IPv6):
            continue
        raw = bytes(packet[IPv6].payload)
        if raw in payloads:
            matching.append(raw)
    wrpcap(args.pcap, packets)
    print(
        "O6_SEND_JSON="
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
