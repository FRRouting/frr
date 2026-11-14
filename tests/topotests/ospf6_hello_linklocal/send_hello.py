#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_hello.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#
"""Craft an OSPFv3 Hello with an attacker-chosen IPv6 source address and
Router-ID, send it on the wire, and prove transmission.

Used by test_ospf6_hello_linklocal.py to inject Hello packets whose IPv6
source is a global (non-link-local) address, which RFC 5340 Section 2.5
does not permit on OSPF interfaces other than virtual links.  The packet
is built as raw bytes with a correct IPv6 pseudo-header checksum (as
RFC 5340 A.3 requires and FRR's in_cksum_with_ph6 computes), wrapped in a
raw Ethernet/IPv6 frame, and sent with a fixed spacing.  A capture on the
sending interface must observe each exact payload; the matching packets
are written to a pcap as evidence that the trigger reached the wire.

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


def build_hello(args):
    neighbors = (
        [socket.inet_aton(rid) for rid in args.neighbor_rids.split(",")]
        if args.neighbor_rids
        else []
    )
    body = struct.pack(
        "!IB3sHH4s4s",
        args.ifindex,
        args.priority,
        bytes((0x00, 0x00, 0x13)),
        args.hello_interval,
        args.dead_interval,
        socket.inet_aton(args.dr),
        socket.inet_aton(args.bdr),
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
        ipv6_ph_checksum(args.src_ip, args.dst_ip, bytes(packet)),
    )
    return bytes(packet)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--dst-mac", required=True)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--packet-rid", required=True)
    parser.add_argument("--ifindex", type=int, required=True)
    parser.add_argument("--neighbors", dest="neighbor_rids", default="")
    parser.add_argument("--area", default="0.0.0.0")
    parser.add_argument("--priority", type=int, default=1)
    parser.add_argument("--dr", default="0.0.0.0")
    parser.add_argument("--bdr", default="0.0.0.0")
    parser.add_argument("--hello-interval", type=int, default=30)
    parser.add_argument("--dead-interval", type=int, default=40)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--spacing", type=float, default=1.0)
    parser.add_argument("--tail", type=float, default=1.0)
    parser.add_argument("--pcap", required=True)
    args = parser.parse_args()

    sent = []
    payloads = []
    sniffer = AsyncSniffer(
        iface=args.iface,
        filter="ip6 proto %d and src host %s and dst host %s"
        % (OSPF_PROTO, args.src_ip, args.dst_ip),
        store=True,
    )
    sniffer.start()
    time.sleep(0.3)
    epoch = time.time()
    try:
        for index in range(args.count):
            if index:
                time.sleep(args.spacing)
            payload = build_hello(args)
            frame = (
                Ether(src=args.src_mac, dst=args.dst_mac)
                / IPv6(src=args.src_ip, dst=args.dst_ip, hlim=1, nh=OSPF_PROTO)
                / Raw(payload)
            )
            sendp(frame, iface=args.iface, count=1, verbose=False)
            sent.append({"time": round(time.time() - epoch, 6), "index": index})
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
