#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_packet.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#
"""Craft one OSPF packet, send it on the wire, and prove transmission.

Used by test_ospf_nbma_unconfigured_neighbor.py to inject packets from
the unconfigured source's namespace.  Hellos are built with scapy's
OSPF layers (so length and checksum are computed the same way a router
would); Database Description packets are built from raw bytes the same
way.  A capture on the sending interface must observe the exact payload
once per transmission; the matching packets are written to a pcap as
evidence that the trigger reached the wire.

Runs inside the sending node's network namespace; the pcap path must be
visible from the host (use the test's logdir).
"""

import argparse
import json
import socket
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, IP, Raw, conf, sendp, wrpcap
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

conf.verb = 0

ALL_SPF_ROUTERS = "224.0.0.5"
ALL_SPF_ROUTERS_MAC = "01:00:5e:00:00:05"
OSPF_PROTO = 89


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_hello(args, neighbor_rids):
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
    return bytes(payload)


def build_dd(args):
    body = struct.pack("!HBBI", args.dd_mtu, 0x02, args.dd_flags, args.dd_seqnum)
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8s",
            2,
            2,
            24 + len(body),
            socket.inet_aton(args.packet_rid),
            socket.inet_aton(args.area),
            0,
            0,
            b"\x00" * 8,
        )
        + body
    )
    checksum = internet_checksum(bytes(packet))
    struct.pack_into("!H", packet, 12, checksum)
    if internet_checksum(bytes(packet)) != 0:
        raise ValueError("invalid generated OSPF checksum")
    if args.corrupt_checksum:
        struct.pack_into("!H", packet, 12, checksum ^ 1)
        if internet_checksum(bytes(packet)) == 0:
            raise ValueError("corrupted OSPF checksum unexpectedly valid")
    return bytes(packet)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("hello", "dd"), required=True)
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
    parser.add_argument("--dd-mtu", type=int, default=1500)
    parser.add_argument("--dd-flags", type=lambda v: int(v, 0), default=0x07)
    parser.add_argument("--dd-seqnum", type=lambda v: int(v, 0), default=0x01)
    parser.add_argument(
        "--corrupt-checksum",
        action="store_true",
        help="flip a bit in the OSPF checksum after building the packet",
    )
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--spacing", type=float, default=0.6)
    parser.add_argument("--pcap", required=True)
    args = parser.parse_args()

    neighbor_rids = [n for n in args.neighbors.split(",") if n]
    if args.mode == "hello":
        payload = build_hello(args, neighbor_rids)
    else:
        payload = build_dd(args)

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
    time.sleep(0.4)
    sent_at = []
    for index in range(args.count):
        if index:
            time.sleep(args.spacing)
        sent_at.append(round(time.time(), 6))
        sendp(bytes(frame), iface=args.iface, verbose=False)
    time.sleep(1.2)
    packets = list(sniffer.stop())

    matching = [
        packet
        for packet in packets
        if packet.haslayer(IP) and bytes(packet[IP].payload) == payload
    ]
    wrpcap(args.pcap, matching)
    print(
        "B8_SEND_JSON="
        + json.dumps(
            {
                "mode": args.mode,
                "sent": args.count,
                "sent_at": sent_at,
                "captured": len(matching),
                "packet_router_id": args.packet_rid,
                "neighbor_rids": neighbor_rids,
                "corrupt_checksum": args.corrupt_checksum,
                "ospf_checksum": "0x%04x" % struct.unpack_from("!H", payload, 12)[0],
                "pcap": args.pcap,
            },
            sort_keys=True,
        )
    )
    if len(matching) != args.count:
        sys.exit(1)


if __name__ == "__main__":
    main()
