#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# exch_hold.py
#
# Copyright (c) 2026 ATCorp
#
"""Park an OSPFv3 neighbor in Exchange state with a scapy-driven host.

Used by test_ospf6_maxage_neighbor_scan.py.  The host speaks just enough
OSPFv3 (Hello + Database Description) to move the victim's neighbor state
to Exchange and keep it there: once the victim is the DD slave it waits
for the master's next DD, which never arrives.
"""

import argparse
import socket
import struct
import sys
import time

from scapy.all import Ether, IPv6, Raw, conf, sendp

conf.verb = 0


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
        + bytes((89,))
    )
    return internet_checksum(pseudo + payload)


def ospf6_packet(cfg, packet_type, body):
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHBB",
            3,
            packet_type,
            16 + len(body),
            socket.inet_aton(cfg["exch_rid"]),
            socket.inet_aton("0.0.0.0"),
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
        ipv6_ph_checksum(cfg["src_ip"], cfg["dst_ip"], bytes(packet)),
    )
    return bytes(packet)


def send(cfg, packet_type, body):
    frame = (
        Ether(src=cfg["src_mac"], dst=cfg["dst_mac"])
        / IPv6(src=cfg["src_ip"], dst=cfg["dst_ip"], hlim=1, nh=89)
        / Raw(ospf6_packet(cfg, packet_type, body))
    )
    sendp(frame, iface=cfg["iface"], count=1, verbose=False)


def hello_body(cfg):
    # Interval/dead must match the victim's interface configuration; the
    # E-bit must match the (normal) area options.
    return (
        struct.pack("!I", cfg["ifindex"])
        + bytes((0,))
        + bytes((0x00, 0x00, 0x13))
        + struct.pack("!HH", cfg["hello_interval"], cfg["dead_interval"])
        + socket.inet_aton(cfg["victim_rid"])
        + socket.inet_aton("0.0.0.0")
        + socket.inet_aton(cfg["victim_rid"])
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--dst-mac", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--exch-rid", required=True)
    parser.add_argument("--victim-rid", required=True)
    parser.add_argument("--mode", required=True, choices=["hello_burst", "dd_handshake", "hold"])
    parser.add_argument("--count", type=int, default=6)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--hello-interval", type=int, default=1)
    parser.add_argument("--dead-interval", type=int, default=10)
    parser.add_argument("--dd-seq", type=lambda v: int(v, 0), default=0x0A1B2C3D)
    args = parser.parse_args()

    cfg = {
        "iface": args.iface,
        "src_mac": args.src_mac,
        "dst_mac": args.dst_mac,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "exch_rid": args.exch_rid,
        "victim_rid": args.victim_rid,
        "ifindex": socket.if_nametoindex(args.iface),
        "hello_interval": args.hello_interval,
        "dead_interval": args.dead_interval,
    }

    if args.mode == "hello_burst":
        for _ in range(args.count):
            send(cfg, 1, hello_body(cfg))
            time.sleep(args.interval)
    elif args.mode == "dd_handshake":
        # ExStart: claim master (higher router-id than the victim); the
        # slave only accepts a master DD with init, more and master set.
        send(cfg, 2, bytes((0, 0x00, 0x00, 0x13))
             + struct.pack("!HBBI", 1500, 0, 0x07, args.dd_seq))
        time.sleep(0.5)
        # Exchange: the slave expects seq+1 and the master bit kept set;
        # keep the more bit set so the victim never finishes.
        send(cfg, 2, bytes((0, 0x00, 0x00, 0x13))
             + struct.pack("!HBBI", 1500, 0, 0x03, args.dd_seq + 1))
    elif args.mode == "hold":
        # Keep the neighbor alive with hellos; never resume the DD exchange.
        deadline = time.time() + args.duration
        while time.time() < deadline:
            send(cfg, 1, hello_body(cfg))
            time.sleep(args.interval)
    print("O6A1_EXCH_OK mode=%s" % args.mode)


if __name__ == "__main__":
    sys.exit(main())
