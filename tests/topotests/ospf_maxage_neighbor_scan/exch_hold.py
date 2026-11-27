#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# exch_hold.py
#
# Copyright (c) 2026 ATCorp
#
"""Park an OSPF neighbor in Exchange state with a scapy-driven host.

Used by test_ospf_maxage_neighbor_scan.py.  The host speaks just enough
OSPF (Hello + Database Description) to move the victim's neighbor state to
Exchange and keep it there: once the victim is the DD slave it waits for
the master's next DD, which never arrives.
"""

import argparse
import json
import socket
import struct
import sys
import time

from scapy.all import Ether, IP, Raw, conf, sendp

conf.verb = 0


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ospf_packet(cfg, packet_type, body):
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8s",
            2,
            packet_type,
            24 + len(body),
            socket.inet_aton(cfg["exch_rid"]),
            socket.inet_aton("0.0.0.0"),
            0,
            0,
            b"\x00" * 8,
        )
        + body
    )
    struct.pack_into("!H", packet, 12, internet_checksum(bytes(packet)))
    return bytes(packet)


def send(cfg, packet_type, body):
    frame = (
        Ether(src=cfg["src_mac"], dst=cfg["dst_mac"])
        / IP(src=cfg["src_ip"], dst=cfg["dst_ip"], ttl=1, proto=89)
        / Raw(ospf_packet(cfg, packet_type, body))
    )
    sendp(frame, iface=cfg["iface"], count=1, verbose=False)


def hello_body(cfg):
    # Interval/dead must match the victim's interface configuration.
    return (
        socket.inet_aton("255.255.255.0")
        + struct.pack("!H", cfg["hello_interval"])
        + bytes((0x02, 0))
        + struct.pack("!I", cfg["dead_interval"])
        + socket.inet_aton(cfg["victim_ip"])
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
    parser.add_argument("--victim-ip", required=True)
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
        "victim_ip": args.victim_ip,
        "hello_interval": args.hello_interval,
        "dead_interval": args.dead_interval,
    }

    if args.mode == "hello_burst":
        for _ in range(args.count):
            send(cfg, 1, hello_body(cfg))
            time.sleep(args.interval)
    elif args.mode == "dd_handshake":
        # ExStart: claim master (higher router-id than the victim), init set.
        send(cfg, 2, struct.pack("!HBBI", 1500, 0x02, 0x07, args.dd_seq))
        time.sleep(0.5)
        # Exchange: keep the more bit set so the victim never finishes.
        send(cfg, 2, struct.pack("!HBBI", 1500, 0x02, 0x03, args.dd_seq + 1))
    elif args.mode == "hold":
        # Keep the neighbor alive with hellos; never resume the DD exchange.
        deadline = time.time() + args.duration
        while time.time() < deadline:
            send(cfg, 1, hello_body(cfg))
            time.sleep(args.interval)
    print("OA1_EXCH_OK mode=%s" % args.mode)


if __name__ == "__main__":
    sys.exit(main())
