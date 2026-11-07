#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_lsu.py
#
# Copyright (c) 2026 ATCorp
#
"""Build and send raw OSPFv3 Link State Update packets.

Used by test_ospf6_maxage_neighbor_scan.py to inject AS-external LSAs with
arbitrary LS age and (optionally) broken Fletcher checksum, bypassing the
well-formedness of high-level packet helpers.
"""

import argparse
import socket
import struct
import sys
import time

from scapy.all import Ether, IPv6, Raw, conf, sendp

conf.verb = 0

FAKE_ADV = "99.99.99.99"
# 20-byte LSA header + 24-byte AS-external body; 16 LSAs stay under MTU 1500.
LSA_CHUNK = 16


def lsa_id(index):
    return "198.18.%d.%d" % (index // 256, index % 256)


def fletcher_checksum(lsa):
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
    if (c1 << 8) + c0 != 0:
        raise ValueError("invalid generated LSA Fletcher checksum")
    return (x << 8) | y


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


def make_external_lsa(index, age, corrupt):
    body = (
        struct.pack("!I", 10)
        + bytes((128, 0))
        + struct.pack("!H", 0)
        + socket.inet_pton(socket.AF_INET6, "2001:db8:ffff::1")
    )
    lsa = bytearray(
        struct.pack(
            "!HH4s4sIHH",
            age,
            0x4005,
            socket.inet_aton(lsa_id(index)),
            socket.inet_aton(FAKE_ADV),
            0x80000001,
            0,
            20 + len(body),
        )
        + body
    )
    struct.pack_into("!H", lsa, 16, fletcher_checksum(lsa))
    if corrupt:
        lsa[17] ^= 0x5A
    return bytes(lsa)


def make_lsu(lsa_blobs, src_rid, src_ip, dst_ip):
    body = struct.pack("!I", len(lsa_blobs)) + b"".join(lsa_blobs)
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHBB",
            3,
            4,
            16 + len(body),
            socket.inet_aton(src_rid),
            socket.inet_aton("0.0.0.0"),
            0,
            0,
            0,
        )
        + body
    )
    struct.pack_into(
        "!H", packet, 12, ipv6_ph_checksum(src_ip, dst_ip, bytes(packet))
    )
    if ipv6_ph_checksum(src_ip, dst_ip, bytes(packet)) != 0:
        raise ValueError("invalid generated OSPFv3 pseudo-header checksum")
    return bytes(packet)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--dst-mac", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--src-rid", required=True)
    parser.add_argument("--count", type=int, default=16)
    parser.add_argument("--first-index", type=int, default=1)
    parser.add_argument("--age", type=int, default=3600)
    parser.add_argument("--corrupt", action="store_true")
    parser.add_argument("--spacing", type=float, default=0.3)
    args = parser.parse_args()

    blobs = [
        make_external_lsa(index, args.age, args.corrupt)
        for index in range(args.first_index, args.first_index + args.count)
    ]
    packets = [
        make_lsu(blobs[off : off + LSA_CHUNK], args.src_rid, args.src_ip, args.dst_ip)
        for off in range(0, len(blobs), LSA_CHUNK)
    ]
    for index, payload in enumerate(packets):
        if index:
            time.sleep(args.spacing)
        frame = (
            Ether(src=args.src_mac, dst=args.dst_mac)
            / IPv6(src=args.src_ip, dst=args.dst_ip, hlim=1, nh=89)
            / Raw(payload)
        )
        sendp(frame, iface=args.iface, count=1, verbose=False)
    print(
        "O6A1_INJECT packets=%d lsas=%d age=%d corrupt=%s first=%d"
        % (len(packets), args.count, args.age, args.corrupt, args.first_index)
    )


if __name__ == "__main__":
    sys.exit(main())
