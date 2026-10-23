#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_lsu.py
#
# Copyright (c) 2026 ATCorp
#
"""Build and send raw OSPF Link State Update packets.

Used by test_ospf_ase_forward_scan.py to inject AS-external LSAs with a
chosen forwarding address, bypassing the well-formedness of high-level
packet helpers.
"""

import argparse
import socket
import struct
import sys
import time

from scapy.all import Ether, IP, Raw, conf, sendp

conf.verb = 0

# 20-byte LSA header + 16-byte AS-external body; 16 LSAs stay under MTU 1500.
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


def make_external_lsa(index, adv_router, fwd, corrupt):
    body = (
        socket.inet_aton("255.255.255.255")
        + bytes((0x00,))
        + (10).to_bytes(3, "big")
        + socket.inet_aton(fwd)
        + (0).to_bytes(4, "big")
    )
    lsa = bytearray(
        struct.pack(
            "!HBB4s4sIHH",
            1,
            0x02,
            5,
            socket.inet_aton(lsa_id(index)),
            socket.inet_aton(adv_router),
            0x80000001,
            0,
            36,
        )
        + body
    )
    struct.pack_into("!H", lsa, 16, fletcher_checksum(lsa))
    if corrupt:
        lsa[17] ^= 0x5A
    return bytes(lsa)


def make_lsu(lsa_blobs, src_rid):
    body = struct.pack("!I", len(lsa_blobs)) + b"".join(lsa_blobs)
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8s",
            2,
            4,
            24 + len(body),
            socket.inet_aton(src_rid),
            socket.inet_aton("0.0.0.0"),
            0,
            0,
            b"\x00" * 8,
        )
        + body
    )
    struct.pack_into("!H", packet, 12, internet_checksum(bytes(packet)))
    if internet_checksum(bytes(packet)) != 0:
        raise ValueError("invalid generated OSPF checksum")
    return bytes(packet)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--dst-mac", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--src-rid", required=True)
    parser.add_argument("--adv-router", required=True)
    parser.add_argument("--fwd", required=True)
    parser.add_argument("--count", type=int, default=16)
    parser.add_argument("--first-index", type=int, default=1)
    parser.add_argument("--corrupt", action="store_true")
    parser.add_argument("--spacing", type=float, default=0.2)
    args = parser.parse_args()

    blobs = [
        make_external_lsa(index, args.adv_router, args.fwd, args.corrupt)
        for index in range(args.first_index, args.first_index + args.count)
    ]
    packets = [
        make_lsu(blobs[off : off + LSA_CHUNK], args.src_rid)
        for off in range(0, len(blobs), LSA_CHUNK)
    ]
    for index, payload in enumerate(packets):
        if index:
            time.sleep(args.spacing)
        frame = (
            Ether(src=args.src_mac, dst=args.dst_mac)
            / IP(src=args.src_ip, dst=args.dst_ip, ttl=1, proto=89)
            / Raw(payload)
        )
        sendp(frame, iface=args.iface, count=1, verbose=False)
    print(
        "OA2_INJECT packets=%d lsas=%d fwd=%s corrupt=%s first=%d"
        % (len(packets), args.count, args.fwd, args.corrupt, args.first_index)
    )


if __name__ == "__main__":
    sys.exit(main())
