#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Network Education Foundation, Inc. ("NetDEF")
#                    Rafael Zalamena

"""
Periodically send PIM Bootstrap Messages (BSM) imitating a BSR.

This script plays the BSR role so the BSM contents are fully controlled:
it builds the BSM with the configured BSR/C-RP information and sends it
to ALL-PIM-ROUTERS (224.0.0.13) every `--interval` seconds.
"""

import argparse
import ipaddress
import random
import socket
import struct
import sys
import time

PIM_VERSION = 2
PIM_MSG_TYPE_BOOTSTRAP = 4
ALL_PIM_ROUTERS = "224.0.0.13"
ADDRESS_FAMILY_IPV4 = 1
NATIVE_ENCODING = 0


def checksum(data):
    "Internet checksum (RFC 1071)."
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def encoded_unicast(address):
    return struct.pack(
        "!BB4s",
        ADDRESS_FAMILY_IPV4,
        NATIVE_ENCODING,
        ipaddress.IPv4Address(address).packed,
    )


def encoded_group(prefix):
    network = ipaddress.IPv4Network(prefix)
    return struct.pack(
        "!BBBB4s",
        ADDRESS_FAMILY_IPV4,
        NATIVE_ENCODING,
        0,  # B (bidir) and Z (admin scope) flags
        network.prefixlen,
        network.network_address.packed,
    )


def build_bsm(bsr, bsr_priority, hash_mask_length, groups):
    """
    Build a single fragment BSM.

    `groups` is a dictionary of group prefix to a list of
    `(rp_address, rp_priority, hold_time)` tuples.
    """
    payload = struct.pack(
        "!HBB", random.randint(0, 0xFFFF), hash_mask_length, bsr_priority
    )
    payload += encoded_unicast(bsr)
    for group, rps in groups.items():
        payload += encoded_group(group)
        payload += struct.pack("!BBH", len(rps), len(rps), 0)
        for rp, rp_priority, hold_time in rps:
            payload += encoded_unicast(rp)
            payload += struct.pack("!HBB", hold_time, rp_priority, 0)

    header = struct.pack("!BBH", (PIM_VERSION << 4) | PIM_MSG_TYPE_BOOTSTRAP, 0, 0)
    message = header + payload
    return message[:2] + struct.pack("!H", checksum(message)) + message[4:]


def parse_rp(value):
    "Parse 'RP,PRIORITY[,HOLDTIME]' (hold time defaults to 150, as in RFC 5059)."
    fields = value.split(",")
    if len(fields) not in (2, 3):
        raise argparse.ArgumentTypeError("expected RP,PRIORITY[,HOLDTIME]")
    hold_time = int(fields[2]) if len(fields) == 3 else 150
    return (fields[0], int(fields[1]), hold_time)


def main():
    parser = argparse.ArgumentParser(description="Send PIM BSM periodically")
    parser.add_argument("source", help="Interface address to send from")
    parser.add_argument("bsr", help="BSR address")
    parser.add_argument("--bsr-priority", type=int, default=64)
    parser.add_argument("--hash-mask-length", type=int, default=30)
    parser.add_argument("--group", default="224.0.0.0/4")
    parser.add_argument(
        "--rp",
        action="append",
        type=parse_rp,
        required=True,
        help="Candidate RP as RP,PRIORITY[,HOLDTIME] (may repeat)",
    )
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--count", type=int, default=0, help="0 means forever")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_PIM)
    sock.setsockopt(
        socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.source)
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    sock.bind((args.source, 0))

    sent = 0
    while args.count == 0 or sent < args.count:
        bsm = build_bsm(
            args.bsr,
            args.bsr_priority,
            args.hash_mask_length,
            {args.group: args.rp},
        )
        sock.sendto(bsm, (ALL_PIM_ROUTERS, 0))
        sent += 1
        print(f"sent BSM #{sent} ({len(bsm)} bytes)", flush=True)
        time.sleep(args.interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
