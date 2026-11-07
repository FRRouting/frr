#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Send one crafted OSPFv3 Hello to AllSPFRouters on a test link."""

import argparse
import socket
import struct

ALL_SPF_ROUTERS = "ff02::5"
IPPROTO_OSPF = 89
OPT_L = 1 << 1  # options[1]: an LLS block follows the packet
OPT_V6_E_R = (1 << 0) | (1 << 1) | (1 << 4)  # options[2]
HELLO_INTERVAL = 10
DEAD_INTERVAL = 40


def inet_checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_hello(args, src):
    hello = struct.pack(
        "!IB3BHHII",
        1,
        1,
        0,
        OPT_L if args.lls else 0,
        OPT_V6_E_R,
        HELLO_INTERVAL,
        DEAD_INTERVAL,
        0,
        0,
    )
    length = 16 + len(hello)
    header = struct.pack(
        "!BBH4s4sHBB", 3, 1, length, socket.inet_aton(args.router_id), bytes(4), 0, 0, 0
    )
    # RFC 5340 A.3.1: the pseudo-header's length is the OSPF length field, so
    # the checksum never covers an LLS block appended after the packet.
    pseudo_header = (
        socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, ALL_SPF_ROUTERS)
        + struct.pack("!I3xB", length, IPPROTO_OSPF)
    )
    checksum = inet_checksum(pseudo_header + header + hello)
    if args.bad_checksum:
        checksum ^= 1
    packet = header[:12] + struct.pack("!H", checksum) + header[14:] + hello

    if args.lls:
        # RFC 5613: checksum, length in words, then an Extended Options TLV.
        lls = struct.pack("!HHHHI", 0, 3, 1, 4, 0)
        lls = struct.pack("!H", inet_checksum(lls)) + lls[2:]
        packet += lls
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ifname")
    parser.add_argument("router_id")
    parser.add_argument("--bad-checksum", action="store_true")
    parser.add_argument("--lls", action="store_true")
    args = parser.parse_args()

    ifindex = socket.if_nametoindex(args.ifname)
    # The kernel fills in no checksum here, IPV6_CHECKSUM is not set.
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_OSPF) as sock:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        sock.connect((ALL_SPF_ROUTERS, 0, 0, ifindex))
        src = sock.getsockname()[0].split("%")[0]
        sock.send(build_hello(args, src))


if __name__ == "__main__":
    main()
