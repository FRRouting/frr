#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_ospf.py
#
# Send one raw OSPF packet (IP protocol 89) from a node namespace.

import sys

from scapy.all import IP, Raw, conf, send

conf.verb = 0

iface, src_ip, dst_ip, payload_hex = sys.argv[1:]
payload = bytes.fromhex(payload_hex)
send(
    IP(src=src_ip, dst=dst_ip, ttl=64, proto=89) / Raw(payload), iface=iface, verbose=0
)
print("sent=1")
