#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# igmp_send.py
#
# Copyright (c) 2026 by
# Vitaliy Guschin <guschin108@gmail.com>
#

import os
import sys
import argparse
import json

from scapy.main import load_contrib
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, IPOption_Router_Alert
from scapy.sendrecv import sendp

# pylint: disable=C0413
load_contrib('igmpv3')
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3gr

def get_packet(rtype, group, src_ip, sources):
    "Builds a single Ethernet/IP/IGMPv3 Membership Report packet"

    record = IGMPv3gr(rtype=rtype, maddr=group, srcaddrs=sources)

    pkt = (
        Ether(dst="01:00:5e:00:00:16") /
        IP(src=src_ip, dst="224.0.0.22", options=[IPOption_Router_Alert()]) /
        IGMPv3() /
        IGMPv3mr(records=[record])
    )
    return pkt

def main():
    parser = argparse.ArgumentParser(description="IGMPv3 Host Script")
    parser.add_argument("--mode", choices=["include", "block"], required=True,
                        help="Operation mode: 'include' (rtype 1) or 'block' (rtype 6)")
    parser.add_argument("--group", required=True, help="Target Multicast Group IP")
    parser.add_argument("--src", required=True, help="Source IP (Packet Sender)")
    parser.add_argument("--json", required=True, help="Path to JSON file containing source IP list")
    parser.add_argument("--iface", default="h1-eth0", help="Network interface to use")
    parser.add_argument("--step", type=int, default=250, help="Number of source IPs per packet")
    args = parser.parse_args()

    # Load source IPs from JSON file
    try:
        with open(args.json, 'r') as f:
            data = json.load(f)
            sources = data if isinstance(data, list) else data.get("sources", [])
    except Exception as e:
        print(f"JSON error: {e}")
        sys.exit(1)

    if not sources:
        print("No sources found")
        sys.exit(1)

    # Prepare packets
    # rtype 1 = MODE_IS_INCLUDE, rtype 6 = BLOCK_OLD_SOURCES
    rtype = 1 if args.mode == "include" else 6

    # Generate list of packets using the provided step size
    packets = [
        get_packet(rtype, args.group, args.src, sources[i : i + args.step])
        for i in range(0, len(sources), args.step)
    ]

    # Transmission
    try:
        sendp(packets, iface=args.iface, verbose=False)
    except Exception as e:
        print(f"Send error: {e}")

    print(f"Success")

if __name__ == "__main__":
    main()
