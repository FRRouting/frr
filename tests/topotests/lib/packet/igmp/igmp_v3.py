#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  imgp_v3.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#
import argparse

from scapy.all import ByteField, ShortField, IPField
from scapy.contrib.igmpv3 import IGMPv3gr
from scapy.fields import BitField, PacketListField
from scapy.layers.inet6 import ICMPv6MLDMultAddrRec

from igmp import IGMP

class IGMPv3(IGMP):
    name = "IGMPv3"
    fields_desc = [
        BitField("type", 0x22, 8),
        BitField("reserved1", None, 8),
        ShortField("checksum", None),
        ShortField("reserved2", None),
        ShortField("records_number", None),
        PacketListField("records",
                        [],
                        IGMPv3gr,
                        count_from=lambda p: p.records_number)
    ]

    def __init__(self, version=3, type=0x22, max_resp_time=10,
                 chksum=None, records=[], maddrs=[], rtype=1, gaddr="224.0.0.22",
                 src_ip="192.168.100.1", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.version = version
        self.type = type
        self.max_resp_time = max_resp_time
        self.chksum = chksum
        self.src_ip = src_ip
        self.options = []
        self.gaddr = gaddr

        num_maddrs = len(maddrs)
        grouped_sources = [[] for _ in range(num_maddrs)]
        for index, source in enumerate(records):
            grouped_sources[index % num_maddrs].append(source)

        for maddr, sources in zip(maddrs, grouped_sources):
            self.records.append(IGMPv3gr(numsrc=len(sources), srcaddrs=sources, maddr=maddr, rtype=rtype))

        self.records_number = num_maddrs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send an IGMPv3 packet")
    parser.add_argument("--gaddr", type=str, default="224.0.0.22", help="Destination IP address")
    parser.add_argument("--maddr", action='append', default=[], help="Multicast Address Records")
    parser.add_argument("--src_ip", type=str, default="192.168.1.10", help="Source IP address")
    parser.add_argument("--type", type=lambda x: int(x, 0), default=0x22, help="Type of IGMP message")
    parser.add_argument("--rtype", type=int, default=1, help="Record type")
    parser.add_argument("--enable_router_alert", action="store_true", help="Enable Router Alert option")
    parser.add_argument("--iface", type=str, default="eth0", help="Network interface to send the packet")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--interval", type=int, default=0, help="Interval between packets")

    args = parser.parse_args()

    igmp_packet = IGMPv3(maddrs=args.maddr,
                         src_ip=args.src_ip,
                         type=args.type,
                         gaddr=args.gaddr,
                         rtype=args.rtype)
    if args.enable_router_alert:
        igmp_packet.enable_router_alert()
    igmp_packet.send(iface=args.iface, count=args.count, interval=args.interval)
