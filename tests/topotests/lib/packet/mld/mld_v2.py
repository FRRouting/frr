#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  mld_v2.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

import argparse

from scapy.fields import BitField, XShortField, IP6Field, ByteField, ByteEnumField, ShortField, PacketListField
from scapy.layers.inet6 import icmp6types, ICMPv6MLDMultAddrRec

from mld import MLD

class MLDv2(MLD):
    """
    MLDv2 (Multicast Listener Discovery version 2) class for creating and handling MLDv2 packets.

    Inherits from:
        MLD: Base class for MLD packets.

    Attributes:
        name (str): Name of the packet type.
        fields_desc (list): List of fields in the packet.
        type (int): Type of MLD message.
        code (int): Code of MLD message.
        cksum (int): Checksum of the packet.
        reserved (int): Reserved field.
        src_ip (str): Source IP address.
        dst_ip (str): Destination IP address.
        options (list): List of options for the packet.
        records (list): List of multicast address records.
        records_number (int): Number of multicast address records.

    Record Type values:
        1: MODE_IS_INCLUDE
        2: MODE_IS_EXCLUDE
        3: CHANGE_TO_INCLUDE_MODE
        4: CHANGE_TO_EXCLUDE_MODE
        5: ALLOW_NEW_SOURCES
        6: BLOCK_OLD_SOURCES

    Methods:
        __init__(self, proto_type=143, code=0, rtype=1, chksum=None, src_ip="fe80::1", dst_ip="ff02::fb", records=[], *args, **kwargs):
            Initializes an MLDv2 packet with the given parameters.

        enable_router_alert(self):
            Enables the Router Alert option for the packet.

        send(self, iface="eth0", count=1, interval=0):
            Sends the MLDv2 packet on the specified network interface.
    """
    name = "MLDv2"
    fields_desc = [
        ByteEnumField("type", 143, icmp6types),
        ByteField("code", 0),
        XShortField("cksum", None),
        BitField("reserved", 0, 16),
        BitField("records_number", 0, 16),
        PacketListField("records",
                        [],
                        ICMPv6MLDMultAddrRec,
                        count_from=lambda p: p.records_number)
    ]

    def __init__(self, proto_type=143, code=0, rtype=1,
                 chksum=None, src_ip="fe80::1", dst_ip="ff02::16", maddrs=[], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = proto_type
        self.code = code
        self.cksum = chksum
        self.reserved = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.options = []

        num_maddrs = len(maddrs)
        grouped_sources = [[] for _ in range(num_maddrs)]
        for index, source in enumerate(maddrs):
            grouped_sources[index % num_maddrs].append(source)

        for maddr, sources in zip(maddrs, grouped_sources):
            self.records.append(ICMPv6MLDMultAddrRec(dst=maddr, rtype=rtype))

        self.records_number = num_maddrs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send an MLDv2 packet")
    parser.add_argument("--type", type=int, default=143, help="Type of MLD message")
    parser.add_argument("--code", type=int, default=0, help="Code of MLD message")
    parser.add_argument("--chksum", type=int, default=None, help="Checksum of the packet")
    parser.add_argument("--src_ip", type=str, default="fe80::1", help="Source IP address")
    parser.add_argument("--dst_ip", type=str, default="ff02::16", help="Destination IP address")
    parser.add_argument("--maddr", action='append', default=[], help="Multicast Address Records")
    parser.add_argument("--rtype", type=int, default=2, help="Record type")
    parser.add_argument("--enable_router_alert", action="store_true", help="Enable Router Alert option")
    parser.add_argument("--iface", type=str, default="eth0", help="Network interface to send the packet")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--interval", type=int, default=0, help="Interval between packets")

    args = parser.parse_args()

    packet = MLDv2(maddrs=args.maddr,
                   src_ip=args.src_ip,
                   dst_ip=args.dst_ip,
                   rtype=args.rtype,
                   proto_type=args.type,
                   code=args.code)

    if args.enable_router_alert:
        packet.enable_router_alert()

    packet.send(iface=args.iface, count=args.count, interval=args.interval)
