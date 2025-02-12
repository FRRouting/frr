#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  igmp_v1.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

import argparse

from igmp import IGMP

from scapy.all import ByteField, IPField
from scapy.fields import XShortField, BitField


class IGMPv1(IGMP) :
    """
    Represents an IGMPv1 packet.

    Attributes:
        version (int): IGMP version (default is 1).
        type (int): The type of the IGMP message (default is 0x11).
        unused (int): The maximum response time (default is 0).
        chksum (int): Checksum of the packet.
        gaddr (str): The group address (default is "0.0.0.0").
        src_ip (str): Source IP address (default is "192.168.100.1").
        options (list): Additional options for the packet.

    Methods:
        __init__(self, version=1, type=0x11, unused=0, chksum=None, gaddr="0.0.0.0", src_ip="192.168.100.1", *args, **kwargs):
            Initializes an IGMPv1 packet with the given parameters.
    """

    name = "IGMPv1"
    fields_desc = [
        BitField("version", 1, 4),
        BitField("type", 0x11, 4),
        ByteField("unused", 0),
        XShortField("chksum", None),
        IPField("gaddr", "0.0.0.0")
    ]

    def __init__(self, version=1, type=0x11, unused=0, chksum=None, gaddr="0.0.0.0", src_ip="192.168.100.1", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.version = version
        self.type = type
        self.unused = unused
        self.chksum = chksum
        self.gaddr = gaddr
        self.src_ip = src_ip
        self.options = []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send an IGMPv1 packet")
    parser.add_argument("--gaddr", type=str, default="224.0.0.1", help="Group address")
    parser.add_argument("--src_ip", type=str, default="192.168.1.10", help="Source IP address")
    parser.add_argument("--type", type=lambda x: int(x, 0), default=0x11, help="Type of IGMP message")
    parser.add_argument("--enable_router_alert", action="store_true", help="Enable Router Alert option")
    parser.add_argument("--iface", type=str, default="eth0", help="Network interface to send the packet")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--interval", type=int, default=0, help="Interval between packets")

    args = parser.parse_args()

    igmp_packet = IGMPv1(gaddr=args.gaddr, src_ip=args.src_ip, type=args.type)
    if args.enable_router_alert:
        igmp_packet.enable_router_alert()
    igmp_packet.send(iface=args.iface, count=args.count, interval=args.interval)