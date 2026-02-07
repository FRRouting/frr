#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  imgp_v2.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#
import argparse

from scapy.all import ByteField, ShortField, IPField
from scapy.fields import BitField
from igmp import IGMP

class IGMPv2(IGMP):
    """
    IGMPv2 class for creating and manipulating IGMP version 2 packets.

    Attributes:
        name (str): Name of the protocol.
        fields_desc (list): List of fields in the IGMPv2 packet.
        version (int): IGMP version.
        type (int): Type of IGMP message.
        max_resp_time (int): Maximum response time.
        chksum (int): Checksum of the packet.
        gaddr (str): Group address.
        src_ip (str): Source IP address.
        options (list): Additional options for the packet.

    Methods:
        __init__(self, version=1, type=0x11, max_resp_time=10, chksum=None, gaddr="0.0.0.0", src_ip="192.168.100.1", *args, **kwargs):
            Initializes an IGMPv2 packet with the given parameters.
    """

    name = "IGMPv2"
    fields_desc = [
        BitField("version", 1, 4),
        BitField("type", 0x11, 4),
        ByteField("max_resp_time", 10),
        ShortField("checksum", None),
        IPField("gaddr", "0.0.0.0")
    ]

    def __init__(self, version=1, type=0x11, max_resp_time=10, chksum=None, gaddr="0.0.0.0", src_ip="192.168.100.1", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.version = version
        self.type = type
        self.max_resp_time = max_resp_time
        self.chksum = chksum
        self.gaddr = gaddr
        self.src_ip = src_ip
        self.options = []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send an IGMPv2 packet")
    parser.add_argument("--gaddr", type=str, default="224.0.0.1", help="Group address")
    parser.add_argument("--src_ip", type=str, default="192.168.1.10", help="Source IP address")
    parser.add_argument("--type", type=lambda x: int(x, 0), default=0x11, help="Type of IGMP message")
    parser.add_argument("--enable_router_alert", action="store_true", help="Enable Router Alert option")
    parser.add_argument("--iface", type=str, default="eth0", help="Network interface to send the packet")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--interval", type=int, default=0, help="Interval between packets")

    args = parser.parse_args()

    igmp_packet = IGMPv2(gaddr=args.gaddr, src_ip=args.src_ip, type=args.type)
    if args.enable_router_alert:
        igmp_packet.enable_router_alert()
    igmp_packet.send(iface=args.iface, count=args.count, interval=args.interval)
