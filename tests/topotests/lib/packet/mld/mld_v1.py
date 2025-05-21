#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  mld_v1.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

import argparse

from scapy.fields import BitField, XShortField, IP6Field, ByteField, ByteEnumField, ShortField
from scapy.layers.inet6 import icmp6types

from mld import MLD

class MLDv1(MLD):
    """
    MLDv1 is a class representing an MLD (Multicast Listener Discovery) version 1 packet.

    Attributes:
        type (int): Type of MLD message, default is 0x11.
        code (int): Code of MLD message, default is 0.
        cksum (int): Checksum of the packet, default is None.
        mrd (int): Maximum response delay, default is 0.
        reserved (int): Reserved field, default is 0.
        mladdr (str): Multicast address, default is "::".
        src_ip (str): Source IP address, default is "fe80::1".
        dst_ip (str): Destination IP address, default is "fe80::2".
        options (list): List of options, default is an empty list.

    Methods:
        __init__(self, type=0x11, code=0, max_response_delay=0, chksum=None, gaddr="ff02::1", src_ip="fe80::1", dst_ip="fe80::2", *args, **kwargs):
            Initializes an MLDv1 packet with the given parameters.

        send(self, iface="eth0", count=1, interval=0):
            Sends the MLDv1 packet on the specified network interface.
    """

    name = "MLDv1"
    fields_desc = [
        ByteEnumField("type", 130, icmp6types),
        ByteField("code", 0),
        XShortField("cksum", None),
        ShortField("mrd", 0),
        ShortField("reserved", 0),
        IP6Field("mladdr", "::")
    ]

    def __init__(self, type=0x11, code=0, max_response_delay=0, chksum=None, gaddr="ff02::1", src_ip="fe80::1", dst_ip="ff02::16", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = type
        self.code = code
        self.mrd = max_response_delay
        self.cksum = chksum
        self.reserved = 0
        self.mladdr = gaddr
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.options = []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send an MLDv1 packet")
    parser.add_argument("--type", type=lambda x: int(x, 0), default=0x83, help="Type of MLD message")
    parser.add_argument("--code", type=int, default=0, help="Code of MLD message")
    parser.add_argument("--max_response_delay", type=int, default=0, help="Maximum response delay")
    parser.add_argument("--chksum", type=int, default=None, help="Checksum of the packet")
    parser.add_argument("--gaddr", type=str, default="ff02::1", help="Group address")
    parser.add_argument("--src_ip", type=str, default="fe80::1", help="Source IP address")
    parser.add_argument("--dst_ip", type=str, default="ff02::16", help="Destination IP address")
    parser.add_argument("--enable_router_alert", action="store_true", help="Enable Router Alert option")
    parser.add_argument("--iface", type=str, default="eth0", help="Network interface to send the packet")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--interval", type=int, default=0, help="Interval between packets")

    args = parser.parse_args()

    mld_packet = MLDv1(gaddr=args.gaddr,
                        src_ip=args.src_ip,
                        dst_ip=args.dst_ip,
                        type=args.type,
                        code=args.code,
                        max_response_delay=args.max_response_delay)

    if args.enable_router_alert:
        mld_packet.enable_router_alert()

    mld_packet.send(iface=args.iface, count=args.count, interval=args.interval)
