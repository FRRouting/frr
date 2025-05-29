#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  igmp.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#
import struct

from scapy.all import Packet
from scapy.layers.inet import IP, IPOption_Router_Alert
from scapy.layers.l2 import Ether
from scapy.packet import bind_layers
from scapy.sendrecv import sendp

def calculate_checksum(packet):
    if len(packet) % 2 == 1:
        packet += b'\0'
    s = sum(struct.unpack("!%dH" % (len(packet) // 2), packet))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

class IGMP(Packet):
    """
    Base class for creating and manipulating IGMP packets.

    Methods:
        __init__(self, version=1, type=0x11, chksum=None, gaddr="0.0.0.0", src_ip="192.168.100.1", *args, **kwargs):
            Initializes an IGMP packet with the given parameters.
        send(self, iface, count=1, interval=0):
            Sends the IGMP packet on the specified interface.
        enable_router_alert(self):
            Enables the Router Alert option for the IGMP packet.
    """

    def enable_router_alert(self):
        router_alert = IPOption_Router_Alert()
        self.options.append(router_alert)

    def post_build(self, p, pay):
        if self.chksum is None:
            chksum = calculate_checksum(p)
            p = p[:2] + struct.pack("!H", chksum) + p[4:]
        return p + pay

    def send(self, interval=0, count=1, iface="eth0"):
        bind_layers(IP, IGMP, proto=2)

        if self.options:
            packet = Ether() / IP(dst=self.gaddr, tos=0xc0, id=0, ttl=1, src=self.src_ip, options=self.options, proto=2, frag=0) / self
        else:
            packet = Ether() / IP(dst=self.gaddr, tos=0xc0, id=0, ttl=1, src=self.src_ip, proto=2, frag=0) / self

        sendp(packet, inter=int(interval), iface=iface, count=int(count))