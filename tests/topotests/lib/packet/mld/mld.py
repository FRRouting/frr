#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  mld.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, _ICMPv6ML, RouterAlert
from scapy.layers.l2 import Ether
from scapy.packet import bind_layers
from scapy.sendrecv import sendp

class MLD(_ICMPv6ML):
    """
    MLD is a class representing a Multicast Listener Discovery (MLD) packet.

    Attributes:
        name (str): Name of the packet, default is "MLD".
        options (list): List of options, default is an empty list.
        mladdr (str): Multicast address, default is "::".
        src_ip (str): Source IP address, default is "fe80::1".

    Methods:
        enable_router_alert(self):
            Enables the Router Alert option for the MLD packet.

        send(self, interval=0, count=1, iface="eth0"):
            Sends the MLD packet on the specified network interface.
    """

    name = "MLD"

    def enable_router_alert(self):
        router_alert = RouterAlert(value=0)
        self.options.append(router_alert)

    def send(self, interval=0, count=1, iface="eth0"):
        bind_layers(IPv6, MLD, nh=58)  # nh=58 for ICMPv6

        if self.options:
            packet = Ether() / IPv6(dst=self.dst_ip, src=self.src_ip, hlim=1) / IPv6ExtHdrHopByHop(options=self.options) / self
        else:
            packet = Ether() / IPv6(dst=self.dst_ip, src=self.src_ip, hlim=1) /  self

        sendp(packet, inter=int(interval), iface=iface, count=int(count))