# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""RIP: UDP packets from the network are encapsulated in UDP to FRR."""

from __future__ import annotations

import asyncio
import socket

from .common import debug_packets, out
from .dataplane import DataPlane, ipv4_pktinfo_ifindex, raw4_socket, recvmsg_packet
from .interface import Interface
from .mroute import RIP_GROUPS, join_groups
from .wire import ipv4_print


class Rip:
    def __init__(self, dataplane: DataPlane, loop: asyncio.AbstractEventLoop) -> None:
        self.dataplane = dataplane
        self.loop = loop
        self.sock = raw4_socket(socket.IPPROTO_UDP)

    def start(self) -> None:
        self.loop.add_reader(self.sock, self._read)

    def interface_enabled(self, interface: Interface) -> None:
        join_groups(self.sock, interface.index, interface.addresses[0], RIP_GROUPS)

    def _read(self) -> None:
        result = recvmsg_packet(self.sock, "rip_read_cb")
        if result is None:
            return
        data, ancdata, _ = result
        ifindex = ipv4_pktinfo_ifindex(ancdata)

        # Loopback traffic is FRR's own (or the encapsulation).
        if ifindex in (0, 1):
            return

        if debug_packets():
            out("<= {} bytes from interface {}".format(len(data), ifindex))
            out("[IPv4]")
            ipv4_print("  ", data)

        self.dataplane.ipv4_packet_send(
            self.sock,
            socket.IPPROTO_UDP,
            ifindex,
            data,
            udp_source=520,
            udp_destination=5200,
        )
        if debug_packets():
            out()
