#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Multicast Assertions/Modifiers for topotato tests
"""

import ipaddress
import socket
import struct

from typing import Any, Optional

from .base import skiptrace
from .assertions import TopotatoModifier


__all__ = [
    "MulticastReceiver",
]

# these definitions are sadly missing from socket.* as of python 3.10

SOL_IPV6: int = getattr(socket, "SOL_IPV6", 41)

MCAST_JOIN_GROUP: int = getattr(socket, "MCAST_JOIN_GROUP", 42)
MCAST_BLOCK_SOURCE: int = getattr(socket, "MCAST_BLOCK_SOURCE", 43)
MCAST_UNBLOCK_SOURCE: int = getattr(socket, "MCAST_UNBLOCK_SOURCE", 44)
MCAST_LEAVE_GROUP: int = getattr(socket, "MCAST_LEAVE_GROUP", 45)
MCAST_JOIN_SOURCE_GROUP: int = getattr(socket, "MCAST_JOIN_SOURCE_GROUP", 46)
MCAST_LEAVE_SOURCE_GROUP: int = getattr(socket, "MCAST_LEAVE_SOURCE_GROUP", 47)


class Sockaddr:
    def __init__(self, addr, ifindex=0, port=0):
        self._addr = addr
        self._ifindex = ifindex
        self._port = port

    def bytes(self):
        data = b""

        if self._addr.version == 4:
            data += struct.pack("@H", socket.AF_INET)
            data += struct.pack(">H", self._port)
            data += self._addr.packed
        elif self._addr.version == 6:
            data += struct.pack("@H", socket.AF_INET6)
            data += struct.pack(">HI", self._port, 0)
            data += self._addr.packed
            data += struct.pack("@I", self._ifindex)

        return data.ljust(128, b"\00")


class MulticastReceiver:
    """
    Join an IP (v4/v6) multicast group on a specified host and interface.
    """

    def __init__(self, rtr, iface):
        self._rtr = rtr
        self._iface = iface

        self._sock = None
        self._ifindex = None

    def _get_sock_ifindex(self, router, af):
        if not self._sock:
            with router:
                self._sock = socket.socket(af, socket.SOCK_DGRAM, 0)
                self._ifindex = socket.if_nametoindex(self._iface.ifname)

        return self._sock, self._ifindex

    class Action(TopotatoModifier):
        _rtr: str
        _cmdobj: "MulticastReceiver"
        _group: Any
        _source: Any

        group_opt: Optional[int] = None
        source_opt: Optional[int] = None

        # pylint: disable=arguments-differ,protected-access,too-many-arguments
        @classmethod
        def from_parent(cls, parent, name, cmdobj, group, source=None):
            _group = ipaddress.ip_address(group)
            _source = source and ipaddress.ip_address(source)
            assert _source is None or _source.version == _group.version

            name = "%s:%s/%s/multicast-%s(%s,%s)" % (
                name,
                cmdobj._rtr.name,
                cmdobj._iface.ifname,
                cls.__name__.lower(),
                _source or "*",
                _group,
            )
            self = super().from_parent(parent, name=name)
            self._cmdobj = cmdobj
            self._rtr = cmdobj._rtr
            self._group = _group
            self._source = _source
            return self

        def __call__(self):
            router = self.instance.routers[self._rtr.name]

            if self._group.version == 4:
                af = socket.AF_INET
                sol = socket.SOL_IP
            elif self._group.version == 6:
                af = socket.AF_INET6
                sol = SOL_IPV6
            else:
                raise ValueError("unknown address family in %r" % self._group)

            sock, ifindex = self._cmdobj._get_sock_ifindex(router, af)

            # 64-bit architectures have padding between ifindex and sockaddr
            arg = struct.pack("@I", ifindex).ljust(struct.calcsize("@L"), b"\0")
            arg += Sockaddr(self._group).bytes()
            if self._source is None:
                sock.setsockopt(sol, self.group_opt, arg)
            else:
                arg += Sockaddr(self._source).bytes()
                sock.setsockopt(sol, self.source_opt, arg)

    class Join(Action):
        group_opt = MCAST_JOIN_GROUP
        source_opt = MCAST_JOIN_SOURCE_GROUP

    class Leave(Action):
        group_opt = MCAST_LEAVE_GROUP
        source_opt = MCAST_LEAVE_SOURCE_GROUP

    class Block(Action):
        source_opt = MCAST_BLOCK_SOURCE

    class Unblock(Action):
        source_opt = MCAST_UNBLOCK_SOURCE

    @skiptrace
    def join(self, group, source=None):
        yield from self.Join.make(self, group, source)

    @skiptrace
    def leave(self, group, source=None):
        yield from self.Leave.make(self, group, source)

    @skiptrace
    def block(self, group, source):
        yield from self.Block.make(self, group, source)

    @skiptrace
    def unblock(self, group, source):
        yield from self.Unblock.make(self, group, source)
