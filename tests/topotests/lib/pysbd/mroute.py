# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""Linux multicast routing API (IPv4 VIFs/MFCs and IPv6 MIFs/MFCs)."""

from __future__ import annotations

import errno
import socket
import struct
from typing import Callable, List, NamedTuple, Optional, Sequence

from .common import (
    IN6_ALL_DR_ROUTERS,
    IN6_ALL_SPF_ROUTERS,
    IPV4_NONE,
    IPV6_ADD_MEMBERSHIP,
    Buffer,
    debug_netlink,
    ntop,
    out,
    pton,
    warn,
    zero_address,
)

MRT_INIT = 200
MRT_ADD_VIF = 202
MRT_DEL_VIF = 203
MRT_ADD_MFC = 204
MRT_DEL_MFC = 205
MAXVIFS = 32
VIFF_USE_IFINDEX = 0x8

IGMPMSG_NOCACHE = 1
IGMPMSG_WRONGVIF = 2
IGMPMSG_WHOLEPKT = 3

MRT6_INIT = 200
MRT6_ADD_MIF = 202
MRT6_DEL_MIF = 203
MRT6_ADD_MFC = 204
MRT6_DEL_MFC = 205
MAXMIFS = 32

MRT6MSG_NOCACHE = 1
MRT6MSG_WRONGMIF = 2
MRT6MSG_WHOLEPKT = 3

#: struct vifctl
VIFCTL = struct.Struct("=HBBIi4s")
#: struct mfcctl
MFCCTL = struct.Struct("=4s4sH32s2xIIIi")
#: struct ip_mreqn
IP_MREQN = struct.Struct("=4s4si")
#: struct igmpmsg
IGMPMSG = struct.Struct("=IIBBBB4s4s")
#: struct mif6ctl
MIF6CTL = struct.Struct("=HBBH2xI")
#: struct mf6cctl (the `sockaddr_in6` only carry the address)
MF6CCTL = struct.Struct("=8x16s4x8x16s4xH2x32s")
#: struct ipv6_mreq
IPV6_MREQ = struct.Struct("=16sI")
#: struct mrt6msg
MRT6MSG = struct.Struct("=BBHI16s16s")

#: All systems, all routers, PIM routers and IGMPv3 routers.
IGMP_GROUPS = [bytes([224, 0, 0, last]) for last in (1, 2, 13, 22)]
OSPF_GROUPS = [bytes([224, 0, 0, 5]), bytes([224, 0, 0, 6])]
RIP_GROUPS = [bytes([224, 0, 0, 9])]
MLD_GROUPS = [
    pton(socket.AF_INET6, address) or b""
    for address in ("ff02::1", "ff02::2", "ff02::16", "ff02::d")
] + [IN6_ALL_SPF_ROUTERS, IN6_ALL_DR_ROUTERS]

#: Kernel upcall kinds (`KernelEvent.kind`).
KERNEL_NOCACHE = "nocache"
KERNEL_WRONGIF = "wrongif"


class KernelEvent(NamedTuple):
    """A kernel multicast upcall (cache miss or wrong interface)."""

    family: int
    kind: str
    #: VIF (IPv4) or MIF (IPv6) the packet arrived on.
    mif: int
    source: bytes
    group: bytes


def parse_igmpmsg(data: Buffer) -> Optional[KernelEvent]:
    """Decode a kernel IPv4 upcall (`struct igmpmsg`)."""
    if len(data) < IGMPMSG.size:
        return None

    # Only the low VIF byte: older kernels don't set `im_vif_hi`.
    _, _, msgtype, _, vif, _, source, group = IGMPMSG.unpack_from(data)
    kinds = {IGMPMSG_NOCACHE: KERNEL_NOCACHE, IGMPMSG_WRONGVIF: KERNEL_WRONGIF}
    if msgtype not in kinds:
        return None
    return KernelEvent(socket.AF_INET, kinds[msgtype], vif, source, group)


def parse_mrt6msg(data: Buffer) -> Optional[KernelEvent]:
    """Decode a kernel IPv6 upcall (`struct mrt6msg`)."""
    if len(data) < MRT6MSG.size:
        return None

    _, msgtype, mif, _, source, group = MRT6MSG.unpack_from(data)
    kinds = {MRT6MSG_NOCACHE: KERNEL_NOCACHE, MRT6MSG_WRONGMIF: KERNEL_WRONGIF}
    if msgtype not in kinds:
        return None
    return KernelEvent(socket.AF_INET6, kinds[msgtype], mif, source, group)


class MfcParams:
    """Multicast route to install or remove, with VIF/MIF numbers."""

    def __init__(self, family: int = socket.AF_INET) -> None:
        self.family = family
        self.install = False
        self.previously_installed = False
        #: Input VIF/MIF.
        self.iif = 0
        #: Output VIFs/MIFs.
        self.oifs: List[int] = []
        self.source = zero_address(family)
        self.group = zero_address(family)


class MulticastRouting:
    """
    Kernel multicast routing: the IPv4 one lives in the IGMP socket, the
    IPv6 one in the MLD socket.

    `rp_vif`/`rp_mif` return the VIF/MIF of the RP interface, which receives
    the traffic registers carry.
    """

    def __init__(
        self,
        sock4: socket.socket,
        sock6: socket.socket,
        rp_vif: Callable[[], int],
        rp_mif: Callable[[], int],
    ) -> None:
        self.sock4 = sock4
        self.sock6 = sock6
        self.rp_vif = rp_vif
        self.rp_mif = rp_mif
        # Number zero is never used: it is the register VIF/MIF.
        self.vif_used = [False] * MAXVIFS
        self.mif_used = [False] * MAXMIFS

    @staticmethod
    def init_sockets(sock4: socket.socket, sock6: socket.socket) -> None:
        sock4.setsockopt(socket.IPPROTO_IP, MRT_INIT, 1)
        sock6.setsockopt(socket.IPPROTO_IPV6, MRT6_INIT, 1)

    @staticmethod
    def _allocate(used: List[bool]) -> int:
        for number in range(1, len(used)):
            if not used[number]:
                used[number] = True
                return number
        return 0

    #
    # Interfaces.
    #
    def vif_add(self, index: int, address: bytes) -> int:
        """Enable IPv4 multicast on the interface: returns its VIF (0 if none)."""
        vif = self._allocate(self.vif_used)
        if vif == 0:
            warn("no free VIF for interface {}".format(index))
            return 0

        vifctl = VIFCTL.pack(vif, VIFF_USE_IFINDEX, 0, 0, index, IPV4_NONE)
        try:
            self.sock4.setsockopt(socket.IPPROTO_IP, MRT_ADD_VIF, vifctl)
        except OSError as error:
            if debug_netlink():
                warn("vif_add: setsockopt(MRT_ADD_VIF)", error)

        join_groups(self.sock4, index, address, IGMP_GROUPS)
        return vif

    def vif_del(self, index: int, vif: int) -> None:
        if vif <= 0 or vif >= MAXVIFS:
            return
        self.vif_used[vif] = False

        # The kernel already removed it when the interface went away.
        vifctl = VIFCTL.pack(vif, VIFF_USE_IFINDEX, 0, 0, index, IPV4_NONE)
        try:
            self.sock4.setsockopt(socket.IPPROTO_IP, MRT_DEL_VIF, vifctl)
        except OSError as error:
            if error.errno != errno.EADDRNOTAVAIL and debug_netlink():
                warn("vif_del: setsockopt(MRT_DEL_VIF)", error)

    def mif_add(self, index: int) -> int:
        """Enable IPv6 multicast on the interface: returns its MIF (0 if none)."""
        mif = self._allocate(self.mif_used)
        if mif == 0:
            warn("no free MIF for interface {}".format(index))
            return 0

        try:
            self.sock6.setsockopt(
                socket.IPPROTO_IPV6, MRT6_ADD_MIF, MIF6CTL.pack(mif, 0, 0, index, 0)
            )
        except OSError as error:
            if debug_netlink():
                warn(
                    "mif_add: setsockopt(MRT6_ADD_MIF): mifi {} pifi {}".format(
                        mif, index
                    ),
                    error,
                )

        for group in MLD_GROUPS:
            try:
                self.sock6.setsockopt(
                    socket.IPPROTO_IPV6,
                    IPV6_ADD_MEMBERSHIP,
                    IPV6_MREQ.pack(group, index),
                )
            except OSError as error:
                if debug_netlink():
                    warn("mif_add: setsockopt(IPV6_ADD_MEMBERSHIP)", error)

        return mif

    def mif_del(self, index: int, mif: int) -> None:
        if mif <= 0 or mif >= MAXMIFS:
            return
        self.mif_used[mif] = False

        try:
            self.sock6.setsockopt(
                socket.IPPROTO_IPV6, MRT6_DEL_MIF, MIF6CTL.pack(mif, 0, 0, index, 0)
            )
        except OSError as error:
            if error.errno != errno.EADDRNOTAVAIL and debug_netlink():
                warn("mif_del: setsockopt(MRT6_DEL_MIF)", error)

    #
    # Routes.
    #
    def mfc(self, params: MfcParams) -> None:
        if params.family == socket.AF_INET:
            self._mfc4(params)
        else:
            self._mfc6(params)

    def _mfc4(self, params: MfcParams) -> None:
        opt = MRT_ADD_MFC if params.install else MRT_DEL_MFC
        parent = params.iif & 0xFFFF
        ttls = bytearray(MAXVIFS)
        for oif in params.oifs:
            if 0 <= oif < MAXVIFS:
                ttls[oif] = 1

        # Linux quirks: a SG(*,G) only matches the packets of the interfaces
        # in its output list, so add the input interface to it.
        #
        # On SG(S,G) we must first install input as `pimreg` and then as the
        # input interface so we have the traffic flowing.
        if params.install:
            if params.source == IPV4_NONE:
                if 0 <= params.iif < MAXVIFS:
                    ttls[params.iif] = 1
            elif not params.previously_installed:
                self._mfc4_set(opt, params.source, params.group, 0, ttls)

        # Registers arrive on the RP interface (the data plane decapsulates
        # them there).
        if params.source != IPV4_NONE and parent == 0:
            parent = self.rp_vif() & 0xFFFF

        self._mfc4_set(opt, params.source, params.group, parent, ttls)

    def _mfc4_set(
        self, opt: int, origin: bytes, group: bytes, parent: int, ttls: bytearray
    ) -> None:
        out(
            "    => mfcctl SG({},{}) parent:{} ttls:[{}]".format(
                ntop(socket.AF_INET, origin),
                ntop(socket.AF_INET, group),
                parent,
                ",".join(str(vif) for vif in range(MAXVIFS) if ttls[vif]),
            )
        )
        mfcctl = MFCCTL.pack(origin, group, parent, bytes(ttls), 0, 0, 0, 0)
        try:
            self.sock4.setsockopt(socket.IPPROTO_IP, opt, mfcctl)
        except OSError as error:
            if opt == MRT_ADD_MFC or error.errno != errno.ENOENT:
                warn("mfc: setsockopt({})".format(_opt_name(opt)), error)

    def _mfc6(self, params: MfcParams) -> None:
        opt = MRT6_ADD_MFC if params.install else MRT6_DEL_MFC
        parent = params.iif & 0xFFFF
        ifset = [0] * 8
        for oif in params.oifs:
            _if_set(ifset, oif)

        # Linux quirks (see `_mfc4`).
        source_is_set = params.source != zero_address(socket.AF_INET6)
        if params.install:
            if not source_is_set:
                _if_set(ifset, params.iif)
            elif not params.previously_installed:
                self._mfc6_set(opt, params.source, params.group, 0, ifset)

        if source_is_set and parent == 0:
            parent = self.rp_mif() & 0xFFFF

        self._mfc6_set(opt, params.source, params.group, parent, ifset)

    def _mfc6_set(
        self, opt: int, origin: bytes, group: bytes, parent: int, ifset: List[int]
    ) -> None:
        mifs = [
            str(mif) for mif in range(MAXMIFS) if ifset[mif // 32] & (1 << (mif % 32))
        ]
        out(
            "    => mf6cctl SG({},{}) parent:{} ifset:[{}]".format(
                ntop(socket.AF_INET6, origin),
                ntop(socket.AF_INET6, group),
                parent,
                ",".join(mifs),
            )
        )
        mf6cctl = MF6CCTL.pack(origin, group, parent, struct.pack("=8I", *ifset))
        try:
            self.sock6.setsockopt(socket.IPPROTO_IPV6, opt, mf6cctl)
        except OSError as error:
            if opt == MRT6_ADD_MFC or error.errno != errno.ENOENT:
                warn("mfc: setsockopt({})".format(_opt_name(opt, True)), error)


def _opt_name(opt: int, ipv6: bool = False) -> str:
    if ipv6:
        return "MRT6_ADD_MFC" if opt == MRT6_ADD_MFC else "MRT6_DEL_MFC"
    return "MRT_ADD_MFC" if opt == MRT_ADD_MFC else "MRT_DEL_MFC"


def _if_set(ifset: List[int], mif: int) -> None:
    if 0 <= mif < 256:
        ifset[mif // 32] |= 1 << (mif % 32)


def join_groups(
    sock: socket.socket, index: int, address: bytes, groups: Sequence[bytes]
) -> None:
    """Join IPv4 multicast groups on the interface `index`."""
    for group in groups:
        try:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                IP_MREQN.pack(group, address, index),
            )
        except OSError as error:
            if error.errno != errno.EADDRINUSE and debug_netlink():
                warn("setsockopt(IP_ADD_MEMBERSHIP)", error)
