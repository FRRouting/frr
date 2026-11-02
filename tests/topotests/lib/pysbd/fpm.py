# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
FPM server: zebra sends the multicast routes (installed as kernel MFC
entries) and, optionally, the unicast routes and EVPN neighbors (installed
in the kernel as they are).
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Callable, List, Optional

from .common import (
    FPM_DEFAULT_PORT,
    PIM_REG_IF_IDX,
    debug_fpm_dump,
    err,
    ntop,
    out,
    warn_ratelimited,
)
from .emulation import Emulator
from .interface import Interfaces
from .mroute import MfcParams, MulticastRouting
from .netlink import (
    NLA_F_NESTED,
    NLA_TYPE_MASK,
    NLM_F_MATCH,
    NLM_F_REQUEST,
    NLM_F_ROOT,
    NLMSG_HEADER,
    RTA_HEADER,
    RTM_DELNEIGH,
    RTM_DELROUTE,
    RTM_GETROUTE,
    RTM_NEWNEIGH,
    RTM_NEWROUTE,
    RTMSG,
    RTNEXTHOP,
    NetlinkMessage,
    nl_align,
    nl_dump,
    nlmsg_build,
    nlmsg_iter,
    rta_iter,
)
from .route import Route, RouteTable
from .stream import StreamEndpoint

FPM_HEADER = struct.Struct("!BBH")
FPM_PROTO_VERSION = 1
FPM_HT_NETLINK = 1

RTNL_FAMILY_IPMR = 128
RTNL_FAMILY_IP6MR = 129

RTA_DST = 1
RTA_SRC = 2
RTA_IIF = 3
RTA_MULTIPATH = 9
RTA_TABLE = 15
RTA_ENCAP_TYPE = 21
RTA_ENCAP = 22
RTA_MRT_EXTRA = 64

#: struct mrt_extra_attr: SPT threshold, notification interface index,
#: flags, register source and destination (host byte order integers).
MRT_EXTRA = struct.Struct("=iiI16s16s")

#: FRR's FPM only next hop encapsulation (zebra/rt_netlink.h).
FPM_NH_ENCAP_VXLAN = 100

#: Largest unicast route message installed with the attributes copy.
ROUTE_COPY_MAX = 16384


class FpmError(ValueError):
    """The stream can't be parsed any further."""


def fpm_route_attrs_copy(data: bytes) -> bytes:
    """
    Copy route attributes without FRR's FPM VXLAN encapsulation
    (RTA_ENCAP_TYPE 100 and its RTA_ENCAP): the kernel rejects it and does
    EVPN with the router MAC FDB entry and the next hop neighbor instead.
    Multipath next hops carry their own encapsulation attributes.
    """
    strip = False
    for rta_type, payload in rta_iter(data):
        if (
            rta_type == RTA_ENCAP_TYPE
            and len(payload) >= 2
            and struct.unpack_from("=H", payload)[0] == FPM_NH_ENCAP_VXLAN
        ):
            strip = True

    result = bytearray()
    for rta_type, payload in rta_iter(data):
        if strip and (
            rta_type == RTA_ENCAP_TYPE or (rta_type & NLA_TYPE_MASK) == RTA_ENCAP
        ):
            continue

        if rta_type != RTA_MULTIPATH:
            length = RTA_HEADER.size + len(payload)
            result += RTA_HEADER.pack(length, rta_type) + payload
            result += bytes(nl_align(length) - length)
            continue

        nexthops = bytearray()
        offset = 0
        while len(payload) - offset >= RTNEXTHOP.size:
            nh_len, nh_flags, nh_hops, nh_ifindex = RTNEXTHOP.unpack_from(
                payload, offset
            )
            if nh_len < RTNEXTHOP.size or nh_len > len(payload) - offset:
                break

            attributes = fpm_route_attrs_copy(
                payload[offset + RTNEXTHOP.size : offset + nh_len]
            )
            nh_dst_len = RTNEXTHOP.size + len(attributes)
            nexthops += RTNEXTHOP.pack(nh_dst_len, nh_flags, nh_hops, nh_ifindex)
            nexthops += attributes + bytes(nl_align(nh_dst_len) - nh_dst_len)

            if nl_align(nh_len) >= len(payload) - offset:
                break
            offset += nl_align(nh_len)

        length = RTA_HEADER.size + len(nexthops)
        result += RTA_HEADER.pack(length, rta_type) + nexthops
        result += bytes(nl_align(length) - length)

    return bytes(result)


def fpm_install_route_build(msg: NetlinkMessage) -> bytes:
    """Unicast route message to install in the kernel."""
    header_size = NLMSG_HEADER.size + RTMSG.size
    if msg.length < header_size or msg.length > ROUTE_COPY_MAX:
        return msg.data

    attributes = fpm_route_attrs_copy(msg.data[header_size : msg.length])
    header = bytearray(msg.data[:header_size])
    struct.pack_into("=I", header, 0, header_size + len(attributes))
    return bytes(header) + attributes


def parse_mroute(msg: NetlinkMessage, family: int) -> Route:
    """Decode a FPM multicast route (interface indexes, not VIFs)."""
    size = 4 if family == socket.AF_INET else 16
    route = Route(family, bytes(size), bytes(size))
    for rta_type, data in rta_iter(msg.payload, RTMSG.size):
        rta_type &= ~NLA_F_NESTED
        if rta_type == RTA_IIF and len(data) >= 4:
            (route.iif,) = struct.unpack_from("=i", data)
        elif rta_type == RTA_SRC and len(data) >= size:
            route.source = data[:size]
        elif rta_type == RTA_DST and len(data) >= size:
            route.group = data[:size]
        elif rta_type == RTA_MULTIPATH:
            offset = 0
            while len(data) - offset >= RTNEXTHOP.size:
                nh_len, _, _, ifindex = RTNEXTHOP.unpack_from(data, offset)
                route.oifs.append(ifindex)
                if nh_len < RTNEXTHOP.size:
                    break
                offset += nl_align(nh_len)
        elif rta_type == RTA_MRT_EXTRA:
            extra = data[: MRT_EXTRA.size].ljust(MRT_EXTRA.size, b"\0")
            (
                route.spt_threshold,
                route.notif,
                route.flags,
                local,
                remote,
            ) = MRT_EXTRA.unpack(extra)
            route.local = local[:size]
            route.remote = remote[:size]
    return route


class Fpm:
    """
    Turns the FPM multicast routes into kernel routes (`MulticastRouting`)
    and keeps them in `routes` for the emulation.

    Without emulation (`emulator` is `None`) `null_register` sends the
    registers, and the routes without input interface are installed with
    their notification interface so the kernel forwards the traffic.
    """

    def __init__(
        self,
        routes: RouteTable,
        routing: MulticastRouting,
        interfaces: Interfaces,
        netlink_enqueue: Callable[[bytes], None],
        null_register: Optional[Callable[[Route], None]],
        emulator: Optional[Emulator],
        install_unicast: bool = False,
    ) -> None:
        self.routes = routes
        self.routing = routing
        self.interfaces = interfaces
        self.netlink_enqueue = netlink_enqueue
        self.null_register = null_register
        self.emulator = emulator
        self.install_unicast = install_unicast
        self.endpoint = StreamEndpoint(
            "fpm", FPM_DEFAULT_PORT, self._serve, self._closed
        )

    async def start(self, address: str) -> None:
        await self.endpoint.start(address)

    def close(self) -> None:
        self.endpoint.close()

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while True:
            try:
                header = await reader.readexactly(FPM_HEADER.size)
            except asyncio.IncompleteReadError:
                err("fpm: connection closed")
                return

            version, frame_type, length = FPM_HEADER.unpack(header)
            if version != FPM_PROTO_VERSION or length < FPM_HEADER.size:
                err(
                    "fpm: invalid header (version {} length {}), closing".format(
                        version, length
                    )
                )
                return

            frame = await reader.readexactly(length - FPM_HEADER.size)
            if frame_type != FPM_HT_NETLINK:
                warn_ratelimited(
                    "fpm-type", "fpm: skip frame of type {}".format(frame_type)
                )
                continue

            try:
                self._handle_frame(frame)
            except FpmError as error:
                err("fpm: {}, closing".format(error))
                return

    def _closed(self) -> None:
        """Zebra is gone: remove the multicast routes it installed."""
        for route in self.routes:
            self.routes.pop(route.key)
            if route.installed:
                self._kernel_delete(route)
            if self.emulator is not None:
                self.emulator.route_removed(route)

    def _handle_frame(self, frame: bytes) -> None:
        if debug_fpm_dump():
            nl_dump(frame, True, "FPM")

        offset = 0
        while len(frame) - offset >= NLMSG_HEADER.size:
            (length,) = struct.unpack_from("=I", frame, offset)
            if length < NLMSG_HEADER.size:
                raise FpmError("invalid netlink message length {}".format(length))

            for msg in nlmsg_iter(frame[offset : offset + nl_align(length)]):
                self._handle_message(msg)
            offset += nl_align(length)

    def _handle_message(self, msg: NetlinkMessage) -> None:
        if msg.type in (RTM_NEWROUTE, RTM_DELROUTE):
            payload = msg.payload
            if len(payload) < RTMSG.size:
                return

            # Special multicast handling.
            family = payload[0]
            if family == RTNL_FAMILY_IPMR:
                self.mroute(msg.type == RTM_NEWROUTE, parse_mroute(msg, socket.AF_INET))
            elif family == RTNL_FAMILY_IP6MR:
                self.mroute(
                    msg.type == RTM_NEWROUTE, parse_mroute(msg, socket.AF_INET6)
                )
            elif self.install_unicast:
                self.netlink_enqueue(fpm_install_route_build(msg))
        elif msg.type in (RTM_NEWNEIGH, RTM_DELNEIGH):
            # EVPN entries (remote MACs and VXLAN flood list) come encoded
            # just like the kernel expects them.
            if self.install_unicast:
                self.netlink_enqueue(msg.data)

    #
    # Multicast routes.
    #
    def _to_mif(self, family: int, ifindex: int) -> int:
        if ifindex in (0, PIM_REG_IF_IDX):
            return 0
        if family == socket.AF_INET:
            return self.interfaces.ifi2vif(ifindex)
        return self.interfaces.ifi2mif(ifindex)

    def _mfc_params(self, route: Route, install: bool) -> MfcParams:
        params = MfcParams(route.family)
        params.install = install
        params.source = route.source
        params.group = route.group
        params.iif = self._to_mif(route.family, route.iif)
        params.oifs = [self._to_mif(route.family, oif) for oif in route.oifs]

        # Without emulation the kernel must forward the traffic it would
        # report (DATA_START) on the notification interface.
        if self.emulator is None and route.iif == 0 and route.notif:
            params.iif = self._to_mif(route.family, route.notif)
        return params

    def _kernel_delete(self, route: Route) -> None:
        self.routing.mfc(self._mfc_params(route, False))
        route.installed = False

    def kernel_remove(self, route: Route) -> None:
        """Remove the route from the kernel (zebra still has it)."""
        if route.installed:
            out(
                "\n  => remove sg({},{})".format(
                    ntop(route.family, route.source), ntop(route.family, route.group)
                )
            )
            self._kernel_delete(route)

    def mroute(self, install: bool, route: Route) -> None:
        previous = self.routes.get(*route.key)
        if install:
            operation = "update" if previous and previous.installed else "install"
        else:
            operation = "delete"

        out(
            "\n  => {} sg({},{}) iif:{} oifs:[{}] notifif:{} flags:{} "
            "local:{} remote:{}".format(
                operation,
                ntop(route.family, route.source),
                ntop(route.family, route.group),
                route.iif,
                ",".join(str(oif) for oif in route.oifs),
                route.notif,
                "|".join(route.flag_names()) or "0",
                ntop(route.family, route.local),
                ntop(route.family, route.remote),
            )
        )

        if not install:
            self.routes.pop(route.key)
            # Remove what we installed (the delete carries no interfaces).
            self.routing.mfc(self._mfc_params(previous or route, False))
            if self.emulator is not None:
                self.emulator.route_removed(previous or route)
            return

        params = self._mfc_params(route, True)
        params.previously_installed = previous is not None and previous.installed
        self.routing.mfc(params)
        route.installed = True
        self.routes.set(route)

        # Without emulation every update of a registering route sends an
        # (empty) register, which also restarts the RP keepalive timer.
        if self.emulator is not None:
            self.emulator.route_changed(route, previous)
        elif route.registers and self.null_register is not None:
            self.null_register(route)

    def sync(self) -> None:
        """Ask zebra to send all routes again."""
        writer = self.endpoint.writer
        if writer is None:
            out("fpm_sync: FPM is not connected")
            return

        message = nlmsg_build(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH,
            3,
            RTMSG.pack(socket.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0),
        )
        writer.write(
            FPM_HEADER.pack(
                FPM_PROTO_VERSION, FPM_HT_NETLINK, FPM_HEADER.size + len(message)
            )
            + message
        )

    def stdin(self, tokens: List[str]) -> None:
        if tokens and tokens[0] == "sync":
            self.sync()
            return

        if tokens:
            out("unknown command: fpm {}".format(tokens[0]))
        out("available commands:")
        out(" * fpm sync")
