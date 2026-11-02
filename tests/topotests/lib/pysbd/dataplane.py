# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Data plane simulation sockets: packets received from the network are
encapsulated and delivered to FRR, packets FRR encapsulates are sent to the
network.
"""

from __future__ import annotations

import asyncio
import errno
import socket
import struct
from typing import Callable, List, Optional, Tuple

from . import packet
from .common import (
    ETH_P_ALL,
    ETH_P_IP,
    ETH_P_IPV6,
    ICMP6_FILTER,
    IN6_ALL_DR_ROUTERS,
    IN6_ALL_SPF_ROUTERS,
    IP_ENCAP_ROUTING,
    IP_MULTICAST_ALL,
    IP_PKTINFO,
    IPPROTO_OSPF,
    IPPROTO_PIM,
    IPV4_ENCAP_DATA_SIZE,
    IPV4_ENCAP_DST,
    IPV4_LOOPBACK,
    IPV6_CHECKSUM,
    IPV6_HOPOPTS,
    IPV6_LOOPBACK,
    IPV6_PKTINFO,
    IPV6_RECVHOPOPTS,
    IPV6_RECVPKTINFO,
    IPV6_TCLASS,
    OSPF_IP_ENCAP_DR,
    OSPF_IP_ENCAP_SPF,
    PACKET_OUTGOING,
    PIM_IP_ENCAP_IGMP,
    PIM_IP_ENCAP_PIM,
    PIM_IPV6_ENCAP_MLD,
    Buffer,
    debug_packets,
    debug_packets_dump,
    err,
    fatal,
    if_indextoname,
    ntop4,
    ntop6,
    out,
    warn_ratelimited,
    zero_address,
)
from .interface import Interface
from .mroute import KernelEvent, MulticastRouting, parse_igmpmsg, parse_mrt6msg
from .wire import (
    ICMP6_MLD_QUERY,
    ICMP6_MLD_V1_DONE,
    ICMP6_MLD_V1_REPORT,
    ICMP6_MLD_V2_REPORT,
    IPV6_HEADER_SIZE,
    PIM_HEADER_SIZE,
    igmp_is_mtrace,
    ipv4_header_length,
    ipv4_print,
    ipv6_print,
    mld_print,
    pim_print,
)

READ_BUFFER_SIZE = 65535
ANCILLARY_SIZE = socket.CMSG_SPACE(20) + socket.CMSG_SPACE(256)
MTU = 1500

Ancillary = List[Tuple[int, int, bytes]]


#
# Sockets.
#
def raw4_socket(protocol: int, header_included: bool = True) -> socket.socket:
    """IPv4 raw socket for `protocol`."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 1)
        if header_included:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    except OSError as error:
        fatal("raw socket for protocol {}".format(protocol), error)

    return sock


def icmp6_filter_mld() -> bytes:
    """`struct icmp6_filter` blocking everything but MLD."""
    words = [0xFFFFFFFF] * 8
    for icmp6_type in (
        ICMP6_MLD_QUERY,
        ICMP6_MLD_V1_REPORT,
        ICMP6_MLD_V1_DONE,
        ICMP6_MLD_V2_REPORT,
    ):
        words[icmp6_type >> 5] &= ~(1 << (icmp6_type & 31)) & 0xFFFFFFFF
    return struct.pack("=8I", *words)


def raw6_socket(protocol: int) -> socket.socket:
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, protocol)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
        if protocol == socket.IPPROTO_ICMPV6:
            sock.setsockopt(socket.IPPROTO_ICMPV6, ICMP6_FILTER, icmp6_filter_mld())
        if protocol in (socket.IPPROTO_ICMPV6, IPPROTO_PIM):
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_TCLASS, 0xC0)
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVHOPOPTS, 1)
        if protocol == IPPROTO_PIM:
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_CHECKSUM, 2)
    except OSError as error:
        fatal("IPv6 raw socket for protocol {}".format(protocol), error)

    return sock


def capture_socket(name: Optional[str]) -> Optional[socket.socket]:
    """Packet socket capturing everything on the interface `name`."""
    if name is None:
        return None

    try:
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IPV6)
        )
    except OSError:
        return None

    try:
        sock.bind((name, ETH_P_ALL))
        sock.setblocking(False)
    except OSError:
        sock.close()
        return None

    return sock


#
# Helpers.
#
def recvmsg_packet(
    sock: socket.socket, caller: str
) -> Optional[Tuple[bytes, Ancillary, object]]:
    try:
        data, ancdata, flags, address = sock.recvmsg(READ_BUFFER_SIZE, ANCILLARY_SIZE)
    except (BlockingIOError, InterruptedError):
        return None
    except OSError as error:
        warn_ratelimited(caller, "{}: recvmsg".format(caller), error)
        return None

    if not data:
        return None
    if flags & socket.MSG_TRUNC:
        err("{}: message truncated".format(caller))
    if flags & socket.MSG_CTRUNC:
        err("{}: control data truncated".format(caller))

    return data, ancdata, address


def ipv4_pktinfo_ifindex(ancdata: Ancillary) -> int:
    ifindex = 0
    for level, cmsg_type, cmsg_data in ancdata:
        # Expecting only `IPPROTO_IP` + `IP_PKTINFO` messages.
        if (
            level == socket.IPPROTO_IP
            and cmsg_type == IP_PKTINFO
            and len(cmsg_data) >= 4
        ):
            (ifindex,) = struct.unpack_from("=i", cmsg_data)
    return ifindex


def ipv6_ancillary(ancdata: Ancillary) -> Tuple[bytes, int, bytes]:
    """Returns the destination address, interface index and hop options."""
    destination = bytes(16)
    ifindex = 0
    hopopts = b""
    for level, cmsg_type, cmsg_data in ancdata:
        if level != socket.IPPROTO_IPV6:
            continue

        if cmsg_type == IPV6_PKTINFO and len(cmsg_data) >= 20:
            destination, ifindex = struct.unpack_from("=16sI", cmsg_data)
        elif cmsg_type == IPV6_HOPOPTS:
            hopopts = bytes(cmsg_data)
    return destination, ifindex, hopopts


def ipv6_source(address: object) -> bytes:
    assert isinstance(address, tuple)
    host = address[0].split("%", 1)[0]
    return socket.inet_pton(socket.AF_INET6, host)


class DataPlane:
    """
    The data plane sockets. Kernel upcalls go to `kernel_event`, the
    traffic each interface receives to `observe` (emulation) and the
    registers the RP receives to `register_received`.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.kernel_event: Optional[Callable[[KernelEvent], None]] = None
        self.observe: Optional[Callable[[int, bytes, int], None]] = None
        self.register_received: Optional[Callable[[int, bytes], None]] = None

        self.igmp_sock = raw4_socket(socket.IPPROTO_IGMP)
        self.mld_sock = raw6_socket(socket.IPPROTO_ICMPV6)
        try:
            MulticastRouting.init_sockets(self.igmp_sock, self.mld_sock)
        except OSError as error:
            fatal("multicast routing initialization", error)

        self.pim_sock = raw4_socket(IPPROTO_PIM)
        self.ospf_sock = raw4_socket(IPPROTO_OSPF)
        # Registers with data: the kernel builds (and fragments) the header.
        self.register_sock = raw4_socket(IPPROTO_PIM, header_included=False)
        self.encap_socks = [
            raw4_socket(protocol)
            for protocol in (
                PIM_IP_ENCAP_IGMP,
                PIM_IP_ENCAP_PIM,
                OSPF_IP_ENCAP_DR,
                OSPF_IP_ENCAP_SPF,
                IP_ENCAP_ROUTING,
            )
        ]
        self.loopback_sock = capture_socket(if_indextoname(1))
        self.ospf6_sock = raw6_socket(IPPROTO_OSPF)
        self.pim6_sock = raw6_socket(IPPROTO_PIM)

    def start(self) -> None:
        for sock in (self.igmp_sock, self.pim_sock, self.ospf_sock):
            self.loop.add_reader(sock, self.packet_read_cb, sock)
        for sock in self.encap_socks:
            self.loop.add_reader(sock, self.encap_packet_read_cb, sock)
        self.loop.add_reader(self.mld_sock, self.mld_packet_read_cb)
        if self.loopback_sock is not None:
            self.loop.add_reader(self.loopback_sock, self.loopback_packet_read_cb)
        self.loop.add_reader(self.ospf6_sock, self.ospf6_packet_read_cb)
        self.loop.add_reader(self.pim6_sock, self.pim6_packet_read_cb)
        # The register socket only sends: drop what it receives.
        self.loop.add_reader(self.register_sock, self._discard, self.register_sock)

    @staticmethod
    def _discard(sock: socket.socket) -> None:
        try:
            sock.recv(READ_BUFFER_SIZE)
        except OSError:
            pass

    #
    # Interfaces.
    #
    def interface_added(self, interface: Interface) -> None:
        # The loopback traffic is FRR's (see `loopback_packet_read_cb`).
        if interface.index == 1:
            return
        interface.capture = capture_socket(interface.name)
        if interface.capture is not None:
            self.loop.add_reader(interface.capture, self.capture_read_cb, interface)

    def interface_removed(self, interface: Interface) -> None:
        if interface.capture is not None:
            self.loop.remove_reader(interface.capture)
            interface.capture.close()
            interface.capture = None

    #
    # Sending.
    #
    def ipv4_packet_send(
        self,
        sock: socket.socket,
        protocol: int,
        ifindex: int,
        data: Buffer,
        udp_source: int = 0,
        udp_destination: int = 0,
    ) -> None:
        """Encapsulate a packet from the network and send it to FRR (loopback)."""
        if debug_packets():
            out("  <Write {} bytes>".format(len(data)))

        for encapsulated, offset, size in packet.ipv4_packet_build(
            protocol, ifindex, MTU, data, udp_source, udp_destination
        ):
            try:
                bytes_sent = sock.sendto(encapsulated, (ntop4(IPV4_LOOPBACK), 0))
            except OSError as error:
                warn_ratelimited("ipv4_packet_send", "ipv4_packet_send: sendto", error)
                return

            if debug_packets():
                out("    <Written {} bytes>".format(bytes_sent))
                out("      IP [offset {} payload_size {}]".format(offset, size))

    def ipv4_encap_packet_send(
        self, sock: socket.socket, ifindex: int, data: Buffer
    ) -> None:
        """Send a packet FRR encapsulated out of the interface `ifindex`."""
        destination = bytes(data[16:20])
        pktinfo = struct.pack("=I4s4s", ifindex & 0xFFFF, bytes(4), bytes(4))

        if debug_packets():
            out(
                "  <Write {} bytes to interface {} (dst {})>".format(
                    len(data), ifindex, ntop4(destination)
                )
            )

        try:
            bytes_sent = sock.sendmsg(
                [bytes(data)],
                [(socket.IPPROTO_IP, IP_PKTINFO, pktinfo)],
                0,
                (ntop4(destination), 0),
            )
        except OSError as error:
            warn_ratelimited(
                "ipv4_encap_packet_send-{}".format(error.errno),
                "ipv4_encap_packet_send: sendmsg to interface {}".format(ifindex),
                error,
            )
            return

        if debug_packets():
            out("    <Written {} bytes>".format(bytes_sent))

    def packet_send_loop(
        self,
        protocol: int,
        ifindex: int,
        source: bytes,
        destination: bytes,
        data: Buffer,
        router_alert: bool = False,
    ) -> None:
        """Send an encapsulated IPv6 packet to FRR through the loopback."""
        self.loopback_send(
            ETH_P_IPV6,
            packet.prepend_ipv6_header(
                protocol, ifindex, source, destination, data, router_alert=router_alert
            ),
        )

    def loopback_send(self, protocol: int, data: bytes) -> None:
        """Deliver a packet on the loopback, as if received there."""
        if self.loopback_sock is None:
            warn_ratelimited("loopback", "no loopback socket")
            return

        # Python doesn't zero `sll_addr` when no hardware address is given,
        # but the kernel uses it as the destination: a random one makes the
        # loopback drop the packet (not for this host).
        try:
            self.loopback_sock.sendto(
                data, (if_indextoname(1) or "lo", protocol, 0, 0, bytes(6))
            )
        except OSError as error:
            warn_ratelimited("loopback_send", "loopback_send: sendto", error)

    def ipv6_packet_send(
        self,
        interface: Interface,
        data: Buffer,
        proto: int,
        l2_address: bytes,
        traffic_class: int = 0,
    ) -> None:
        """Send a packet FRR encapsulated out of its data plane interface."""
        if interface.capture is None:
            return

        regenerated = packet.regenerate_ipv6_header(data, proto, traffic_class)
        try:
            interface.capture.sendto(
                regenerated, (interface.name, ETH_P_IPV6, 0, 0, bytes(l2_address))
            )
        except OSError as error:
            warn_ratelimited(
                "ipv6_packet_send-" + interface.name, "ipv6_packet_send: sendto", error
            )

    def pim_send_register(
        self, source: bytes, neighbor: bytes, mcast_source: bytes, mcast_group: bytes
    ) -> None:
        """Empty register (without emulation)."""
        data = packet.pim_register_build(source, neighbor, mcast_source, mcast_group)
        try:
            self.pim_sock.sendto(data, (ntop4(neighbor), 0))
        except OSError as error:
            warn_ratelimited("pim_send_register", "pim_send_register: sendto", error)

    def pim6_send_register(
        self, neighbor: bytes, mcast_source: bytes, mcast_group: bytes
    ) -> None:
        """Empty register (without emulation)."""
        data = packet.pim6_register_build(mcast_source, mcast_group)
        try:
            self.pim6_sock.sendto(data, (ntop6(neighbor), 0, 0, 0))
        except OSError as error:
            warn_ratelimited("pim6_send_register", "pim6_send_register: sendto", error)

    def register_send(self, family: int, source: bytes, rp: bytes, data: bytes) -> None:
        """Send the packet `data` in a register from `source` to the RP."""
        message = packet.pim_register_data_build(data)
        ancillary = []
        try:
            if family == socket.AF_INET:
                if source != zero_address(family):
                    pktinfo = struct.pack("=I4s4s", 0, source, bytes(4))
                    ancillary = [(socket.IPPROTO_IP, IP_PKTINFO, pktinfo)]
                self.register_sock.sendmsg([message], ancillary, 0, (ntop4(rp), 0))
            else:
                if source != zero_address(family):
                    pktinfo = struct.pack("=16sI", source, 0)
                    ancillary = [(socket.IPPROTO_IPV6, IPV6_PKTINFO, pktinfo)]
                self.pim6_sock.sendmsg([message], ancillary, 0, (ntop6(rp), 0, 0, 0))
        except OSError as error:
            warn_ratelimited("register_send", "register_send: sendmsg", error)

    def decapsulate(self, family: int, data: bytes) -> None:
        """Forward the traffic a register carried (from the RP interface)."""
        self.loopback_send(ETH_P_IP if family == socket.AF_INET else ETH_P_IPV6, data)

    #
    # IPv4.
    #
    def packet_read_cb(self, sock: socket.socket) -> None:
        """IGMP, PIM and OSPF packets from the network to FRR."""
        result = recvmsg_packet(sock, "packet_read_cb")
        if result is None:
            return
        data, ancdata, _ = result
        ifindex = ipv4_pktinfo_ifindex(ancdata)

        # Kernel upcalls (they look like IP packets of protocol zero).
        if sock is self.igmp_sock and len(data) > 9 and data[9] == 0:
            event = parse_igmpmsg(data)
            if event is not None and self.kernel_event is not None:
                self.kernel_event(event)
            return

        # Registers the RP receives carry traffic to forward.
        if (
            sock is self.pim_sock
            and self.register_received is not None
            and len(data) >= 20
        ):
            inner = packet.pim_register_decode(data[ipv4_header_length(data) :])
            if inner is not None:
                self.register_received(socket.AF_INET, inner)

        # Loopback traffic is FRR's own (or the encapsulation).
        if ifindex in (0, 1):
            return

        # mtrace doesn't go through the data plane: the operating system
        # delivers it to pimd (see doc/user/pim.rst).
        if sock is self.igmp_sock and igmp_is_mtrace(data):
            return

        if debug_packets():
            out("<= {} bytes from interface {}".format(len(data), ifindex))

        if sock is self.igmp_sock:
            protocol = PIM_IP_ENCAP_IGMP
        elif sock is self.pim_sock:
            protocol = PIM_IP_ENCAP_PIM
        else:
            protocol = OSPF_IP_ENCAP_DR

        if debug_packets_dump():
            out("[IPv4]")
            ipv4_print("  ", data)

        self.ipv4_packet_send(sock, protocol, ifindex, data)
        if debug_packets():
            out()

    def encap_packet_read_cb(self, sock: socket.socket) -> None:
        """Packets FRR encapsulated to the data plane, sent to the network."""
        result = recvmsg_packet(sock, "encap_packet_read_cb")
        if result is None:
            return
        data, ancdata, _ = result

        # Only FRR (on the loopback) talks to the data plane, and the packets
        # we deliver to FRR come from the encapsulation address.
        if ipv4_pktinfo_ifindex(ancdata) != 1 or len(data) < IPV4_ENCAP_DATA_SIZE:
            return
        if data[12:16] == IPV4_ENCAP_DST:
            return

        decoded = packet.ipv4_encap_decode(data)
        if decoded is None:
            if debug_packets():
                out("encap_packet_read_cb: invalid encapsulation, dropped")
            return
        _, ifindex, inner = decoded

        if debug_packets():
            out("<= {} bytes encapsulated to interface {}".format(len(data), ifindex))
        if debug_packets_dump():
            out("[eIPv4]")
            ipv4_print("  ", data)
            out("    [IPv4]")
            ipv4_print("    ", inner)

        self.ipv4_encap_packet_send(sock, ifindex, inner)
        if debug_packets():
            out()

    #
    # IPv6.
    #
    def mld_packet_read_cb(self) -> None:
        """MLD packets (and kernel upcalls) from the network to FRR."""
        result = recvmsg_packet(self.mld_sock, "mld_packet_read_cb")
        if result is None:
            return
        data, ancdata, address = result

        # Kernel upcalls (`struct mrt6msg` starts with a zero byte).
        if data[0] == 0:
            event = parse_mrt6msg(data)
            if event is not None and self.kernel_event is not None:
                self.kernel_event(event)
            return

        destination, ifindex, hopopts = ipv6_ancillary(ancdata)
        if ifindex == 1:
            return

        source = ipv6_source(address)
        has_router_alert = packet.hop_options_has_router_alert(hopopts)
        if debug_packets():
            out(
                "[MLD] source:{} destination:{} (redirect ::1) (ifindex {})".format(
                    ntop6(source), ntop6(destination), ifindex
                )
            )
            out("  has_router_alert:{}".format("yes" if has_router_alert else "no"))
            mld_print("  ", data)
            out()

        self.packet_send_loop(
            PIM_IPV6_ENCAP_MLD,
            ifindex,
            source,
            IPV6_LOOPBACK,
            data,
            router_alert=has_router_alert,
        )

    def loopback_packet_read_cb(self) -> None:
        """Show the encapsulated IPv6 packets seen on the loopback."""
        assert self.loopback_sock is not None
        try:
            data = self.loopback_sock.recv(READ_BUFFER_SIZE)
        except OSError:
            return

        if not debug_packets() or len(data) < IPV6_HEADER_SIZE:
            return
        if (data[0] & 0xF0) != 0x60 or data[6] != 0:
            return

        ipv6_print("", data)
        if len(data) > IPV6_HEADER_SIZE:
            out("    Extension [next header: {}]".format(data[IPV6_HEADER_SIZE]))
        out()

    def capture_read_cb(self, interface: Interface) -> None:
        """
        Traffic of an interface: the IPv6 packets FRR encapsulated to it go
        to the network, the received multicast data to the emulation.
        """
        assert interface.capture is not None
        try:
            data, address = interface.capture.recvfrom(READ_BUFFER_SIZE)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as error:
            # Reported once when the interface goes down (or away).
            if error.errno not in (errno.ENETDOWN, errno.ENXIO):
                warn_ratelimited(
                    "capture-" + interface.name,
                    "capture {}".format(interface.name),
                    error,
                )
            return

        if not data:
            return

        if address[2] != PACKET_OUTGOING:
            if self.observe is not None:
                version = data[0] >> 4
                if version == 4:
                    self.observe(socket.AF_INET, data, interface.index)
                elif version == 6:
                    self.observe(socket.AF_INET6, data, interface.index)
            return

        # Insufficient packet size and IPv6 checks.
        if len(data) < IPV6_HEADER_SIZE or (data[0] & 0xF0) != 0x60:
            return

        protocol, payload_offset = packet.ipv6_upper_layer(data)
        payload = data[payload_offset:]

        if protocol == PIM_IPV6_ENCAP_MLD:
            if debug_packets():
                ipv6_print("", data)
                mld_print("  ", payload)
                out()

            self.ipv6_packet_send(
                interface,
                data,
                socket.IPPROTO_ICMPV6,
                bytes([0x33, 0x33, 0, 0, 0, data[39]]),
            )
        elif protocol == PIM_IP_ENCAP_PIM:
            if debug_packets():
                ipv6_print("", data)
                pim_print("  ", payload)
                out()

            self.ipv6_packet_send(
                interface,
                data,
                IPPROTO_PIM,
                bytes([0x33, 0x33, 0, 0, 0, 0x0D]),
                traffic_class=0xC0,
            )
        elif protocol in (OSPF_IP_ENCAP_DR, OSPF_IP_ENCAP_SPF):
            if debug_packets():
                ipv6_print("", data)
                out()

            last = 0x06 if protocol == OSPF_IP_ENCAP_DR else 0x05
            self.ipv6_packet_send(
                interface,
                data,
                IPPROTO_OSPF,
                bytes([0x33, 0x33, 0, 0, 0, last]),
                traffic_class=0xC0,
            )

    def ospf6_packet_read_cb(self) -> None:
        """OSPFv3 packets from the network to FRR."""
        result = recvmsg_packet(self.ospf6_sock, "ospf6_packet_read_cb")
        if result is None:
            return
        data, ancdata, address = result

        # Insufficient packet size.
        if len(data) < PIM_HEADER_SIZE:
            return

        destination, ifindex, _ = ipv6_ancillary(ancdata)
        if ifindex == 1:
            return

        if destination == IN6_ALL_SPF_ROUTERS:
            protocol = OSPF_IP_ENCAP_SPF
        elif destination == IN6_ALL_DR_ROUTERS:
            protocol = OSPF_IP_ENCAP_DR
        else:
            protocol = IPPROTO_OSPF

        if destination[0] == 0xFF:
            destination = IPV6_LOOPBACK

        self.packet_send_loop(
            protocol, ifindex, ipv6_source(address), destination, data
        )

    def pim6_packet_read_cb(self) -> None:
        """PIMv6 packets from the network to FRR."""
        result = recvmsg_packet(self.pim6_sock, "pim6_packet_read_cb")
        if result is None:
            return
        data, ancdata, address = result

        # Insufficient packet size.
        if len(data) < PIM_HEADER_SIZE:
            return

        # Registers the RP receives carry traffic to forward.
        if self.register_received is not None:
            inner = packet.pim_register_decode(data)
            if inner is not None:
                self.register_received(socket.AF_INET6, inner)

        _, ifindex, hopopts = ipv6_ancillary(ancdata)
        if ifindex == 1:
            return

        if debug_packets():
            pim_print("", data)

        self.packet_send_loop(
            PIM_IP_ENCAP_PIM,
            ifindex,
            ipv6_source(address),
            IPV6_LOOPBACK,
            data,
            router_alert=packet.hop_options_has_router_alert(hopopts),
        )
