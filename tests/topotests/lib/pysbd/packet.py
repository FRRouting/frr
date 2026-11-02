# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Packet encapsulation and decapsulation: these functions only produce bytes
(the data plane writes them to its sockets), so they need no privileges.
"""

from __future__ import annotations

import socket
import struct
from typing import List, Optional, Tuple

from .common import (
    IP_ENCAP_MAGIC_VALUE,
    IPPROTO_OSPF,
    IPPROTO_PIM,
    IPV4_ENCAP_DST,
    IPV4_ENCAP_TOS,
    IPV4_LOOPBACK,
    OSPF_IP_ENCAP_DR,
    OSPF_IP_ENCAP_SPF,
    PIM_IP_ENCAP_PIM,
    PIM_IPV6_ENCAP_MLD,
    Buffer,
    is_forwardable_group,
    is_routable_source,
)
from .wire import (
    IPV4_DONT_FRAGMENT,
    IPV4_MORE_FRAGMENTS,
    IPV6_HEADER_SIZE,
    PIM_HEADER_SIZE,
    PIM_TYPE_REGISTER,
    UDP_HEADER_SIZE,
    checksum16,
    ipv4_header_length,
)

IP6OPT_PAD1 = 0x00
IP6OPT_ROUTER_ALERT = 0x05

#: PIM register Null-Register bit.
PIM_REGISTER_NULL = 0x40000000

IPV4_HEADER = struct.Struct("!BBHHHBBH4s4s")
ENCAP_HEADER = struct.Struct("!HHI")
UDP_HEADER = struct.Struct("!HHHH")

#: Outer IPv4 header plus version, interface index and magic.
ENCAP_OVERHEAD = 20 + ENCAP_HEADER.size

#: IPv6 next headers that are never multicast data.
IPV6_CONTROL_HEADERS = (
    socket.IPPROTO_ICMPV6,
    IPPROTO_PIM,
    IPPROTO_OSPF,
    PIM_IPV6_ENCAP_MLD,
    PIM_IP_ENCAP_PIM,
    OSPF_IP_ENCAP_DR,
    OSPF_IP_ENCAP_SPF,
)
#: IPv4 protocols that are never multicast data.
IPV4_CONTROL_PROTOCOLS = (socket.IPPROTO_IGMP, IPPROTO_PIM, IPPROTO_OSPF)


def ipv4_header_build(
    tos: int,
    total_length: int,
    ttl: int,
    protocol: int,
    source: bytes,
    destination: bytes,
) -> bytes:
    header = bytearray(
        IPV4_HEADER.pack(
            0x45, tos, total_length, 0, 0, ttl, protocol, 0, source, destination
        )
    )
    struct.pack_into("!H", header, 10, checksum16(header))
    return bytes(header)


def ipv4_packet_build(
    protocol: int,
    ifindex: int,
    mtu: int,
    data: Buffer,
    udp_source: int = 0,
    udp_destination: int = 0,
) -> List[Tuple[bytes, int, int]]:
    """
    Encapsulate an IPv4 packet (header included) received from the network
    to deliver it to FRR, fragmenting it when the encapsulation does not fit
    in `mtu`. The fragments keep the offset (and the more fragments flag) of
    the packet, which may already be a fragment.

    UDP encapsulation (`protocol` UDP) replaces the packet UDP ports with
    `udp_source` and `udp_destination` and adds an outer UDP header.

    Returns a list of (packet, fragment offset, fragment size).
    """
    inner = bytes(data)
    if len(inner) < 20:
        return []
    ihl = ipv4_header_length(inner)
    (total_length,) = struct.unpack_from("!H", inner, 2)
    if ihl < 20 or total_length < ihl or len(inner) < ihl:
        return []
    inner = inner[: min(total_length, len(inner))]

    header = bytearray(inner[:ihl])
    payload = inner[ihl:]
    (fragmentation,) = struct.unpack_from("!H", header, 6)
    original_offset = (fragmentation & 0x1FFF) << 3
    original_more = fragmentation & IPV4_MORE_FRAGMENTS

    is_udp = protocol == socket.IPPROTO_UDP
    if is_udp and original_offset == 0 and len(payload) >= UDP_HEADER_SIZE:
        payload = (
            UDP_HEADER.pack(udp_source, udp_destination, len(payload), 0)
            + payload[UDP_HEADER_SIZE:]
        )

    overhead = ENCAP_OVERHEAD + (UDP_HEADER_SIZE if is_udp else 0)
    chunk_size = mtu - overhead - ihl
    chunk_size -= chunk_size % 8
    if chunk_size <= 0:
        return []

    if len(payload) <= chunk_size:
        pieces = [(0, payload, fragmentation & ~0x1FFF)]
    else:
        # Fragments can't keep the don't fragment flag.
        pieces = []
        for offset in range(0, len(payload), chunk_size):
            piece = payload[offset : offset + chunk_size]
            last = offset + chunk_size >= len(payload)
            more = original_more if last else IPV4_MORE_FRAGMENTS
            pieces.append((offset, piece, more))

    fragments = []
    for offset, piece, flags in pieces:
        flags &= IPV4_MORE_FRAGMENTS | IPV4_DONT_FRAGMENT
        struct.pack_into("!H", header, 6, flags | ((original_offset + offset) >> 3))
        struct.pack_into("!H", header, 2, ihl + len(piece))
        struct.pack_into("!H", header, 10, 0)
        struct.pack_into("!H", header, 10, checksum16(header))

        encap = ENCAP_HEADER.pack(0, ifindex & 0xFFFF, IP_ENCAP_MAGIC_VALUE)
        size = overhead + ihl + len(piece)
        outer = ipv4_header_build(
            IPV4_ENCAP_TOS, size, 1, protocol, IPV4_ENCAP_DST, IPV4_LOOPBACK
        )
        if is_udp:
            outer_udp = UDP_HEADER.pack(520, 5200, size - 20, 0)
            packet = outer + outer_udp + encap + bytes(header) + piece
        else:
            packet = outer + encap + bytes(header) + piece

        fragments.append((packet, original_offset + offset, len(piece)))

    return fragments


def ipv4_encap_decode(data: Buffer) -> Optional[Tuple[int, int, bytes]]:
    """
    Decode a packet FRR encapsulated to the data plane.

    Returns (version, interface index, original packet) or `None`.
    """
    if len(data) < 28:
        return None
    (total_length,) = struct.unpack_from("!H", data, 2)
    version, ifindex, magic = struct.unpack_from("!HHI", data, 20)
    if version != 0 or magic != IP_ENCAP_MAGIC_VALUE or total_length < 48:
        return None
    return version, ifindex, bytes(data[28:total_length])


def pim_register_build(
    source: bytes, neighbor: bytes, mcast_source: bytes, mcast_group: bytes
) -> bytes:
    """
    PIM register with an empty inner packet (IP header included), sent when
    a route starts registering without traffic emulation.
    """
    inner = ipv4_header_build(
        IPV4_ENCAP_TOS, 20, 64, IPPROTO_PIM, mcast_source, mcast_group
    )
    pim = bytearray(struct.pack("!BBHI", (2 << 4) | PIM_TYPE_REGISTER, 0, 0, 0) + inner)
    struct.pack_into("!H", pim, 2, checksum16(pim))

    outer = ipv4_header_build(
        IPV4_ENCAP_TOS, 20 + len(pim), 64, IPPROTO_PIM, source, neighbor
    )
    return outer + bytes(pim)


def pim_register_data_build(packet: Buffer) -> bytes:
    """
    PIM register message (without the IP header) carrying `packet`: the
    checksum only covers the PIM register header (RFC 7761 Section 4.9.3).
    For IPv6 the kernel calculates it (over the whole message, which FRR
    accepts too).
    """
    header = bytearray(struct.pack("!BBHI", (2 << 4) | PIM_TYPE_REGISTER, 0, 0, 0))
    struct.pack_into("!H", header, 2, checksum16(header))
    return bytes(header) + bytes(packet)


def pim_register_decode(message: Buffer) -> Optional[bytes]:
    """The packet a (non null) PIM register message carries, or `None`."""
    if len(message) <= PIM_HEADER_SIZE or message[0] != (2 << 4) | PIM_TYPE_REGISTER:
        return None
    (flags,) = struct.unpack_from("!I", message, 4)
    if flags & PIM_REGISTER_NULL:
        return None
    return bytes(message[PIM_HEADER_SIZE:])


def ipv6_checksum(
    source: Buffer,
    destination: Buffer,
    payload_length: int,
    next_header: int,
    payload: Buffer,
) -> int:
    pseudo = (
        bytes(source)
        + bytes(destination)
        + struct.pack("!I", payload_length)
        + bytes(3)
        + bytes([next_header])
    )
    return checksum16(pseudo + bytes(payload))


def _upper_layer_checksum_offset(protocol: int) -> int:
    if protocol in (IPPROTO_OSPF, OSPF_IP_ENCAP_DR, OSPF_IP_ENCAP_SPF):
        return 12
    return 2


def hop_options_has_router_alert(data: Buffer) -> bool:
    """Whether hop-by-hop options carry the MLD router alert (value zero)."""
    # Need at least 8 bytes for options.
    if len(data) < 8:
        return False

    # Options are bigger than read data.
    length = (data[1] + 1) * 8
    if length > len(data):
        return False

    position = 2
    while position < length:
        option = data[position]
        if option == IP6OPT_PAD1:
            position += 1
            continue

        if position + 2 > length:
            return False
        option_length = data[position + 1]
        if position + 2 + option_length > length:
            return False

        if (
            option == IP6OPT_ROUTER_ALERT
            and option_length == 2
            and data[position + 2 : position + 4] == b"\0\0"
        ):
            return True
        position += 2 + option_length

    return False


def ipv6_extension_length(data: Buffer, offset: int = IPV6_HEADER_SIZE) -> int:
    """Length of the IPv6 extension header at `offset`."""
    if len(data) < offset + 2:
        return 0
    return (data[offset + 1] + 1) * 8


def prepend_ipv6_header(
    protocol: int,
    ifindex: int,
    source: bytes,
    destination: bytes,
    data: Buffer,
    traffic_class: int = 0,
    router_alert: bool = False,
) -> bytes:
    """
    Add the IPv6 encapsulation header to a packet received from the network
    to deliver it to FRR (the interface index goes in the flow label).
    """
    payload = bytearray(data)

    hop_options = b""
    if router_alert:
        # Data plane quirk: the hop options are supplied twice.
        hop_options = bytes([protocol, 0, IP6OPT_ROUTER_ALERT, 2, 0, 0, 0, 0]) + bytes(
            [socket.IPPROTO_ICMPV6, 0, IP6OPT_ROUTER_ALERT, 2, 0, 0, 0, 0]
        )
    elif protocol == PIM_IPV6_ENCAP_MLD:
        # Data plane quirk: the hop options are always supplied.
        hop_options = bytes(8)

    offset = _upper_layer_checksum_offset(protocol)
    if len(payload) >= offset + 2:
        struct.pack_into("!H", payload, offset, 0)
        struct.pack_into(
            "!H",
            payload,
            offset,
            ipv6_checksum(source, destination, len(data), protocol, payload),
        )

    flow = (0x60000000 | ((traffic_class & 0xFF) << 20) | ifindex) & 0xFFFFFFFF
    header = struct.pack(
        "!IHBB16s16s",
        flow,
        len(data) + len(hop_options),
        0 if router_alert else protocol,
        1,
        bytes(source),
        bytes(destination),
    )
    return header + hop_options + bytes(payload)


def regenerate_ipv6_header(data: Buffer, proto: int, traffic_class: int = 0) -> bytes:
    """
    Turn an encapsulated IPv6 packet sent by FRR back into the original one:
    restore the next header and recalculate the upper layer checksum.
    """
    packet = bytearray(data)
    if traffic_class:
        (flow,) = struct.unpack_from("!I", packet)
        struct.pack_into("!I", packet, 0, flow | ((traffic_class & 0xFF) << 20))

    (plen,) = struct.unpack_from("!H", packet, 4)
    extension_length = ipv6_extension_length(packet) if packet[6] == 0 else 0
    if extension_length:
        packet[IPV6_HEADER_SIZE] = proto
    else:
        packet[6] = proto
    payload_offset = IPV6_HEADER_SIZE + extension_length

    offset = payload_offset + (12 if proto == IPPROTO_OSPF else 2)
    if len(packet) >= offset + 2:
        struct.pack_into("!H", packet, offset, 0)
        struct.pack_into(
            "!H",
            packet,
            offset,
            ipv6_checksum(
                packet[8:24],
                packet[24:40],
                plen - extension_length,
                proto,
                packet[payload_offset:],
            ),
        )

    return bytes(packet)


def ipv6_upper_layer(data: Buffer) -> Tuple[int, int]:
    """(next header, offset) of the IPv6 payload (after the hop-by-hop options)."""
    if data[6] == 0 and len(data) > IPV6_HEADER_SIZE:
        return data[IPV6_HEADER_SIZE], IPV6_HEADER_SIZE + ipv6_extension_length(data)
    return data[6], IPV6_HEADER_SIZE


def pim6_register_build(mcast_source: bytes, mcast_group: bytes) -> bytes:
    """PIMv6 register: the kernel calculates the checksum (`IPV6_CHECKSUM`)."""
    return struct.pack(
        "!BBHIIHBB16s16s",
        (2 << 4) | PIM_TYPE_REGISTER,
        0,
        0,
        0,
        0x60000000 | (0xC0 << 20),
        IPV6_HEADER_SIZE,
        IPPROTO_PIM,
        64,
        bytes(mcast_source),
        bytes(mcast_group),
    )


def data_packet_flow(family: int, packet: Buffer) -> Optional[Tuple[bytes, bytes]]:
    """
    The (source, group) of a multicast data packet routers forward, `None`
    for anything else (control protocols, link-local scopes, unicast).
    """
    if family == socket.AF_INET:
        if len(packet) < 20 or packet[0] >> 4 != 4:
            return None
        if packet[9] in IPV4_CONTROL_PROTOCOLS:
            return None
        source, group = bytes(packet[12:16]), bytes(packet[16:20])
    else:
        if len(packet) < IPV6_HEADER_SIZE or packet[0] >> 4 != 6:
            return None
        next_header, _ = ipv6_upper_layer(packet)
        if next_header in IPV6_CONTROL_HEADERS:
            return None
        source, group = bytes(packet[8:24]), bytes(packet[24:40])

    if not is_forwardable_group(family, group) or not is_routable_source(
        family, source
    ):
        return None
    return source, group
