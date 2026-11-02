# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""Packet header helpers: checksum, field access and debug printing."""

from __future__ import annotations

import struct

from .common import Buffer, ntop4, ntop6, out

IPV4_MORE_FRAGMENTS = 0x2000
IPV4_DONT_FRAGMENT = 0x4000

IPV6_HEADER_SIZE = 40
UDP_HEADER_SIZE = 8
PIM_HEADER_SIZE = 8

IGMP_MTRACE_RESPONSE = 0x1E
IGMP_MTRACE_QUERY_REQUEST = 0x1F

ICMP6_MLD_QUERY = 130
ICMP6_MLD_V1_REPORT = 131
ICMP6_MLD_V1_DONE = 132
ICMP6_MLD_V2_REPORT = 143

PIM_TYPE_REGISTER = 1


def checksum16(data: Buffer) -> int:
    """Internet checksum, to be stored in network byte order."""
    data = bytes(data)
    if len(data) % 2:
        data += b"\0"

    total = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def ipv4_header_length(data: Buffer) -> int:
    return (data[0] & 0x0F) << 2


def igmp_is_mtrace(data: Buffer) -> bool:
    "Whether the IPv4 packet `data` carries an mtrace query/request or response."
    header_length = ipv4_header_length(data)
    return len(data) > header_length and data[header_length] in (
        IGMP_MTRACE_RESPONSE,
        IGMP_MTRACE_QUERY_REQUEST,
    )


def ipv4_print(spaces: str, data: Buffer) -> None:
    ihl = ipv4_header_length(data)
    (
        version_ihl,
        tos,
        total_length,
        ident,
        fragmentation,
        ttl,
        protocol,
        checksum,
    ) = struct.unpack_from("!BBHHHBBH", data)
    valid = checksum16(data[:ihl]) == 0
    offset = fragmentation & 0x1FFF

    out("{}version: {}".format(spaces, version_ihl >> 4))
    out("{}header length: {} octets ({} bytes)".format(spaces, ihl >> 2, ihl))
    out("{}ToS: 0x{:02x}".format(spaces, tos))
    out("{}length: {}".format(spaces, total_length))
    out("{}ID: 0x{:04x}".format(spaces, ident))
    out(
        "{}Dont Fragment: {}".format(
            spaces, "yes" if fragmentation & IPV4_DONT_FRAGMENT else "no"
        )
    )
    out(
        "{}More Fragments: {}".format(
            spaces, "yes" if fragmentation & IPV4_MORE_FRAGMENTS else "no"
        )
    )
    out(
        "{}Fragment offset: {} in 8 octets ({} bytes)".format(
            spaces, offset, offset << 3
        )
    )
    out("{}Time To Live: {}".format(spaces, ttl))
    out("{}Protocol: {}".format(spaces, protocol))
    out(
        "{}Checksum: 0x{:04x} ({})".format(
            spaces, checksum, "CORRECT" if valid else "INCORRECT"
        )
    )
    out("{}Source: {}".format(spaces, ntop4(data[12:16])))
    out("{}Destination: {}".format(spaces, ntop4(data[16:20])))


def ipv6_print(spaces: str, data: Buffer) -> None:
    flow, plen, _, hlim = struct.unpack_from("!IHBB", data)
    out(
        "{}[IPv6] {}->{} flow:0x{:05X} length:{} hop-limit:{}".format(
            spaces,
            ntop6(data[8:24]),
            ntop6(data[24:40]),
            flow & 0x000FFFFF,
            plen,
            hlim,
        )
    )


def mld_print(spaces: str, data: Buffer) -> None:
    if len(data) < 8:
        out("mld_print: ICMPv6 packet too small")
        return

    icmp6_type, code, checksum = struct.unpack_from("!BBH", data)
    out(
        "{}[MLD] type: {}, code: {}, checksum: 0x{:04X}".format(
            spaces, icmp6_type, code, checksum
        )
    )

    if icmp6_type == ICMP6_MLD_QUERY:
        out("{}  MLD Query: {}".format(spaces, ntop6(data[8:24])))
    elif icmp6_type == ICMP6_MLD_V1_REPORT:
        out("{}  MLD Report v1 ({}): {}".format(spaces, icmp6_type, ntop6(data[8:24])))
    elif icmp6_type == ICMP6_MLD_V2_REPORT:
        (records,) = struct.unpack_from("!H", data, 6)
        out(
            "{}  MLD Report v2 ({}) number records {}".format(
                spaces, icmp6_type, records
            )
        )

        offset = 8
        for _ in range(records):
            if offset + 20 > len(data):
                break

            record_type, _, sources = struct.unpack_from("!BBH", data, offset)
            out(
                "{}    type {} sources: {} group {}:".format(
                    spaces,
                    record_type,
                    sources,
                    ntop6(data[offset + 4 : offset + 20]),
                )
            )
            for index in reversed(range(sources)):
                start = offset + 20 + index * 16
                if start + 16 <= len(data):
                    out("{}      {}".format(spaces, ntop6(data[start : start + 16])))

            offset += 20 + sources * 16
    elif icmp6_type == ICMP6_MLD_V1_DONE:
        out("{}  MLD Done: {}".format(spaces, ntop6(data[8:24])))
    else:
        out("{}  Unexpected MLD type: {}".format(spaces, icmp6_type))


def pim_print(spaces: str, data: Buffer) -> None:
    if len(data) < PIM_HEADER_SIZE:
        out("pim_print: PIM packet too small")
        return

    version_type, _, checksum, flags = struct.unpack_from("!BBHI", data)
    out(
        "{}[PIMv6] version {} type {} checksum 0x{:04X} flags 0x{:08X}".format(
            spaces, version_type >> 4, version_type & 0x0F, checksum, flags
        )
    )
