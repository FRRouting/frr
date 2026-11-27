# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
pysbd unit tests (no privileges needed), from tests/topotests/lib:

    python3 -m pysbd.test_pysbd
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import sys
from typing import Any, List, Optional, Tuple

import pytest

from . import packet
from .common import (
    IPV4_ENCAP_DST,
    IPV4_LOOPBACK,
    IPV6_LOOPBACK,
    PIM_IP_ENCAP_IGMP,
    PIM_IP_ENCAP_PIM,
    PIM_IPV6_ENCAP_MLD,
    PIM_REG_IF_IDX,
    ConfigError,
    address_parse,
    strtoul,
)
from .console import console
from .dataplane import icmp6_filter_mld
from .emulation import Emulator
from .fpm import (
    RTA_ENCAP,
    RTA_ENCAP_TYPE,
    RTA_MULTIPATH,
    RTA_MRT_EXTRA,
    MRT_EXTRA,
    Fpm,
    fpm_route_attrs_copy,
    parse_mroute,
)
from .interface import Interface, Interfaces
from .mroute import (
    MF6CCTL,
    MFCCTL,
    MRT6_ADD_MFC,
    MRT_ADD_MFC,
    KERNEL_NOCACHE,
    IGMPMSG,
    MfcParams,
    MulticastRouting,
    parse_igmpmsg,
)
from . import mroute
from .netlink import (
    IFADDRMSG,
    IFINFOMSG,
    NLMSG_DONE,
    RTM_DELADDR,
    RTM_DELLINK,
    RTM_NEWADDR,
    RTM_NEWLINK,
    RTM_NEWROUTE,
    RTMSG,
    RTNEXTHOP,
    NetlinkMessage,
    NetlinkMonitor,
    nlmsg_build,
    nlmsg_iter,
    rta_build,
    rta_iter,
)
from .pim import (
    MRT_EVENT_DATA_START,
    MRT_EVENT_DATA_STOP,
    MRT_EVENT_JOIN_SPT,
    MRT_EVENT_WRONG_IF,
    mroute_event_build,
)
from .route import (
    MRT_FLAG_DL_TIMER,
    MRT_FLAG_DUMMY,
    MRT_FLAG_JOIN_SPT_ALLOWED,
    MRT_FLAG_RESTART_DL_TIMER,
    Route,
    RouteTable,
)
from .sbd import Daemon, parse_args
from .stream import StreamEndpoint
from .wire import checksum16, igmp_is_mtrace

AF4 = socket.AF_INET
AF6 = socket.AF_INET6
SRC6 = socket.inet_pton(AF6, "fe80::1")
MLD_ALL = socket.inet_pton(AF6, "ff02::16")
SOURCE = socket.inet_aton("192.168.3.10")
GROUP = socket.inet_aton("239.1.1.1")
ANY4 = bytes(4)


def a4(text: str) -> bytes:
    return socket.inet_aton(text)


def a6(text: str) -> bytes:
    return socket.inet_pton(AF6, text)


def ipv4_build(
    protocol: int,
    payload: bytes,
    source: str,
    destination: str,
    fragmentation: int = 0,
) -> bytes:
    header = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            0x1234,
            fragmentation,
            5,
            protocol,
            0,
            a4(source),
            a4(destination),
        )
    )
    struct.pack_into("!H", header, 10, checksum16(header))
    return bytes(header) + payload


def udp_data(source: bytes = SOURCE, group: bytes = GROUP) -> bytes:
    payload = struct.pack("!HHHH", 5000, 5000, 12, 0) + b"data"
    return ipv4_build(
        socket.IPPROTO_UDP, payload, socket.inet_ntoa(source), socket.inet_ntoa(group)
    )


#
# Codecs.
#
def test_checksum16() -> None:
    # RFC 1071 section 3 example.
    data = bytes([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7])
    assert checksum16(data) == (~0xDDF2 & 0xFFFF)
    # Odd length is padded with zero.
    assert checksum16(b"\x01") == checksum16(b"\x01\x00")


def test_strtoul() -> None:
    assert strtoul("10") == 10
    assert strtoul("0x10") == 16
    assert strtoul("010") == 8
    assert strtoul("-1") == 0xFFFFFFFF
    assert strtoul("10a") is None


def test_address_parse() -> None:
    assert address_parse("ipv4:127.0.0.1", 2650) == (AF4, ("127.0.0.1", 2650), False)
    assert address_parse("ipv4c:127.0.0.1:1234", 2650) == (
        AF4,
        ("127.0.0.1", 1234),
        True,
    )
    assert address_parse("ipv6:[::1]", 2651) == (AF6, ("::1", 2651), False)
    assert address_parse("ipv6c:[2001:db8::1]:3000", 2651) == (
        AF6,
        ("2001:db8::1", 3000),
        True,
    )
    assert address_parse("unix:/tmp/x", 0) == (socket.AF_UNIX, "/tmp/x", False)

    for invalid in ("127.0.0.1", "ipv4:300.0.0.1", "ipv6:::1", "ipv4:1.1.1.1:0", "x:y"):
        with pytest.raises(ConfigError):
            address_parse(invalid, 1)


def test_mroute_event() -> None:
    message = mroute_event_build(MRT_EVENT_WRONG_IF, 5, SOURCE, GROUP)

    assert len(message) == 44
    assert message[:12] == bytes([1, 2, 0, 44, 0, 0, 0, 0, 0, 0, 0, 5])
    assert message[12:28] == SOURCE + bytes(12)
    assert message[28:44] == GROUP + bytes(12)

    # Negative interface indexes stay 32 bits.
    message = mroute_event_build(0, 0xFFFFFFFF, SOURCE, GROUP)
    assert message[8:12] == b"\xff\xff\xff\xff"


def test_kernel_struct_sizes() -> None:
    assert mroute.VIFCTL.size == 16
    assert MFCCTL.size == 60
    assert mroute.IP_MREQN.size == 12
    assert IGMPMSG.size == 20
    assert mroute.MIF6CTL.size == 12
    assert MF6CCTL.size == 92
    assert mroute.IPV6_MREQ.size == 20
    assert mroute.MRT6MSG.size == 40


def test_kernel_upcalls() -> None:
    nocache = IGMPMSG.pack(0, 0, 1, 0, 3, 0, SOURCE, GROUP)
    event = parse_igmpmsg(nocache)
    assert event is not None
    assert (event.kind, event.mif, event.source, event.group) == (
        KERNEL_NOCACHE,
        3,
        SOURCE,
        GROUP,
    )
    # WHOLEPKT and unknown messages are not events.
    assert parse_igmpmsg(IGMPMSG.pack(0, 0, 3, 0, 3, 0, SOURCE, GROUP)) is None
    assert parse_igmpmsg(IGMPMSG.pack(0, 0, 9, 0, 3, 0, SOURCE, GROUP)) is None


def test_icmp6_filter() -> None:
    words = struct.unpack("=8I", icmp6_filter_mld())
    for icmp6_type in range(256):
        blocked = bool(words[icmp6_type >> 5] & (1 << (icmp6_type & 31)))
        assert blocked == (icmp6_type not in (130, 131, 132, 143))


#
# Encapsulation.
#
def test_igmp_is_mtrace() -> None:
    "mtrace stays out of the encapsulation: the OS delivers it to pimd."
    igmp = socket.IPPROTO_IGMP
    for igmp_type in (0x1E, 0x1F):
        data = ipv4_build(igmp, bytes([igmp_type]) + bytes(23), "10.0.0.1", "10.0.0.2")
        assert igmp_is_mtrace(data)
    for igmp_type in (0x11, 0x16, 0x17, 0x22):
        data = ipv4_build(igmp, bytes([igmp_type]) + bytes(7), "10.0.0.1", "224.0.0.1")
        assert not igmp_is_mtrace(data)
    # Nothing past the header.
    assert not igmp_is_mtrace(ipv4_build(igmp, b"", "10.0.0.1", "10.0.0.2"))


def test_ipv4_encapsulation() -> None:
    igmp = bytes([0x16, 0, 0, 0]) + a4("239.1.1.1")
    original = ipv4_build(socket.IPPROTO_IGMP, igmp, "192.168.1.10", "239.1.1.1")

    fragments = packet.ipv4_packet_build(PIM_IP_ENCAP_IGMP, 7, 1500, original)
    assert len(fragments) == 1
    encapsulated, offset, size = fragments[0]
    assert (offset, size) == (0, len(igmp))

    # Outer header.
    assert checksum16(encapsulated[:20]) == 0
    assert struct.unpack_from("!H", encapsulated, 2)[0] == len(encapsulated)
    assert encapsulated[1] == 0xC0 and encapsulated[8] == 1
    assert encapsulated[9] == PIM_IP_ENCAP_IGMP
    assert encapsulated[12:16] == IPV4_ENCAP_DST
    assert encapsulated[16:20] == IPV4_LOOPBACK
    # Version, interface index and magic.
    assert struct.unpack_from("!HHI", encapsulated, 20) == (0, 7, 0x676F6C64)
    # Original packet.
    assert encapsulated[28:] == original


def test_ipv4_encapsulation_fragments() -> None:
    payload = bytes(range(256)) * 12
    original = ipv4_build(103, payload, "10.0.0.1", "224.0.0.13")

    fragments = packet.ipv4_packet_build(PIM_IP_ENCAP_PIM, 2, 1500, original)
    assert len(fragments) == 3

    reassembled = b""
    for index, (encapsulated, offset, _) in enumerate(fragments):
        inner = encapsulated[28:]
        assert checksum16(inner[:20]) == 0
        (fragmentation,) = struct.unpack_from("!H", inner, 6)
        assert (fragmentation & 0x1FFF) << 3 == offset
        assert bool(fragmentation & 0x2000) == (index < 2)
        assert len(encapsulated) <= 1500
        reassembled += inner[20:]
    assert reassembled == payload


def test_ipv4_encapsulation_of_a_fragment() -> None:
    # A middle fragment (offset 800, more fragments) too big for one packet.
    payload = bytes(range(256)) * 8
    original = ipv4_build(103, payload, "10.0.0.1", "224.0.0.13", 0x2000 | 100)

    fragments = packet.ipv4_packet_build(PIM_IP_ENCAP_PIM, 2, 1500, original)
    assert len(fragments) == 2
    for encapsulated, offset, size in fragments:
        (fragmentation,) = struct.unpack_from("!H", encapsulated[28:], 6)
        assert (fragmentation & 0x1FFF) << 3 == offset
        # Every piece has more fragments: the original wasn't the last.
        assert fragmentation & 0x2000
    assert fragments[0][1] == 800
    assert fragments[1][1] == 800 + fragments[0][2]


def test_ipv4_encapsulation_keeps_flags() -> None:
    # Don't fragment survives when the packet fits.
    original = ipv4_build(103, b"x" * 20, "10.0.0.1", "224.0.0.13", 0x4000)
    ((encapsulated, _, _),) = packet.ipv4_packet_build(
        PIM_IP_ENCAP_PIM, 2, 1500, original
    )
    assert struct.unpack_from("!H", encapsulated[28:], 6)[0] == 0x4000

    # A packet without payload is still delivered.
    empty = ipv4_build(103, b"", "10.0.0.1", "224.0.0.13")
    assert len(packet.ipv4_packet_build(PIM_IP_ENCAP_PIM, 2, 1500, empty)) == 1


def test_ipv4_udp_encapsulation() -> None:
    rip_payload = b"\x02\x02\x00\x00" + bytes(20)
    udp = struct.pack("!HHHH", 520, 520, 8 + len(rip_payload), 0) + rip_payload
    original = ipv4_build(socket.IPPROTO_UDP, udp, "10.0.0.1", "224.0.0.9")

    ((encapsulated, _, _),) = packet.ipv4_packet_build(
        socket.IPPROTO_UDP, 3, 1500, original, 520, 5200
    )
    assert encapsulated[9] == socket.IPPROTO_UDP
    assert struct.unpack_from("!HHH", encapsulated, 20) == (
        520,
        5200,
        len(encapsulated) - 20,
    )
    assert struct.unpack_from("!HHI", encapsulated, 28) == (0, 3, 0x676F6C64)
    assert encapsulated[36:56] == original[:20]
    assert struct.unpack_from("!HHH", encapsulated, 56) == (520, 5200, len(udp))
    assert encapsulated[64:] == rip_payload


def test_ipv4_encap_decode() -> None:
    inner = ipv4_build(103, b"hello", "10.0.0.1", "224.0.0.13")
    outer = packet.ipv4_header_build(
        0xC0, 28 + len(inner), 1, 249, a4("127.0.0.1"), IPV4_ENCAP_DST
    )
    encap = struct.pack("!HHI", 0, 4, 0x676F6C64)
    assert packet.ipv4_encap_decode(outer + encap + inner) == (0, 4, inner)

    bad_magic = struct.pack("!HHI", 0, 4, 0x12345678)
    assert packet.ipv4_encap_decode(outer + bad_magic + inner) is None
    bad_version = struct.pack("!HHI", 1, 4, 0x676F6C64)
    assert packet.ipv4_encap_decode(outer + bad_version + inner) is None


def test_pim_registers() -> None:
    register = packet.pim_register_build(a4("10.0.0.1"), a4("10.0.0.2"), SOURCE, GROUP)
    assert len(register) == 48
    assert checksum16(register[:20]) == 0
    assert register[20] == 0x21
    assert checksum16(register[20:]) == 0
    assert checksum16(register[28:]) == 0

    # Data registers: the checksum only covers the register header.
    data = udp_data()
    message = packet.pim_register_data_build(data)
    assert checksum16(message[:8]) == 0
    assert packet.pim_register_decode(message) == data

    null = bytearray(message)
    null[4] |= 0x40
    assert packet.pim_register_decode(bytes(null)) is None
    assert packet.pim_register_decode(b"\x20\x00\x00\x00\x00\x00\x00\x00x") is None


def mld_report() -> bytes:
    return struct.pack("!BBHHH", 143, 0, 0, 0, 1) + struct.pack(
        "!BBH16s", 4, 0, 0, a6("ff05::1")
    )


def test_ipv6_encapsulation_router_alert() -> None:
    report = mld_report()
    encapsulated = packet.prepend_ipv6_header(
        PIM_IPV6_ENCAP_MLD, 9, SRC6, IPV6_LOOPBACK, report, router_alert=True
    )

    flow, plen, nxt, hlim = struct.unpack_from("!IHBB", encapsulated)
    assert flow == 0x60000009
    assert (plen, nxt, hlim) == (len(report) + 16, 0, 1)
    assert encapsulated[8:24] == SRC6 and encapsulated[24:40] == IPV6_LOOPBACK
    assert encapsulated[40:48] == bytes([240, 0, 5, 2, 0, 0, 0, 0])
    assert encapsulated[48:56] == bytes([58, 0, 5, 2, 0, 0, 0, 0])
    assert encapsulated[56:58] == report[:2]
    assert encapsulated[60:] == report[4:]
    # The checksum uses the encapsulation next header.
    assert (
        packet.ipv6_checksum(SRC6, IPV6_LOOPBACK, len(report), 240, encapsulated[56:])
        == 0
    )


def test_ipv6_encapsulation_mld_without_router_alert() -> None:
    report = mld_report()
    encapsulated = packet.prepend_ipv6_header(
        PIM_IPV6_ENCAP_MLD, 9, SRC6, IPV6_LOOPBACK, report
    )
    assert struct.unpack_from("!HB", encapsulated, 4) == (len(report) + 8, 240)
    assert encapsulated[40:48] == bytes(8)


@pytest.mark.parametrize(
    "options",
    [
        bytes([5, 2, 0, 0, 1, 0]),  # router alert, PadN
        bytes([1, 0, 5, 2, 0, 0]),  # PadN, router alert
        bytes([0, 0, 5, 2, 0, 0]),  # Pad1, Pad1, router alert
    ],
)
def test_ipv6_regenerate(options: bytes) -> None:
    report = mld_report()
    hop_by_hop = bytes([240, 0]) + options
    plen = len(hop_by_hop) + len(report)
    sent = (
        struct.pack("!IHBB16s16s", 0x60000005, plen, 0, 1, SRC6, MLD_ALL)
        + hop_by_hop
        + report
    )

    regenerated = packet.regenerate_ipv6_header(sent, socket.IPPROTO_ICMPV6)
    assert len(regenerated) == len(sent)
    assert regenerated[6] == 0
    assert regenerated[40] == socket.IPPROTO_ICMPV6
    assert (
        packet.ipv6_checksum(
            SRC6, MLD_ALL, len(report), socket.IPPROTO_ICMPV6, regenerated[48:]
        )
        == 0
    )
    assert packet.hop_options_has_router_alert(hop_by_hop)


def test_ipv6_regenerate_long_extension() -> None:
    # A 16 byte hop-by-hop header (length 1).
    report = mld_report()
    hop_by_hop = bytes([240, 1, 5, 2, 0, 0, 1, 10]) + bytes(8)
    sent = (
        struct.pack(
            "!IHBB16s16s",
            0x60000005,
            len(hop_by_hop) + len(report),
            0,
            1,
            SRC6,
            MLD_ALL,
        )
        + hop_by_hop
        + report
    )
    regenerated = packet.regenerate_ipv6_header(sent, socket.IPPROTO_ICMPV6)
    assert (
        packet.ipv6_checksum(
            SRC6, MLD_ALL, len(report), socket.IPPROTO_ICMPV6, regenerated[56:]
        )
        == 0
    )
    assert packet.ipv6_upper_layer(sent) == (240, 56)


def test_hop_options_router_alert() -> None:
    assert packet.hop_options_has_router_alert(bytes([58, 0, 5, 2, 0, 0, 1, 0]))
    assert not packet.hop_options_has_router_alert(bytes([58, 0, 1, 4, 0, 0, 0, 0]))
    assert not packet.hop_options_has_router_alert(b"")
    # Only MLD (value zero) counts.
    assert not packet.hop_options_has_router_alert(bytes([58, 0, 5, 2, 0, 1, 1, 0]))
    # Malformed option lengths.
    assert not packet.hop_options_has_router_alert(bytes([58, 0, 5, 0, 1, 9, 0, 0]))


def test_data_packet_flow() -> None:
    assert packet.data_packet_flow(AF4, udp_data()) == (SOURCE, GROUP)
    # Link-local groups, control protocols and bad sources are not data.
    assert packet.data_packet_flow(AF4, udp_data(group=a4("224.0.0.9"))) is None
    assert packet.data_packet_flow(AF4, udp_data(source=a4("127.0.0.1"))) is None
    pim = ipv4_build(103, b"\x20" * 8, "10.0.0.1", "239.1.1.1")
    assert packet.data_packet_flow(AF4, pim) is None

    ipv6 = struct.pack(
        "!IHBB16s16s", 0x60000000, 8, 17, 5, a6("2001:db8::1"), a6("ff05::1")
    ) + bytes(8)
    assert packet.data_packet_flow(AF6, ipv6) == (a6("2001:db8::1"), a6("ff05::1"))
    link_local = ipv6[:8] + SRC6 + ipv6[24:]
    assert packet.data_packet_flow(AF6, link_local) is None
    mld = ipv6[:6] + bytes([58]) + ipv6[7:]
    assert packet.data_packet_flow(AF6, mld) is None


#
# Netlink and FPM.
#
def test_netlink_iterators() -> None:
    body = bytes(12) + rta_build(1, b"\x01\x02\x03") + rta_build(2, b"\x04" * 4)
    data = nlmsg_build(24, 0, 5, body) + nlmsg_build(3, 0, 6, b"")

    messages = list(nlmsg_iter(data))
    assert [(msg.type, msg.seq) for msg in messages] == [(24, 5), (3, 6)]
    assert list(rta_iter(messages[0].payload, 12)) == [
        (1, b"\x01\x02\x03"),
        (2, b"\x04" * 4),
    ]


def test_fpm_route_attrs_copy() -> None:
    encap_type = rta_build(RTA_ENCAP_TYPE, struct.pack("=H", 100))
    encap = rta_build(RTA_ENCAP | 0x8000, rta_build(1, struct.pack("=I", 1000)))
    gateway = rta_build(5, a4("10.0.0.2"))
    nexthop_attrs = encap_type + encap + gateway
    nexthop = (
        RTNEXTHOP.pack(RTNEXTHOP.size + len(nexthop_attrs), 0, 0, 4) + nexthop_attrs
    )
    attributes = rta_build(1, a4("10.1.0.0")) + rta_build(RTA_MULTIPATH, nexthop)

    copied = fpm_route_attrs_copy(attributes + encap_type + encap)
    (dst, multipath) = list(rta_iter(copied))
    assert dst == (1, a4("10.1.0.0"))
    assert multipath[0] == RTA_MULTIPATH
    nh_len, _, _, ifindex = RTNEXTHOP.unpack_from(multipath[1])
    assert (nh_len, ifindex) == (RTNEXTHOP.size + len(gateway), 4)
    assert multipath[1][RTNEXTHOP.size :] == gateway

    # Nothing is stripped without the VXLAN encapsulation type (each next
    # hop decides for its own attributes).
    plain_nexthop = RTNEXTHOP.pack(RTNEXTHOP.size + len(encap), 0, 0, 4) + encap
    plain = rta_build(RTA_MULTIPATH, plain_nexthop) + encap
    assert fpm_route_attrs_copy(plain) == plain


def mroute_message(
    family: int,
    source: bytes,
    group: bytes,
    iif: int,
    oifs: List[int],
    notif: int = 0,
    flags: int = 0,
    remote: bytes = b"",
    install: bool = True,
) -> NetlinkMessage:
    attributes = (
        rta_build(2, source)
        + rta_build(1, group)
        + rta_build(3, struct.pack("=i", iif))
    )
    if oifs:
        nexthops = b"".join(RTNEXTHOP.pack(8, 0, 0, oif) for oif in oifs)
        attributes += rta_build(RTA_MULTIPATH, nexthops)
    attributes += rta_build(
        RTA_MRT_EXTRA,
        MRT_EXTRA.pack(0, notif, flags, bytes(16), remote.ljust(16, b"\0")),
    )
    rtm = RTMSG.pack(128 if family == AF4 else 129, 0, 0, 0, 254, 11, 0, 1, 0)
    msg_type = RTM_NEWROUTE if install else RTM_NEWROUTE + 1
    return NetlinkMessage(nlmsg_build(msg_type, 0, 1, rtm + attributes))


def test_parse_mroute() -> None:
    route = parse_mroute(
        mroute_message(
            AF4,
            SOURCE,
            GROUP,
            3,
            [4, PIM_REG_IF_IDX],
            notif=5,
            flags=MRT_FLAG_RESTART_DL_TIMER,
            remote=a4("10.254.0.2"),
        ),
        AF4,
    )
    assert (route.source, route.group, route.iif, route.notif) == (SOURCE, GROUP, 3, 5)
    assert route.oifs == [4, PIM_REG_IF_IDX]
    assert route.forwarding_oifs == [4]
    assert route.registers
    assert route.flag_names() == ["RESTART_DL_TIMER"]


#
# Kernel routing, interfaces and netlink (fake sockets).
#
class FakeSocket:
    def __init__(self) -> None:
        self.options: List[Tuple[int, int, Any]] = []
        self.sent: List[bytes] = []

    def setsockopt(self, level: int, option: int, value: Any) -> None:
        self.options.append((level, option, value))

    def sendto(self, data: bytes, address: Any) -> int:
        self.sent.append(data)
        return len(data)


def mfc6_entries(sock: FakeSocket) -> List[Tuple[bytes, int, List[int]]]:
    entries = []
    for _, option, value in sock.options:
        if option == MRT6_ADD_MFC:
            origin, _, parent, ifset = MF6CCTL.unpack(value)
            words = struct.unpack("=8I", ifset)
            mifs = [mif for mif in range(32) if words[mif // 32] & (1 << (mif % 32))]
            entries.append((origin, parent, mifs))
    return entries


def mfc4_entries(sock: FakeSocket) -> List[Tuple[bytes, int, List[int]]]:
    entries = []
    for _, option, value in sock.options:
        if option == MRT_ADD_MFC:
            origin, _, parent, ttls, _, _, _, _ = MFCCTL.unpack(value)
            entries.append((origin, parent, [vif for vif in range(32) if ttls[vif]]))
    return entries


def make_routing() -> Tuple[MulticastRouting, FakeSocket, FakeSocket]:
    sock4, sock6 = FakeSocket(), FakeSocket()
    routing = MulticastRouting(sock4, sock6, lambda: 1, lambda: 7)  # type: ignore
    return routing, sock4, sock6


def test_mfc_quirks() -> None:
    routing, sock4, sock6 = make_routing()

    # SG(*,G): the input interface is in the output list (IPv4 and IPv6).
    for family, sock, entries in (
        (AF4, sock4, mfc4_entries),
        (AF6, sock6, mfc6_entries),
    ):
        params = MfcParams(family)
        params.install = True
        params.group = GROUP if family == AF4 else a6("ff05::1")
        params.iif = 2
        params.oifs = [3]
        routing.mfc(params)
        assert entries(sock)[-1][1:] == (2, [2, 3])

    # SG(S,G): first with input zero, then the real one; zero means the RP
    # interface (VIF 1, MIF 7).
    params = MfcParams(AF6)
    params.install = True
    params.source = a6("2001:db8::1")
    params.group = a6("ff05::1")
    params.iif = 2
    params.oifs = [3]
    sock6.options.clear()
    routing.mfc(params)
    assert [entry[1:] for entry in mfc6_entries(sock6)] == [(0, [3]), (2, [3])]

    params.iif = 0
    params.previously_installed = True
    sock6.options.clear()
    routing.mfc(params)
    assert [entry[1:] for entry in mfc6_entries(sock6)] == [(7, [3])]


def test_vif_mif_reuse() -> None:
    routing, _, _ = make_routing()
    assert [routing.vif_add(index, a4("10.0.0.1")) for index in (2, 3, 4)] == [1, 2, 3]
    routing.vif_del(3, 2)
    assert routing.vif_add(5, a4("10.0.0.1")) == 2
    assert [routing.mif_add(index) for index in (2, 3)] == [1, 2]
    routing.mif_del(2, 1)
    assert routing.mif_add(4) == 1


class FakeHooks:
    def __init__(self) -> None:
        self.events: List[Tuple[str, str]] = []

    def interface_added(self, interface: Interface) -> None:
        self.events.append(("added", interface.name))

    def interface_removed(self, interface: Interface) -> None:
        self.events.append(("removed", interface.name))

    def interface_ipv4_enabled(self, interface: Interface) -> None:
        self.events.append(("ipv4", interface.name))


def make_interfaces() -> Tuple[Interfaces, FakeHooks, MulticastRouting]:
    routing, _, _ = make_routing()
    hooks = FakeHooks()
    return Interfaces(routing, hooks), hooks, routing


def test_interfaces() -> None:
    interfaces, hooks, routing = make_interfaces()
    interfaces.link(1, "lo")
    interfaces.link(2, "eth0")
    assert [(i.name, i.mif, i.vif) for i in interfaces] == [
        ("lo", 1, 0),
        ("eth0", 2, 0),
    ]

    # Loopback addresses never get a VIF.
    interfaces.address_add(1, a4("127.0.0.1"))
    assert interfaces.find_index(1).vif == 0  # type: ignore
    interfaces.address_add(1, a4("10.254.0.1"))
    interfaces.address_add(2, a4("10.0.0.1"))
    interfaces.address_add(2, a4("10.0.1.1"))
    assert (interfaces.ifi2vif(1), interfaces.ifi2vif(2)) == (1, 2)
    assert hooks.events[-2:] == [("ipv4", "lo"), ("ipv4", "eth0")]

    # The VIF stays while an address remains.
    interfaces.address_del(2, a4("10.0.0.1"))
    assert interfaces.ifi2vif(2) == 2
    interfaces.address_del(2, a4("10.0.1.1"))
    assert interfaces.ifi2vif(2) == 0 and not routing.vif_used[2]

    # Rename and removal.
    interfaces.link(2, "eth9")
    assert interfaces.name(2) == "eth9"
    interfaces.unlink(2)
    assert interfaces.find_index(2) is None and not routing.mif_used[2]
    assert hooks.events[-1] == ("removed", "eth9")

    # A name seen with another index replaces the stale interface.
    interfaces.link(3, "lo")
    assert interfaces.find_index(1) is None and interfaces.name(3) == "lo"


def test_interfaces_sync() -> None:
    interfaces, _, _ = make_interfaces()
    interfaces.link(1, "lo")
    interfaces.link(2, "eth0")
    interfaces.address_add(2, a4("10.0.0.1"))

    interfaces.sync_links({1: "lo", 3: "eth1"})
    assert [i.name for i in interfaces] == ["lo", "eth1"]
    interfaces.sync_addresses({3: [a4("10.0.3.1")]})
    assert interfaces.ifi2vif(3) == 1
    interfaces.sync_addresses({})
    assert interfaces.ifi2vif(3) == 0


def link_message(
    msg_type: int, index: int, name: str, pid: int = 0, seq: int = 0
) -> NetlinkMessage:
    body = IFINFOMSG.pack(0, 0, index, 0, 0) + rta_build(3, name.encode() + b"\0")
    return NetlinkMessage(nlmsg_build(msg_type, 0, seq, body, pid))


def address_message(
    msg_type: int, index: int, address: str, pid: int = 0, seq: int = 0
) -> NetlinkMessage:
    body = IFADDRMSG.pack(AF4, 24, 0, 0, index) + rta_build(2, a4(address))
    return NetlinkMessage(nlmsg_build(msg_type, 0, seq, body, pid))


def test_netlink_monitor() -> None:
    interfaces, _, _ = make_interfaces()
    monitor = NetlinkMonitor(interfaces, None)  # type: ignore
    monitor.sock = FakeSocket()  # type: ignore
    monitor.pid = 1234

    # Start dump: links, then addresses.
    monitor.resync()
    seq = monitor.dump_seq
    monitor._handle(link_message(RTM_NEWLINK, 1, "lo", 1234, seq))
    monitor._handle(link_message(RTM_NEWLINK, 2, "eth0", 1234, seq))
    # A notification during the dump.
    monitor._handle(link_message(RTM_NEWLINK, 3, "eth1"))
    monitor._handle(NetlinkMessage(nlmsg_build(NLMSG_DONE, 0, seq, b"\0" * 4, 1234)))
    assert monitor.dumping == "addresses"
    assert [i.name for i in interfaces] == ["lo", "eth0", "eth1"]

    seq = monitor.dump_seq
    monitor._handle(address_message(RTM_NEWADDR, 2, "10.0.0.1", 1234, seq))
    monitor._handle(address_message(RTM_NEWADDR, 3, "10.0.1.1"))
    monitor._handle(NetlinkMessage(nlmsg_build(NLMSG_DONE, 0, seq, b"\0" * 4, 1234)))
    assert monitor.dumping is None
    # The notification applied right away (first VIF), the dump at its end.
    assert (interfaces.ifi2vif(3), interfaces.ifi2vif(2)) == (1, 2)

    # Notifications afterwards.
    monitor._handle(address_message(RTM_DELADDR, 3, "10.0.1.1"))
    monitor._handle(link_message(RTM_DELLINK, 2, "eth0"))
    assert interfaces.ifi2vif(3) == 0 and interfaces.find_index(2) is None

    # Lost notifications: the next dump removes what's gone.
    monitor.resync()
    seq = monitor.dump_seq
    monitor._handle(link_message(RTM_NEWLINK, 1, "lo", 1234, seq))
    monitor._handle(NetlinkMessage(nlmsg_build(NLMSG_DONE, 0, seq, b"\0" * 4, 1234)))
    assert [i.name for i in interfaces] == ["lo"]


class FakeRouting:
    def __init__(self) -> None:
        self.calls: List[MfcParams] = []

    def mfc(self, params: MfcParams) -> None:
        self.calls.append(params)


def make_fpm(
    emulator: Optional[Emulator] = None,
) -> Tuple[Fpm, FakeRouting, List[Route]]:
    interfaces, _, _ = make_interfaces()
    interfaces.link(2, "eth0")
    interfaces.link(3, "eth1")
    interfaces.address_add(2, a4("10.0.0.1"))
    interfaces.address_add(3, a4("10.0.1.1"))
    routing = FakeRouting()
    registers: List[Route] = []
    fpm = Fpm(
        RouteTable() if emulator is None else emulator.routes,
        routing,  # type: ignore
        interfaces,
        lambda data: None,
        registers.append,
        emulator,
    )
    return fpm, routing, registers


def test_fpm_mroutes() -> None:
    fpm, routing, registers = make_fpm()

    # Without emulation the notification interface is the input one.
    fpm._handle_message(
        mroute_message(
            AF4, SOURCE, GROUP, 0, [3, PIM_REG_IF_IDX], notif=2, remote=a4("10.254.0.2")
        )
    )
    params = routing.calls[-1]
    assert (params.install, params.iif, params.oifs) == (True, 1, [2, 0])
    assert not params.previously_installed
    assert registers and registers[-1].key == (AF4, SOURCE, GROUP)

    # IPv6 routes use the MIF numbers.
    group6 = a6("ff05::1")
    fpm._handle_message(mroute_message(AF6, a6("2001:db8::1"), group6, 0, [3], notif=2))
    assert routing.calls[-1].iif == fpm.interfaces.ifi2mif(2)

    # Update, then delete.
    fpm._handle_message(mroute_message(AF4, SOURCE, GROUP, 2, [3]))
    assert routing.calls[-1].previously_installed
    fpm._handle_message(mroute_message(AF4, SOURCE, GROUP, 2, [3], install=False))
    assert not routing.calls[-1].install
    assert fpm.routes.get(AF4, SOURCE, GROUP) is None

    # Lost connection: the routes go away.
    fpm._closed()
    assert len(fpm.routes) == 0


def test_fpm_frames() -> None:
    fpm, routing, _ = make_fpm()
    message = mroute_message(AF4, SOURCE, GROUP, 2, [3]).data

    async def _feed(data: bytes) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        await fpm._serve(reader, None)  # type: ignore

    # Protobuf frames are skipped, netlink ones handled.
    frames = struct.pack("!BBH", 1, 2, 8) + b"abcd"
    frames += struct.pack("!BBH", 1, 1, 4 + len(message)) + message
    asyncio.run(_feed(frames))
    assert len(routing.calls) == 1

    # Unknown versions end the connection (nothing after them is read).
    asyncio.run(_feed(struct.pack("!BBH", 2, 1, 4 + len(message)) + message))
    assert len(routing.calls) == 1


def test_stream_replace() -> None:
    closed: List[int] = []
    served: List[asyncio.StreamWriter] = []

    async def _handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        served.append(writer)
        await reader.read()

    async def _scenario() -> None:
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        endpoint = StreamEndpoint("test", port, _handler, lambda: closed.append(1))
        await endpoint.start("ipv4:127.0.0.1")
        _, writer1 = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.1)
        assert endpoint.connected and closed == []

        reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.1)
        assert closed == [1] and len(served) == 2
        assert endpoint.writer is served[1]

        writer2.close()
        await asyncio.sleep(0.1)
        assert closed == [1, 1] and not endpoint.connected
        writer1.close()
        endpoint.close()

    asyncio.run(_scenario())


#
# Emulation.
#
class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class Recorder:
    def __init__(self) -> None:
        self.events: List[Tuple[int, int]] = []
        self.registers: List[bytes] = []
        self.decapsulated: List[bytes] = []
        self.removed: List[Route] = []

    def report(self, family: int, event: int, ifindex: int, s: bytes, g: bytes) -> None:
        self.events.append((event, ifindex))


def make_emulator(timeout: float = 5.0) -> Tuple[Emulator, RouteTable, Recorder, Clock]:
    routes = RouteTable()
    recorder = Recorder()
    clock = Clock()

    def _remove(route: Route) -> None:
        recorder.removed.append(route)
        route.installed = False

    emulator = Emulator(
        routes,
        recorder.report,
        lambda route, data: recorder.registers.append(data),
        lambda family, data: recorder.decapsulated.append(data),
        _remove,
        timeout,
        clock,
    )
    return emulator, routes, recorder, clock


def add_route(
    emulator: Emulator,
    routes: RouteTable,
    source: bytes,
    iif: int,
    oifs: List[int],
    flags: int = 0,
    notif: int = 0,
) -> Route:
    route = Route(AF4, source, GROUP)
    route.iif, route.oifs, route.flags, route.notif = iif, oifs, flags, notif
    route.remote = a4("10.254.0.2")
    route.installed = True
    previous = routes.get(*route.key)
    routes.set(route)
    emulator.route_changed(route, previous)
    return route


def test_emulation_spt_switch() -> None:
    emulator, routes, recorder, clock = make_emulator()
    # LHR: SG(*,G) from the RPT interface 2, allowed to switch.
    add_route(emulator, routes, ANY4, 2, [4, PIM_REG_IF_IDX], MRT_FLAG_JOIN_SPT_ALLOWED)

    for _ in range(3):
        emulator.observe(AF4, udp_data(), 2)
        clock.now += 1
    assert recorder.events == [(MRT_EVENT_JOIN_SPT, 2)]

    # The SG(S,G) moves to the SPT (interface 3): traffic there means the
    # switch is done.
    add_route(emulator, routes, SOURCE, 3, [4], MRT_FLAG_RESTART_DL_TIMER)
    emulator.observe(AF4, udp_data(), 3)
    emulator.observe(AF4, udp_data(), 3)
    assert recorder.events[1:] == [(MRT_EVENT_DATA_START, 3)]

    # The traffic stops: one DATA_STOP.
    clock.now += 6
    emulator.tick()
    emulator.tick()
    assert recorder.events[2:] == [(MRT_EVENT_DATA_STOP, 3)]

    # And starts again.
    emulator.observe(AF4, udp_data(), 3)
    assert recorder.events[3:] == [(MRT_EVENT_DATA_START, 3)]

    # Without the SG(S,G) the source can switch again.
    removed = routes.pop((AF4, SOURCE, GROUP))
    assert removed is not None
    emulator.route_removed(removed)
    emulator.observe(AF4, udp_data(), 2)
    assert recorder.events[4:] == [(MRT_EVENT_JOIN_SPT, 2)]


def test_emulation_notification_interface() -> None:
    emulator, routes, recorder, _ = make_emulator()
    # RP waiting for the traffic on interface 3 (no input interface yet).
    add_route(emulator, routes, SOURCE, 0, [4], notif=3)
    emulator.observe(AF4, udp_data(), 2)
    assert recorder.events == []
    emulator.observe(AF4, udp_data(), 3)
    emulator.observe(AF4, udp_data(), 3)
    assert recorder.events == [(MRT_EVENT_DATA_START, 3)]


def test_emulation_wrong_if() -> None:
    emulator, routes, recorder, clock = make_emulator()
    add_route(emulator, routes, SOURCE, 2, [3, 4])
    emulator.observe(AF4, udp_data(), 3)
    emulator.observe(AF4, udp_data(), 3)
    assert recorder.events == [(MRT_EVENT_WRONG_IF, 3)]
    clock.now += 3
    emulator.observe(AF4, udp_data(), 3)
    assert recorder.events == [(MRT_EVENT_WRONG_IF, 3)] * 2


def test_emulation_dl_timer() -> None:
    emulator, routes, recorder, clock = make_emulator()
    # Drop route created by traffic: removed once the traffic stops.
    route = add_route(
        emulator, routes, SOURCE, 2, [], MRT_FLAG_DUMMY | MRT_FLAG_DL_TIMER
    )
    for _ in range(4):
        clock.now += 2
        emulator.observe(AF4, udp_data(), 2)
        emulator.tick()
    assert recorder.removed == []

    clock.now += 5
    emulator.tick()
    assert recorder.removed == [route] and not route.installed


def test_emulation_registers() -> None:
    emulator, routes, recorder, _ = make_emulator()
    # FHR: the traffic goes in registers.
    add_route(emulator, routes, SOURCE, 2, [PIM_REG_IF_IDX], MRT_FLAG_RESTART_DL_TIMER)
    emulator.observe(AF4, udp_data(), 2)
    emulator.observe(AF4, udp_data(), 3)
    assert recorder.registers == [udp_data()]

    # RP: registers are forwarded while the route input is `pimreg`.
    emulator.register_received(AF4, udp_data())
    assert recorder.decapsulated == []
    add_route(emulator, routes, SOURCE, PIM_REG_IF_IDX, [4])
    emulator.register_received(AF4, udp_data())
    assert recorder.decapsulated == [udp_data()]


#
# Commands.
#
def test_commands() -> None:
    daemon = Daemon(parse_args(["-n", "-p", "ipv4:127.0.0.1"]), 1)

    text = console.run_captured(daemon.command, "mrt data-start 10.0.0.1 239.1.1.1 2")
    assert "pim: not connected, drop DATA_START if 2 SG(10.0.0.1, 239.1.1.1)" in text

    text = console.run_captured(daemon.command, "mrt6 join-spt 2001:db8::1 ff05::1 0x3")
    assert "drop JOIN_SPT if 3 SG(2001:db8::1, ff05::1)" in text

    assert "check inputs please" in console.run_captured(
        daemon.command, "mrt data-stop 10.0.0.1 x 2"
    )
    assert "unrecognized input: foo" in console.run_captured(daemon.command, "foo")
    assert console.run_captured(daemon.command, "   ") == ""

    # `show` and `debug`.
    assert '"connected": false' in console.run_captured(
        daemon.command, "show connections json"
    )
    assert '"emulation": false' in console.run_captured(
        daemon.command, "show flows json"
    )
    assert "debug emulation on" in console.run_captured(
        daemon.command, "debug emulation"
    )
    assert "emulation: on" in console.run_captured(daemon.command, "debug")
    console.run_captured(daemon.command, "debug all off")
    assert "unknown command: show nothing" in console.run_captured(
        daemon.command, "show nothing"
    )


if __name__ == "__main__":
    sys.exit(
        pytest.main(
            [
                os.path.abspath(__file__),
                "-q",
                "-p",
                "no:cacheprovider",
                "--noconftest",
                "-c",
                os.devnull,
            ]
            + sys.argv[1:]
        )
    )
