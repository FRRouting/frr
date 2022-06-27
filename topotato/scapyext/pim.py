#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2021  David Lamparter for NetDEF, Inc.
"""
Scapy PIM support.

Only Bootstrap & Candidate RP messages right now (because I needed those...)
"""
# pylint: disable=unused-argument

import socket
import struct
from enum import Enum
from typing import ClassVar

from scapy.packet import bind_layers, Packet  # type: ignore
from scapy.fields import (  # type: ignore
    Field,
    BitField,
    BitEnumField,
    ByteField,
    DestIP6Field,
    FieldLenField,
    FieldListField,
    PacketListField,
    ShortField,
    XShortField,
    StrLenField,
)
from scapy.layers.inet import IP, DestIPField  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore
from scapy.utils import checksum  # type: ignore
from scapy.volatile import RandShort  # type: ignore
from scapy.error import Scapy_Exception  # type: ignore
from scapy.pton_ntop import inet_ntop, inet_pton  # type: ignore


class PIM_Types(Enum):
    Hello = 0
    Bootstrap = 4
    CandidateRP = 8


_PIM_Types = {v.value: k for k, v in PIM_Types.__members__.items()}


class _PIMEncodedAddrField(Field):
    """
    Common base for the various PIM "Encoded-Address" formats.
    """

    hdr_size: ClassVar[int]

    def m2i(self, pkt, x):
        hsz, asz, _ = self._addr_size(x)

        afi = struct.unpack("B", x[:1])[0]
        addr = x[hsz : hsz + asz]

        if afi == 1:
            text = inet_ntop(socket.AF_INET, addr)
        elif afi == 2:
            text = inet_ntop(socket.AF_INET6, addr)
        else:
            raise ValueError(afi)

        return self.sub_m2i(pkt, x[2:hsz], text)

    def i2m(self, pkt, x):
        if isinstance(x, bytes):
            return x
        sub, x = self.sub_i2m(pkt, x)
        if ":" in x:
            return struct.pack("BB", 2, 0) + sub + inet_pton(socket.AF_INET6, x)
        return struct.pack("BB", 1, 0) + sub + inet_pton(socket.AF_INET, x)

    def _addr_size(self, x):
        afi, enc = struct.unpack("BB", x[:2])

        if afi == 1:  # IP
            sz = 4
        elif afi == 2:  # IPv6
            sz = 16
        else:
            raise Scapy_Exception("Unknown AFI %d" % afi)

        if enc == 0:
            return (2 + self.hdr_size, sz, 0)
        if enc == 1:
            raise Scapy_Exception("PIM Join Attributes not supported")

        raise Scapy_Exception("Unknown encoding %d" % enc)

    def size(self, x):
        return sum(self._addr_size(x))

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        tmp_len = self.size(s)
        return s[tmp_len:], self.i2m(pkt, s[:tmp_len])

    # pylint: disable=no-self-use
    def sub_m2i(self, pkt, x, text):
        return text

    # pylint: disable=no-self-use
    def sub_i2m(self, pkt, x):
        return b"", x


class PIMEncodedAddrField(_PIMEncodedAddrField):
    hdr_size = 0


class PIMEncodedPrefixField(_PIMEncodedAddrField):
    hdr_size = 2

    def sub_m2i(self, pkt, x, text):
        flags, masklen = struct.unpack("BB", x)
        text = "%s/%d" % (text, masklen)
        if flags & 0x80:
            text += ",B"
            flags &= ~0x80
        if flags & 0x01:
            text += ",Z"
            flags &= ~0x01
        if flags:
            text += ",0x%02x" % flags
        return text

    def sub_i2m(self, pkt, x):
        flags = 0
        while "," in x:
            x, flag = x.rsplit(",", 1)
            if flag.upper() == "B":
                flags |= 0x80
            elif flag.upper() == "Z":
                flags |= 0x01
            else:
                flags |= int(flag, 0)

        x, masklen = x.rsplit("/", 1)

        return struct.pack("BB", flags, int(masklen)), x


# class PIMEncodedSourceField(_PIMEncodedAddrField):

from scapy.layers.inet6 import in6_chksum


class PIM_Hdr(Packet):
    name = "PIM Header"
    fields_desc = [
        BitField("version", 2, 4),
        BitEnumField("type", 0, 4, _PIM_Types),
        ByteField("reserved", 0),
        XShortField("chksum", None),
    ]

    def post_build(self, pkt, pay):
        pkt += pay
        if self.chksum is None:
            if True:
                ck = in6_chksum(IPPROTO_PIM, self.underlayer, pkt)
            else:
                ck = checksum(pkt)
            pkt = pkt[:2] + struct.pack("!H", ck) + pkt[4:]
        return pkt


class PIM_Hello_Option(Packet):
    name = "Generic PIM Hello Option/TLV"

    fields_desc = [ShortField("type", 0),
                   FieldLenField("len", None, length_of="data", fmt="H"),
                   StrLenField("data", b"", length_from=lambda pkt: pkt.len)]

    def extract_padding(self, p):
        return b"", p

    _reg = {}

    @classmethod
    def register_variant(cls):
        cls._reg[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            tmp_type = struct.unpack(pkt[:2], ">H")[0]
            return cls._reg.get(tmp_type, cls)
        return cls


class PIM_Hello_Option_HoldTime(PIM_Hello_Option):
    name = "PIM Hello Holdtime TLV"
    fields_desc = [ShortField("type", 1),
                   ShortField("len", 2),
                   ShortField("holdtime", 105)]


class PIM_Hello(Packet):
    name = "PIM Hello"
    fields_desc = [
        PacketListField("options", [], PIM_Hello_Option),
    ]

    def post_build(self, pkt, pay):
        pkt += pay
        return pkt


class PIM_Bootstrap_RP(Packet):
    name = "PIM Bootstrap Group RP entry"

    fields_desc = [
        PIMEncodedAddrField("address", "0.0.0.0"),
        ShortField("holdtime", 0),
        ByteField("priority", 128),
        ByteField("reserved", 0),
    ]

class PIM_Bootstrap_Group(Packet):
    name = "PIM Bootstrap Group mapping entry"

    fields_desc = [
        PIMEncodedPrefixField("group", "0.0.0.0/0"),
        ByteField("rp_count", 0),
        FieldLenField("frag_count", None, count_of="rps", fmt="B"),
        ShortField("reserved", 0),
        PacketListField("rps", [], PIM_Bootstrap_RP,
                        count_from=lambda pkt: pkt.frag_count)
    ]

class PIM_Bootstrap(Packet):
    name = "PIM Bootstrap"
    fields_desc = [
        XShortField("fragmenttag", None),
        ByteField("hashmasklen", 24),
        ByteField("priority", 64),
        PIMEncodedAddrField("address", "0.0.0.0"),
        PacketListField("groups", [], PIM_Bootstrap_Group),
    ]

    def post_build(self, pkt, pay):
        if self.fragmenttag is None:
            pkt = struct.pack("!H", RandShort()) + pkt[2:]
        pkt += pay
        return pkt


class PIM_CandidateRP(Packet):
    name = "PIM Candidate-RP"
    fields_desc = [
        ByteField("prefixcount", None),
        ByteField("priority", 192),
        ShortField("holdtime", 150),
        PIMEncodedAddrField("address", "0.0.0.0"),
        FieldListField(
            "groups",
            [],
            PIMEncodedPrefixField("group", "224.0.0.0/4"),
            count_from=lambda pkt: pkt.prefixcount,
        ),
    ]

    def post_build(self, pkt, pay):
        if self.prefixcount is None:
            pkt = struct.pack("B", len(self.groups)) + pkt[1:]
        pkt += pay
        return pkt


IPPROTO_PIM = 103
PIM_IPV4_GROUP = "224.0.0.13"
PIM_IPV6_GROUP = "ff02::d"

bind_layers(IP, PIM_Hdr, proto=IPPROTO_PIM)
DestIPField.bind_addr(PIM_Hdr, PIM_IPV4_GROUP)
bind_layers(IPv6, PIM_Hdr, nh=IPPROTO_PIM)
DestIP6Field.bind_addr(PIM_Hdr, PIM_IPV6_GROUP)

bind_layers(PIM_Hdr, PIM_Hello, type=PIM_Types.Hello.value)
bind_layers(PIM_Hdr, PIM_Bootstrap, type=PIM_Types.Bootstrap.value)
bind_layers(PIM_Hdr, PIM_CandidateRP, type=PIM_Types.CandidateRP.value)
