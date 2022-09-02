#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
pcap-ng file writer

At the time of writing, scapy has just gotten a pcap-ng writer added, but it
is not contained in any release yet.  It is also fairly rudimentary, e.g. not
supporting proper interface descriptions, encoding log messages, or additional
options.

Since pcap-ng is a fairly simple file format, the easiest approach here is to
just have our own encoder.  The format is described in
draft-tuexen-opsawg-pcapng (-04 as of writing.)
"""

from enum import IntEnum
from collections import namedtuple
import struct
import os
import hashlib

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import (
    Any,
    BinaryIO,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
)


_EndianType = Union[Literal["<"], Literal[">"]]


def _pad(data: bytes) -> bytes:
    pad = b"\0" * (4 - ((len(data) % 4) or 4))
    return data + pad


class DLT(IntEnum):
    """
    pcap DLTs (Data Link Types?)

    Consult ``/usr/include/pcap/dlt.h`` on a computer near you.  Only
    "interesting" types are picked out here.
    """

    NULL = 0
    EN10MB = 1
    """
    Plain Ethernet, 99% of use cases
    """

    PPP = 9
    IEEE802_11 = 105
    IEEE802_11_RADIO = 127
    MPLS = 219
    IPV4 = 228
    IPV6 = 229
    WIRESHARK_UPPER_PDU = 252
    NETLINK = 253
    VPP_DISPATCH = 280


class Context:
    """
    General setup bits for what becomes one pcap-ng file.

    TBD: decide whether this is a good place to put interface ID / description
    setup.
    """

    endian: _EndianType
    ifaces: Dict[str, int]
    _frame_num: int = 0

    def __init__(self, endian: _EndianType):
        super().__init__()
        self.endian = endian
        self.ifaces = {}

    def pack(self, spec, *args):
        """
        Helper for all the output to grab the right endianness.

        Note that pcap-ng endianness has no effect on the encoded packets,
        those are always in network byte order.  This is just for pcap-ng
        block headers and options.
        """
        return struct.pack(self.endian + spec, *args)

    def take_frame_num(self):
        self._frame_num += 1
        return self._frame_num


class Option(ABC):
    """
    TLVs at the end of :py:class:`Block`

    Insert into :py:attr:`Block.options` with plain old append.
    """

    code: ClassVar[int]
    """
    Option code as documented in pcap-ng spec.  Note that options 0 and 1 are
    general, but further options are specific to the block type.
    """

    @abstractmethod
    def _encode(self, context: Context) -> bytes:
        raise NotImplementedError()

    def encode(self, context: Context) -> bytes:
        encoded = self._encode(context)
        header = context.pack("HH", self.code, len(encoded))
        return header + _pad(encoded)


@dataclass
class TextOption(Option):
    text: str

    def _encode(self, context: Context):
        return self.text.encode("UTF-8")


@dataclass
class BinOption(Option):
    data: bytes

    def _encode(self, context: Context):
        return self.data


class TupleOption(Option, Tuple):
    """
    Use this to encode structured pcap-ng options (including integers.)

    To use, create a subclass of this class plus namedtuple, and place the
    struct pack specification into :py:attr:`encoding`, e.g.::

       class OptTSResol(TupleOption, namedtuple("TSResol", ("ts_resol",))):
           code = 9
           encoding = "B"
    """

    encoding: ClassVar[str]
    """
    Packing specification string.  Note the order must match the order of
    fields in the named tuple.
    """

    def _encode(self, context: Context):
        return context.pack(self.encoding, *self)


class Block(ABC):
    """
    pcap-ng Block.  A pcap-ng file is a sequence of these.
    """

    block_type: ClassVar[int]
    options: List[Option]

    class OptComment(TextOption):
        """
        Comment option - valid for all blocks.  May occur multiple times.
        """

        code = 1

    def __init__(self):
        self.__post_init__()

    def __post_init__(self):
        """
        dataclass post-init; just sets up an empty options list.
        """
        self.options = []

    @abstractmethod
    def _data(self, context: Context) -> bytes:
        raise NotImplementedError()

    def encode(self, context: Context):
        """
        Produce output for this block.

        Should be called through :py:meth:`Sink.write`.
        """
        data = _pad(self._data(context))

        if self.options:
            eoo = b"\0" * 4
            options = b"".join([opt.encode(context) for opt in self.options]) + eoo
        else:
            options = b""

        blklen = len(data) + len(options) + 12
        return (
            context.pack("II", self.block_type, blklen)
            + data
            + options
            + context.pack("I", blklen)
        )


class SectionHeader(Block):
    """
    pcap-ng Section Header - one section is one continuous capture.

    Most pcap-ng files would only have one of these.  Multi-capture files are
    pretty rare, but just concatenating two pcap-ng files creates a valid
    multi-capture file.
    """

    block_type = 0x0A0D0D0A
    bom_magic = 0x1A2B3C4D
    version = (1, 0)

    class OptHardware(TextOption):
        code = 2

    class OptOS(TextOption):
        code = 3

    class OptUserAppl(TextOption):
        code = 4

    def __init__(self, *, uname=None):
        super().__init__()
        self.options.append(self.OptOS(uname or " ".join(os.uname())))
        self.options.append(self.OptUserAppl("topotato"))

    def _data(self, context: Context) -> bytes:
        return context.pack(
            "IHHq", self.bom_magic, self.version[0], self.version[1], -1
        )


@dataclass
class IfDesc(Block):
    """
    Interface description block - must precede the use of its interface index.

    Interfaces are numbered starting at zero in order of their description
    blocks in the file.  It is not possible to change or reorder these indexes
    in any way.  The ID for the description block is not actually contained in
    the block itself, so the calling code must keep track of which description
    was output in which order.

    IDBs may appear mixed in between packets, i.e. can be emitted lazily the
    first time an interface shows up with a packet.
    """

    block_type = 0x01
    linktype: DLT = DLT.EN10MB
    snaplen: int = 262144

    class OptName(TextOption):
        code = 2

    class OptDescription(TextOption):
        code = 3

    # 4: IPv4addr
    # 5: IPv6addr
    # 6: MACaddr
    # 7: EUIaddr
    # 8: speed

    class OptTSResol(TupleOption, namedtuple("TSResol", ("ts_resol",))):
        """
        Timestamp resolution for all timestamps on this interface.

        Positive value: power of 10 digits after the dot, e.g. 3 = millisec.

        Negative value: number of bits after the dot, e.g. 2 = quarter second.

        Note that this is stateful and must be kept track of for all packet
        blocks emitted that use this interface.
        """

        code = 9
        encoding = "B"

    # 10: tzone
    # 11: filter

    class OptOS(TextOption):
        code = 12

    # 13: fcslen
    # 14: tsoffset

    class OptHardware(TextOption):
        code = 15

    # 16: txspeed
    # 17: rxspeed

    def _data(self, context: Context) -> bytes:
        return context.pack("HHI", self.linktype, 0, self.snaplen)


@dataclass
class EnhancedPacket(Block):
    """
    Actual packet captured on some network interface.
    """

    block_type = 0x06

    iface_id: int
    """
    Number (in file order) of :py:class:`IfDesc` that set up the interface for
    this packet.
    """
    timestamp: int
    """
    Unix timestamp for this packet, resolution defaults to microseconds but
    can be changed with :py:class:`IfDesc.OptTSResol`.
    """
    packet: bytes
    orig_len: Optional[int] = None

    # 2: flags

    class OptHash(BinOption):
        code = 3

    # 4: dropcount

    class OptPacketID(TupleOption, namedtuple("PacketID", ("packet_id",))):
        """
        Packet IDs for cases where the same packet is seen multiple times.

        The description of this option gives as example a situation where
        a packet is forwarded and therefore both seen on receive and transmit.
        Those packets would have the same ID.

        That said, this ID is accessible as a field in wireshark and thus
        useful even if there's never two packets with the same ID.
        """

        code = 5
        encoding = "Q"

    # 6: queue
    # 7: verdict

    def add_hash(self):
        hval = hashlib.sha1(self.packet).digest()
        self.options.append(self.OptHash(b"\x04" + hval))

    def _data(self, context: Context) -> bytes:
        return (
            context.pack(
                "IIIII",
                self.iface_id,
                self.timestamp >> 32,
                self.timestamp & 0xFFFFFFFF,
                len(self.packet),
                self.orig_len or len(self.packet),
            )
            + self.packet
        )


class JournalExport(Block, dict[str, Any]):
    """
    Log message representation in pcap-ng files.

    This uses systemd's journal export format with key-value pairs.  Being a
    subclass of ``dict``, construct and/or modify as if it were a dict.

    A ``__REALTIME_TIMESTAMP`` field is needed with the unix timestamp.  Sadly
    this is always microseconds precision, no way to output nanoseconds.
    """

    block_type = 0x09

    def __init__(self, *args, **kwargs):
        # explicitly route args to appropriate parent class
        dict.__init__(self, *args, **kwargs)
        Block.__init__(self)

    def _data(self, context: Context) -> bytes:
        def field_enc(key, data):
            key = key.encode("UTF-8")
            if not isinstance(data, bytes):
                data = str(data).encode("UTF-8")

            for i in data:
                if i < 32 and i != 9:
                    # binary journal export encoding
                    return key + b"\n" + struct.pack("<Q", len(data)) + data + b"\n"

            # valid UTF-8 without CR/LF/other control chars
            return key + b"=" + data + b"\n"

        return b"".join([field_enc(*item) for item in sorted(self.items())])


class Sink(Context):
    """
    Actual writable pcap-ng sink, i.e. file (or pipe)

    This is a subclass of :py:class:`Context` since a pcap-ng file needs a
    Context anyway, and making that indirect serves no purpose.
    """

    fd: BinaryIO

    def __init__(self, fd: BinaryIO, endian: _EndianType):
        super().__init__(endian)
        self.fd = fd

    def write(self, block: Block):
        self.fd.write(block.encode(self))

    def flush(self):
        self.fd.flush()

    def close(self):
        self.fd.close()
        self.fd = None
