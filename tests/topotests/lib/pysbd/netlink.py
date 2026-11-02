# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Netlink message helpers and the netlink connection that follows the
interfaces and their IPv4 addresses (and installs FPM routes when asked).
"""

from __future__ import annotations

import asyncio
import errno
import os
import socket
import struct
from typing import Dict, Iterator, List, Optional, Tuple

from .common import (
    Buffer,
    debug_netlink,
    err,
    fatal,
    ntop4,
    out,
    warn,
    warn_ratelimited,
)
from .interface import Interfaces

NLMSG_HEADER = struct.Struct("=IHHII")
RTA_HEADER = struct.Struct("=HH")
IFINFOMSG = struct.Struct("=BxHiII")
IFADDRMSG = struct.Struct("=BBBBI")
RTMSG = struct.Struct("=BBBBBBBBI")
RTNEXTHOP = struct.Struct("=HBBi")

NLMSG_ERROR = 2
NLMSG_DONE = 3
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_GETLINK = 18
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_GETADDR = 22
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29

NLM_F_REQUEST = 0x01
NLM_F_MULTI = 0x02
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200

NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000
NLA_TYPE_MASK = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER) & 0xFFFF

IFLA_IFNAME = 3
IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_LABEL = 3

RTMGRP_LINK = 0x1
RTMGRP_NEIGH = 0x4
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV4_MROUTE = 0x20
RTMGRP_IPV4_ROUTE = 0x40
RTMGRP_IPV6_IFADDR = 0x100
RTMGRP_IPV6_MROUTE = 0x200
RTMGRP_IPV6_ROUTE = 0x400
RTNLGRP_IPV4_RULE = 8
RTNLGRP_IPV6_RULE = 19

SOCKET_BUFFER_SIZE = 90 * 1024 * 1024

#: Dump sequence numbers start here (FPM messages keep zebra's ones).
DUMP_SEQUENCE_BASE = 0x7F000000

MESSAGE_NAMES = {
    NLMSG_ERROR: "NLMSG_ERROR",
    NLMSG_DONE: "NLMSG_DONE",
    RTM_NEWLINK: "RTM_NEWLINK",
    RTM_DELLINK: "RTM_DELLINK",
    RTM_GETLINK: "RTM_GETLINK",
    RTM_NEWADDR: "RTM_NEWADDR",
    RTM_DELADDR: "RTM_DELADDR",
    RTM_GETADDR: "RTM_GETADDR",
    RTM_NEWROUTE: "RTM_NEWROUTE",
    RTM_DELROUTE: "RTM_DELROUTE",
    RTM_GETROUTE: "RTM_GETROUTE",
    RTM_NEWNEIGH: "RTM_NEWNEIGH",
    RTM_DELNEIGH: "RTM_DELNEIGH",
}


def nl_align(length: int) -> int:
    return (length + 3) & ~3


class NetlinkMessage:
    def __init__(self, data: bytes) -> None:
        self.data = data
        (
            self.length,
            self.type,
            self.flags,
            self.seq,
            self.pid,
        ) = NLMSG_HEADER.unpack_from(data)

    @property
    def payload(self) -> bytes:
        return self.data[NLMSG_HEADER.size : self.length]


def nlmsg_iter(buffer: Buffer) -> Iterator[NetlinkMessage]:
    """Iterate over the netlink messages in a buffer (`NLMSG_OK`)."""
    offset = 0
    while len(buffer) - offset >= NLMSG_HEADER.size:
        (length,) = struct.unpack_from("=I", buffer, offset)
        if length < NLMSG_HEADER.size or length > len(buffer) - offset:
            break

        yield NetlinkMessage(bytes(buffer[offset : offset + length]))
        offset += nl_align(length)


def rta_iter(
    buffer: Buffer, offset: int = 0, end: Optional[int] = None
) -> Iterator[Tuple[int, bytes]]:
    """Iterate over (type, payload) netlink attributes (`RTA_OK`)."""
    if end is None:
        end = len(buffer)

    while end - offset >= RTA_HEADER.size:
        length, rta_type = RTA_HEADER.unpack_from(buffer, offset)
        if length < RTA_HEADER.size or length > end - offset:
            break

        yield rta_type, bytes(buffer[offset + RTA_HEADER.size : offset + length])
        offset += nl_align(length)


def nlmsg_build(
    msg_type: int, flags: int, seq: int, body: bytes, pid: int = 0
) -> bytes:
    return (
        NLMSG_HEADER.pack(NLMSG_HEADER.size + len(body), msg_type, flags, seq, pid)
        + body
    )


def rta_build(rta_type: int, payload: bytes) -> bytes:
    length = RTA_HEADER.size + len(payload)
    return (
        RTA_HEADER.pack(length, rta_type) + payload + bytes(nl_align(length) - length)
    )


def nl_dump(buffer: Buffer, is_input: bool, target: str) -> None:
    """Print a short description of the netlink messages in `buffer`."""
    for msg in nlmsg_iter(buffer):
        out(
            "[{}] {} {} len:{} flags:0x{:04x} seq:{} pid:{}".format(
                target,
                "<=" if is_input else "=>",
                MESSAGE_NAMES.get(msg.type, "type-{}".format(msg.type)),
                msg.length,
                msg.flags,
                msg.seq,
                msg.pid,
            )
        )

        if msg.type in (RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE):
            header_size = RTMSG.size
        elif msg.type in (RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK):
            header_size = IFINFOMSG.size
        elif msg.type in (RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR):
            header_size = IFADDRMSG.size
        else:
            continue

        payload = msg.payload
        if len(payload) < header_size:
            continue

        out("  family:{}".format(payload[0]))
        for rta_type, data in rta_iter(payload, header_size):
            out("  attribute type:{} length:{}".format(rta_type, len(data)))


def parse_link(msg: NetlinkMessage) -> Optional[Tuple[int, str]]:
    """(index, name) of a link message."""
    payload = msg.payload
    if len(payload) < IFINFOMSG.size:
        return None

    _, _, index, _, _ = IFINFOMSG.unpack_from(payload)
    for rta_type, data in rta_iter(payload, IFINFOMSG.size):
        if rta_type == IFLA_IFNAME:
            name = data.split(b"\0", 1)[0].decode(errors="replace")
            if name:
                return index, name
    return None


def parse_address(msg: NetlinkMessage) -> Optional[Tuple[int, bytes]]:
    """(interface index, address) of an IPv4 address message."""
    payload = msg.payload
    if len(payload) < IFADDRMSG.size:
        return None

    family, _, _, _, index = IFADDRMSG.unpack_from(payload)
    if family != socket.AF_INET:
        return None

    # IFA_LOCAL is the interface address (IFA_ADDRESS the peer on point to
    # point links).
    address = None
    for rta_type, data in rta_iter(payload, IFADDRMSG.size):
        if rta_type == IFA_LOCAL and len(data) >= 4:
            address = data[:4]
        elif rta_type == IFA_ADDRESS and len(data) >= 4 and address is None:
            address = data[:4]
    if address is None:
        return None
    return index, address


class NetlinkMonitor:
    """
    Follows the links and IPv4 addresses: a dump at start (and after
    notifications were lost), notifications afterwards.
    """

    def __init__(self, interfaces: Interfaces, loop: asyncio.AbstractEventLoop) -> None:
        self.interfaces = interfaces
        self.loop = loop
        self.sock: Optional[socket.socket] = None
        #: Port id the kernel assigned to the socket.
        self.pid = 0
        self.write_queue: List[bytes] = []
        self.writing = False

        #: Running dump: None, "links" or "addresses".
        self.dumping: Optional[str] = None
        self.dump_seq = DUMP_SEQUENCE_BASE
        self.dump_links: Dict[int, str] = {}
        self.dump_addresses: Dict[int, List[bytes]] = {}
        #: Notifications were lost during the running dump: do another.
        self.resync_pending = False
        #: Number of dumps done (the first one is at start).
        self.dumps = 0

    def start(self) -> None:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, socket.NETLINK_ROUTE)
        sock.bind((0, RTMGRP_LINK | RTMGRP_IPV4_IFADDR))
        self.pid = sock.getsockname()[0]
        sock.setblocking(False)

        # Increase receive buffer to avoid overruns.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
        except OSError:
            err("netlink_init: failed to increase socket buffer size")

        self.sock = sock
        self.loop.add_reader(sock, self._read)
        self.resync()

    #
    # Dumps.
    #
    def resync(self) -> None:
        """Dump the links and then the addresses, and apply the differences."""
        if self.dumping is not None:
            self.resync_pending = True
            return

        self.dumping = "links"
        self.dump_links = {}
        self._dump_request(RTM_GETLINK, socket.AF_UNSPEC)

    def _dump_request(self, msg_type: int, family: int) -> None:
        assert self.sock is not None
        self.dump_seq += 1
        message = nlmsg_build(
            msg_type,
            NLM_F_REQUEST | NLM_F_ROOT,
            self.dump_seq,
            IFINFOMSG.pack(family, 0, 0, 0, 0),
        )
        try:
            self.sock.sendto(message, (0, 0))
        except OSError as error:
            fatal("netlink dump request", error)

    def _dump_reply(self, msg: NetlinkMessage) -> None:
        if msg.type == RTM_NEWLINK and self.dumping == "links":
            link = parse_link(msg)
            if link:
                self.dump_links[link[0]] = link[1]
        elif msg.type == RTM_NEWADDR and self.dumping == "addresses":
            address = parse_address(msg)
            if address:
                addresses = self.dump_addresses.setdefault(address[0], [])
                if address[1] not in addresses:
                    addresses.append(address[1])
        elif msg.type in (NLMSG_DONE, NLMSG_ERROR):
            if msg.type == NLMSG_ERROR:
                warn("netlink {} dump failed".format(self.dumping))
            self._dump_done()

    def _dump_done(self) -> None:
        if self.dumping == "links":
            self.interfaces.sync_links(self.dump_links)
            self.dumping = "addresses"
            self.dump_addresses = {}
            self._dump_request(RTM_GETADDR, socket.AF_INET)
            return

        self.interfaces.sync_addresses(self.dump_addresses)
        self.dumping = None
        self.dumps += 1
        if self.resync_pending:
            self.resync_pending = False
            self.resync()

    #
    # Notifications: also applied to the running dump, which may have
    # already reported the old state.
    #
    def _notification(self, msg: NetlinkMessage) -> None:
        if msg.type == RTM_NEWLINK:
            link = parse_link(msg)
            if link is None:
                return
            if self.dumping == "links":
                self.dump_links[link[0]] = link[1]
            self.interfaces.link(*link)
        elif msg.type == RTM_DELLINK:
            link = parse_link(msg)
            if link is None:
                return
            if self.dumping == "links":
                self.dump_links.pop(link[0], None)
            self.interfaces.unlink(link[0])
        elif msg.type in (RTM_NEWADDR, RTM_DELADDR):
            address = parse_address(msg)
            if address is None:
                return
            index, value = address
            if self.dumping == "addresses":
                addresses = self.dump_addresses.setdefault(index, [])
                if msg.type == RTM_DELADDR:
                    if value in addresses:
                        addresses.remove(value)
                elif value not in addresses:
                    addresses.append(value)

            if debug_netlink():
                out(
                    "[NETLINK] {} {} index {}".format(
                        MESSAGE_NAMES[msg.type], ntop4(value), index
                    )
                )
            if msg.type == RTM_NEWADDR:
                self.interfaces.address_add(index, value)
            else:
                self.interfaces.address_del(index, value)

    #
    # Socket.
    #
    def enqueue(self, data: Buffer) -> None:
        """Send a message to the kernel (FPM routes and neighbors)."""
        self.write_queue.append(bytes(data))
        self._write()

    def _write(self) -> None:
        assert self.sock is not None
        while self.write_queue:
            try:
                bytes_written = self.sock.sendto(self.write_queue[0], (0, 0))
            except (BlockingIOError, InterruptedError):
                if not self.writing:
                    self.writing = True
                    self.loop.add_writer(self.sock, self._write)
                return
            except OSError as error:
                warn_ratelimited("netlink-write", "netlink: write", error)
                bytes_written = 0

            if debug_netlink():
                out("netlink_write: bytes written: {}".format(bytes_written))
            self.write_queue.pop(0)

        if self.writing:
            self.writing = False
            self.loop.remove_writer(self.sock)

    def _read(self) -> None:
        assert self.sock is not None
        try:
            data, _, flags, _ = self.sock.recvmsg(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as error:
            if error.errno == errno.ENOBUFS:
                warn("netlink: notifications lost, resynchronizing")
                self.resync()
                return
            fatal("netlink_read: read", error)

        if not data:
            fatal("netlink_read: read: connection closed")
        if flags & socket.MSG_TRUNC:
            err("netlink_read: message truncated")

        if debug_netlink():
            out("netlink_read: bytes read: {}".format(len(data)))

        for msg in nlmsg_iter(data):
            self._handle(msg)

    def _handle(self, msg: NetlinkMessage) -> None:
        if msg.pid != self.pid:
            self._notification(msg)
        elif self.dumping is not None and msg.seq == self.dump_seq:
            self._dump_reply(msg)
        elif msg.type == NLMSG_ERROR and len(msg.payload) >= 4:
            # Answer to a message we installed (zebra's sequence number).
            (code,) = struct.unpack_from("=i", msg.payload)
            if code:
                warn_ratelimited(
                    "netlink-error-{}".format(-code),
                    "netlink: kernel refused a message (seq {}): {}".format(
                        msg.seq, os.strerror(-code)
                    ),
                )
