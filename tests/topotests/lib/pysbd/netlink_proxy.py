# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Netlink proxy (enabled with `-X`, used by the DPD zebra `-Y` option):
clients connected to the TCP port send netlink messages that are forwarded
to the kernel, and receive every kernel netlink message (replies and
notifications).
"""

from __future__ import annotations

import asyncio
import errno
import socket
import struct
from typing import Callable, List, Optional

from .common import (
    NETLINK_PROXY_PORT,
    Buffer,
    debug_netlink_proxy,
    debug_netlink_proxy_dump,
    err,
    fatal,
    out,
    pton,
    warn,
    warn_ratelimited,
)
from .netlink import (
    IFA_ADDRESS,
    IFADDRMSG,
    NLMSG_HEADER,
    RTM_DELADDR,
    RTM_NEWADDR,
    RTMGRP_IPV4_IFADDR,
    RTMGRP_IPV4_MROUTE,
    RTMGRP_IPV4_ROUTE,
    RTMGRP_IPV6_IFADDR,
    RTMGRP_IPV6_MROUTE,
    RTMGRP_IPV6_ROUTE,
    RTMGRP_LINK,
    RTMGRP_NEIGH,
    RTNLGRP_IPV4_RULE,
    RTNLGRP_IPV6_RULE,
    SOCKET_BUFFER_SIZE,
    nl_dump,
    nlmsg_build,
    rta_build,
)

NETLINK_GROUPS = (
    RTMGRP_LINK
    | RTMGRP_NEIGH
    | RTMGRP_IPV4_IFADDR
    | RTMGRP_IPV4_ROUTE
    | RTMGRP_IPV4_MROUTE
    | (1 << (RTNLGRP_IPV4_RULE - 1))
    | RTMGRP_IPV6_IFADDR
    | RTMGRP_IPV6_ROUTE
    | RTMGRP_IPV6_MROUTE
    | (1 << (RTNLGRP_IPV6_RULE - 1))
)


class ProxyClient:
    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self.writer = writer
        sock = writer.get_extra_info("socket")
        self.fd = sock.fileno() if sock is not None else -1


class NetlinkProxy:
    """`own_pid` returns the main netlink socket port id: the notifications
    its messages cause (FPM routes installation) are not forwarded."""

    def __init__(
        self, loop: asyncio.AbstractEventLoop, own_pid: Callable[[], int]
    ) -> None:
        self.loop = loop
        self.own_pid = own_pid
        self.sock: Optional[socket.socket] = None
        self.server: Optional[asyncio.AbstractServer] = None
        self.clients: List[ProxyClient] = []
        self.write_queue: List[bytes] = []
        self.writing = False

    async def start(self) -> None:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, socket.NETLINK_ROUTE)
        try:
            sock.bind((0, NETLINK_GROUPS))
        except OSError as error:
            fatal("netlink proxy: bind", error)
        sock.setblocking(False)

        # Increase receive buffer to avoid overruns.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
        except OSError:
            err("netlink proxy: failed to increase socket buffer size")

        self.sock = sock
        self.loop.add_reader(sock, self._read)

        try:
            self.server = await asyncio.start_server(
                self._accept,
                host="127.0.0.1",
                port=NETLINK_PROXY_PORT,
                family=socket.AF_INET,
                reuse_address=True,
            )
        except OSError as error:
            fatal("netlink proxy: listen", error)

        out("listening for netlink proxy connections")

    def close(self) -> None:
        if self.server is not None:
            self.server.close()

    def _read(self) -> None:
        assert self.sock is not None
        try:
            data, _, flags, _ = self.sock.recvmsg(65535)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as error:
            if error.errno == errno.ENOBUFS:
                warn("netlink proxy: notifications lost")
                return
            fatal("netlink proxy: read", error)

        if not data:
            fatal("netlink proxy: read: connection closed")
        if flags & socket.MSG_TRUNC:
            err("netlink proxy: message truncated")

        if debug_netlink_proxy():
            out("netlink proxy: bytes read: {}".format(len(data)))
        if debug_netlink_proxy_dump():
            nl_dump(data, True, "southbound/IFM")

        if len(data) >= NLMSG_HEADER.size:
            (pid,) = struct.unpack_from("=I", data, 12)
            if pid != 0 and pid == self.own_pid():
                if debug_netlink_proxy() or debug_netlink_proxy_dump():
                    out("netlink proxy: ignoring message with PID {}".format(pid))
                return

        self.enqueue_clients(data)

    def _kernel_enqueue(self, data: bytes) -> None:
        if debug_netlink_proxy():
            out("netlink proxy: enqueue netlink message ({}) bytes".format(len(data)))
        self.write_queue.append(data)
        self._write()

    def _write(self) -> None:
        assert self.sock is not None
        while self.write_queue:
            message = self.write_queue[0]
            try:
                bytes_written = self.sock.sendto(message, (0, 0))
            except (BlockingIOError, InterruptedError):
                if not self.writing:
                    self.writing = True
                    self.loop.add_writer(self.sock, self._write)
                return
            except OSError as error:
                warn_ratelimited("netlink-proxy-write", "netlink proxy: write", error)
                bytes_written = 0

            if debug_netlink_proxy_dump():
                nl_dump(message, False, "southbound/IFM")
            if debug_netlink_proxy():
                out(
                    "netlink proxy: bytes sent: {} (of {})".format(
                        bytes_written, len(message)
                    )
                )
            self.write_queue.pop(0)

        if self.writing:
            self.writing = False
            self.loop.remove_writer(self.sock)

    async def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        client = ProxyClient(writer)
        self.clients.append(client)
        out("netlink proxy: new client socket {}".format(client.fd))

        buffer = bytearray()
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break

                if debug_netlink_proxy():
                    out("netlink proxy: client read {} bytes".format(len(data)))

                buffer += data
                while len(buffer) >= NLMSG_HEADER.size:
                    (length,) = struct.unpack_from("=I", buffer)
                    if length < NLMSG_HEADER.size:
                        raise ValueError("invalid netlink message length")
                    # Check for enough available bytes.
                    if len(buffer) < length:
                        break

                    self._kernel_enqueue(bytes(buffer[:length]))
                    del buffer[:length]
        except (OSError, ValueError) as error:
            if debug_netlink_proxy():
                out("netlink proxy: client error: {}".format(error))
        finally:
            out("netlink proxy: client socket {} removed".format(client.fd))
            self.clients.remove(client)
            writer.close()

    def enqueue_clients(self, data: Buffer) -> None:
        """Send data to every proxy client."""
        for client in self.clients:
            if debug_netlink_proxy():
                out(
                    "netlink proxy: enqueue {} bytes for socket {}".format(
                        len(data), client.fd
                    )
                )
            if not client.writer.is_closing():
                client.writer.write(bytes(data))

    def enqueue_address(self, add: bool, address: bytes, ifindex: int) -> None:
        """Simulate an address notification to the proxy clients."""
        body = IFADDRMSG.pack(socket.AF_INET, 32, 0, 0, ifindex) + rta_build(
            IFA_ADDRESS, address
        )
        self.enqueue_clients(
            nlmsg_build(RTM_NEWADDR if add else RTM_DELADDR, 0, 0, body)
        )

    def stdin(self, tokens: List[str]) -> None:
        if len(tokens) >= 2 and tokens[0] == "address" and tokens[1] == "add":
            if len(tokens) < 4:
                out("unknown command: netlink {}".format(" ".join(tokens)))
                self._print_commands()
                return

            address = pton(socket.AF_INET, tokens[2])
            if address is None:
                out("invalid address: {}".format(tokens[2]))
                self._print_commands()
                return

            try:
                ifindex = int(tokens[3], 10)
            except ValueError:
                out("invalid interface index: {}".format(tokens[3]))
                self._print_commands()
                return
            if ifindex <= 0 or ifindex > 0xFFFFFFFF:
                out("invalid interface index: {} (out of range)".format(tokens[3]))
                self._print_commands()
                return

            self.enqueue_address(True, address, ifindex)
            return

        self._print_commands()

    def _print_commands(self) -> None:
        out("available commands:")
        out(" * netlink address add <address> <interface-index>")
