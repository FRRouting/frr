# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Stream connections with the daemons (pimd/pim6d events, zebra FPM): listen
or connect, one peer at a time.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Awaitable, Callable, Dict, Optional

from .common import SocketAddress, address_parse, err, out, set_keepalive

RECONNECT_INTERVAL = 3

#: Serves one connection until it ends.
Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class StreamEndpoint:
    """
    In listen mode a new connection replaces the current one (the peer
    restarted, or the old connection is half open). In connect mode the
    connection is retried every `RECONNECT_INTERVAL` seconds.

    `on_close` runs when a connection ends, before a replacing one is
    served.
    """

    def __init__(
        self,
        name: str,
        default_port: int,
        handler: Handler,
        on_close: Callable[[], None],
    ) -> None:
        self.name = name
        self.default_port = default_port
        self.handler = handler
        self.on_close = on_close
        self.writer: Optional[asyncio.StreamWriter] = None
        self.peer: Optional[str] = None
        self.address: Optional[str] = None
        self.is_client = False
        self._server: Optional[asyncio.AbstractServer] = None
        self._connect_task: Optional[asyncio.Future] = None
        self._serve_task: Optional[asyncio.Task] = None

    @property
    def connected(self) -> bool:
        return self.writer is not None and not self.writer.is_closing()

    async def start(self, address: str) -> None:
        family, sockaddr, self.is_client = address_parse(address, self.default_port)
        self.address = address

        if self.is_client:
            out("starting {} connection...".format(self.name))
            self._connect_task = asyncio.ensure_future(
                self._connect_loop(family, sockaddr)
            )
            return

        out("listening for {} connection...".format(self.name))
        if family == socket.AF_UNIX:
            assert isinstance(sockaddr, str)
            self._server = await asyncio.start_unix_server(self._accept, path=sockaddr)
        else:
            assert not isinstance(sockaddr, str)
            self._server = await asyncio.start_server(
                self._accept,
                host=sockaddr[0],
                port=sockaddr[1],
                family=family,
                reuse_address=True,
            )

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
        if self._connect_task is not None:
            self._connect_task.cancel()
        if self._serve_task is not None:
            self._serve_task.cancel()

    async def _connect_loop(self, family: int, sockaddr: SocketAddress) -> None:
        while True:
            try:
                if family == socket.AF_UNIX:
                    assert isinstance(sockaddr, str)
                    reader, writer = await asyncio.open_unix_connection(sockaddr)
                else:
                    assert not isinstance(sockaddr, str)
                    reader, writer = await asyncio.open_connection(
                        sockaddr[0], sockaddr[1], family=family
                    )
            except OSError as error:
                err("{}: connect: {}".format(self.name, error.strerror or error))
            else:
                out("{}: connected".format(self.name))
                self._serve_task = asyncio.current_task()
                await self._serve(reader, writer)

            # Try again later.
            await asyncio.sleep(RECONNECT_INTERVAL)

    async def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        previous = self._serve_task
        if previous is not None and not previous.done():
            out("{}: new connection replaces the previous one".format(self.name))
            previous.cancel()
            await asyncio.wait([previous])

        out("{}: new client connected".format(self.name))
        self._serve_task = asyncio.current_task()
        await self._serve(reader, writer)

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        set_keepalive(writer.get_extra_info("socket"))
        peer = writer.get_extra_info("peername")
        self.peer = str(peer) if peer else "unix"
        self.writer = writer
        try:
            await self.handler(reader, writer)
        except asyncio.CancelledError:
            pass
        except (OSError, asyncio.IncompleteReadError) as error:
            err("{}: connection error: {}".format(self.name, error))
        finally:
            if self.writer is writer:
                self.writer = None
                self.peer = None
                self.on_close()
            writer.close()
            if self._serve_task is asyncio.current_task():
                self._serve_task = None

    def describe(self) -> Dict[str, Any]:
        return {
            "mode": "connect" if self.is_client else "listen",
            "address": self.address,
            "connected": self.connected,
            "peer": self.peer,
        }
