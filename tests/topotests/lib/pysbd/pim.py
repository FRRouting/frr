# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
PIM southbound: data plane events (`DATA_START`, `WRONG_IF` ...) sent to
pimd/pim6d on a stream connection.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Any, Dict, List

from .common import (
    PIM6SB_DEFAULT_PORT,
    PIMSB_DEFAULT_PORT,
    Buffer,
    err,
    ntop,
    out,
    pton,
    strtoul,
)
from .stream import StreamEndpoint

MRT_EVENT_DATA_START = 0
MRT_EVENT_DATA_STOP = 1
MRT_EVENT_WRONG_IF = 2
MRT_EVENT_JOIN_SPT = 3
MRT_EVENT_DATA_PACKET = 4

EVENT_NAMES = {
    MRT_EVENT_DATA_START: "DATA_START",
    MRT_EVENT_DATA_STOP: "DATA_STOP",
    MRT_EVENT_WRONG_IF: "WRONG_IF",
    MRT_EVENT_JOIN_SPT: "JOIN_SPT",
}

#: PIM southbound message version.
MRE_VERSION_V1 = 0x01

#: struct mroute_event: version, type, length, flags, input interface
#: index, source and group (IPv4 addresses use the first 4 bytes).
MROUTE_EVENT = struct.Struct("!BBHIi16s16s")


def _signed(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


def mroute_event_build(
    event_type: int, iif_idx: int, source: Buffer, group: Buffer
) -> bytes:
    return MROUTE_EVENT.pack(
        MRE_VERSION_V1,
        event_type,
        MROUTE_EVENT.size,
        0,
        _signed(iif_idx & 0xFFFFFFFF),
        bytes(source).ljust(16, b"\0"),
        bytes(group).ljust(16, b"\0"),
    )


class PimSouthbound:
    def __init__(self, family: int) -> None:
        self.family = family
        if family == socket.AF_INET:
            self.prefix = "pim"
            self.command = "mrt"
            default_port = PIMSB_DEFAULT_PORT
        else:
            self.prefix = "pim6"
            self.command = "mrt6"
            default_port = PIM6SB_DEFAULT_PORT

        self.endpoint = StreamEndpoint(
            self.prefix, default_port, self._serve, self._closed
        )
        self.events_sent = 0
        self.events_dropped = 0

    async def start(self, address: str) -> None:
        await self.endpoint.start(address)

    def close(self) -> None:
        self.endpoint.close()

    @property
    def connected(self) -> bool:
        return self.endpoint.connected

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while True:
            data = await reader.read(4096)
            if not data:
                err("{}: connection closed".format(self.prefix))
                return

            # Nothing is expected from the daemon.
            err("{}: read and discard {} bytes".format(self.prefix, len(data)))

    def _closed(self) -> None:
        pass

    def send(
        self, event_type: int, iif_idx: int, source: Buffer, group: Buffer
    ) -> bool:
        """Send a data plane event: returns `False` when it was dropped."""
        name = EVENT_NAMES.get(event_type, str(event_type))
        description = "{} if {} SG({}, {})".format(
            name,
            _signed(iif_idx & 0xFFFFFFFF),
            ntop(self.family, source),
            ntop(self.family, group),
        )

        writer = self.endpoint.writer
        if writer is None or writer.is_closing():
            self.events_dropped += 1
            out("{}: not connected, drop {}".format(self.prefix, description))
            return False

        out("{}: => {}".format(self.prefix, description))
        writer.write(mroute_event_build(event_type, iif_idx, source, group))
        self.events_sent += 1
        return True

    def _print_commands(self) -> None:
        out("available commands:")
        out(" * {} data-start SRC GRP IFINDEX".format(self.command))
        out(" * {} data-stop SRC GRP IFINDEX".format(self.command))
        out(" * {} join-spt SRC GRP IFINDEX".format(self.command))
        out(" * {} wrong-if SRC GRP IFINDEX".format(self.command))

    def stdin(self, tokens: List[str]) -> None:
        """Handle the `mrt`/`mrt6` commands (data plane event simulation)."""
        if not tokens:
            self._print_commands()
            return

        commands = {
            "join-spt": MRT_EVENT_JOIN_SPT,
            "data-start": MRT_EVENT_DATA_START,
            "data-stop": MRT_EVENT_DATA_STOP,
            "wrong-if": MRT_EVENT_WRONG_IF,
        }
        cmd = tokens[0]
        if cmd not in commands:
            out("unknown command: {} {}".format(self.command, cmd))
            self._print_commands()
            return

        usage = 'use: "{} {} SRC GRP IFINDEX"'.format(self.command, cmd)
        if len(tokens) < 4:
            out(usage)
            return

        source = pton(self.family, tokens[1])
        group = pton(self.family, tokens[2])
        ifindex = strtoul(tokens[3])
        if source is None or group is None or ifindex is None:
            out("check inputs please")
            out(usage)
            return

        self.send(commands[cmd], ifindex, source, group)

    def describe(self) -> Dict[str, Any]:
        description = self.endpoint.describe()
        description.update(
            {"eventsSent": self.events_sent, "eventsDropped": self.events_dropped}
        )
        return description
