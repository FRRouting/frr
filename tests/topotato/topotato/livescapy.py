#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2021  David Lamparter for NetDEF, Inc.
"""
Utility for running a live scapy packet capture in the background.
"""

import time
import logging

from typing import Optional

from scapy.supersocket import SuperSocket  # type: ignore
from scapy.packet import Raw  # type: ignore

from .timeline import MiniPollee, TimedElement
from .pcapng import EnhancedPacket, IfDesc, Context

_logger = logging.getLogger("topotato")


class TimedScapy(TimedElement):
    def __init__(self, pkt):
        super().__init__()
        self._pkt = pkt

    @property
    def ts(self):
        return (self._pkt.time, 0)

    @property
    def pkt(self):
        return self._pkt

    def serialize(self, context: Context):
        assert self._pkt.sniffed_on in context.ifaces

        frame_num = context.take_frame_num()
        ts = getattr(self._pkt, "time_ns", int(self._pkt.time * 1e9))

        epb = EnhancedPacket(context.ifaces[self._pkt.sniffed_on], ts, bytes(self._pkt))
        for match in self.match_for:
            epb.options.append(epb.OptComment("match_for: %r" % match))

        jsdata = {
            "type": "packet",
            "iface": self._pkt.sniffed_on,
            "dump": self._pkt.show(dump=True),
            "frame_num": frame_num,
        }

        return (jsdata, epb)


class LiveScapy(MiniPollee):
    """
    DOCME
    """

    _ifname: str
    _sock: Optional[SuperSocket]

    def __init__(self, ifname: str, sock: SuperSocket):
        super().__init__()

        self._ifname = ifname
        self._sock = sock

    def fileno(self):
        if self._sock is None:
            return None
        return self._sock.fileno()

    def readable(self):
        maxdelay = time.time() + 0.1

        while time.time() < maxdelay:
            try:
                pkt = self._sock.recv()
            except BlockingIOError:
                break

            if isinstance(pkt, Raw):
                # not exactly sure why/when this happens, scapy bug?
                rawpkt = pkt
                pkt = self._sock.LL(bytes(rawpkt))
                if hasattr(rawpkt, "time"):
                    pkt.time = rawpkt.time
                if hasattr(rawpkt, "time_ns"):
                    pkt.time_ns = rawpkt.time_ns

            pkt.sniffed_on = self._ifname
            yield TimedScapy(pkt)

    def close(self):
        self._sock.close()
        self._sock = None

    def serialize(self, context: Context):
        """
        Plop out Interface Description Block for pcap-ng.
        """
        if self._ifname in context.ifaces:
            return

        context.ifaces[self._ifname] = len(context.ifaces)

        ifd = IfDesc()
        ifd.options.append(ifd.OptName(self._ifname))
        ifd.options.append(ifd.OptTSResol(9))
        yield (None, ifd)
