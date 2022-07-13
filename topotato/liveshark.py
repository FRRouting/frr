#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2021  David Lamparter for NetDEF, Inc.
"""
Utility for running a wireshark in background with piping live
data into Python.
"""

import sys
import os
import select
import time
import logging

from typing import List, Dict, Tuple, Any, Optional, Callable, Iterable

from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from xml.etree.ElementTree import XMLPullParser

from .utils import MiniPollee
from .pdmlpacket import PDMLPacket

_logger = logging.getLogger("topotato")


class LiveScapy(MiniPollee):
    """
    DOCME
    """

    packets: List[Packet]
    receivers: List[Callable[[Packet], Any]]

    _socks: Dict[int, Tuple[str, SuperSocket]]
    _abs_start_ts: float

    def __init__(
        self,
        netinst,
        abs_start_ts: Optional[float] = None,
    ):
        self._abs_start_ts = abs_start_ts or time.time()
        self._socks = {}

        for ifname, sock in netinst.scapys.items():
            self._socks[sock.fileno()] = (ifname, sock)

        self.receivers = []
        self.packets = []

    def _handle_packet(self, pkt: Packet):
        _logger.debug("iface %r pkt %r live-delay %fs", pkt.sniffed_on, pkt, time.time() - pkt.time)

        self.packets.append(pkt)
        for receiver in self.receivers:
            receiver(pkt)
        return pkt

    def subscribe(self, receiver: Callable[[Packet], Any]):
        """
        add a receiver that gets all the packets passed, used to make the
        HTML dumps.  receiver gets all the history packets first.
        """
        for pkt in self.packets:
            receiver(pkt)
        self.receivers.append(receiver)

    def _do_read(self, fd: int):
        ifname, sock = self._socks[fd]
        maxdelay = time.time() + 0.1

        while time.time() < maxdelay:
            try:
                pkt = sock.recv()
            except BlockingIOError:
                break
            pkt.sniffed_on = ifname
            yield (True, self._handle_packet(pkt))

    def filenos(self):
        for i in self._socks.keys():
            yield (i, self._do_read)

    def close(self):
        pass


class LiveSharkEOFError(EOFError):
    """
    EOF on reading from wireshark
    """


class LiveShark(MiniPollee):
    """
    mini eventloop for tshark running in background decoding packets

    the idea is that this is used everywhere in topotato where a test
    sleeps or waits for some IO.  while waiting, we shovel packets.
    """

    packets: List[PDMLPacket]
    receivers: List[Callable[[PDMLPacket], Any]]

    _pdmlfd: Optional[int]
    _abs_start_ts: float

    def __init__(
        self,
        pdmlfd: Optional[int] = None,
        abs_start_ts: Optional[float] = None,
    ):
        self._pdmlfd = pdmlfd

        self._abs_start_ts = abs_start_ts or time.time()

        self.xml = None
        self.receivers = []
        self.packets = []
        self.expect_eof = False
        if self._pdmlfd is not None:
            self._pdml_pp = XMLPullParser(["end"])

    def _handle_packet(self, xmlpkt):
        pkt = PDMLPacket(xmlpkt)
        # _logger.debug("pkt %r live-delay %fs", pkt, time.time() - pkt.ts)
        self.packets.append(pkt)
        for receiver in self.receivers:
            receiver(pkt)
        return pkt

    def subscribe(self, receiver: Callable[[PDMLPacket], Any]):
        """
        add a receiver that gets all the packets passed, used to make the
        HTML dumps.  receiver gets all the history packets first.
        """
        for pkt in self.packets:
            receiver(pkt)
        self.receivers.append(receiver)

    def filenos(self):
        if self._pdmlfd:
            yield (self._pdmlfd, self._pdml_read)

    def _pdml_read(self, fd):
        _ = fd  # unused

        rddata = os.read(self._pdmlfd, 16384)
        if not rddata:
            self.close()
            self._pdmlfd = None
            if not self.expect_eof:
                raise LiveSharkEOFError()
            return True

        self._pdml_pp.feed(rddata)
        for _, obj in self._pdml_pp.read_events():
            if obj.tag == "packet":
                yield (True, self._handle_packet(obj))
            if obj.tag == "pdml":
                self.xml = obj
        return False

    def run(
        self,
        delay: Optional[float] = None,
        abs_until: Optional[float] = None,
        fds: Optional[Iterable[Any]] = None,
        expect_eof: bool = False,
    ):
        """
        run small event loop reading from wireshark on the side

        delay: time to sleep for
        until: maximum deadline to cap sleep time at (relative to abs_start_ts)
        other_fds: break out if one of these is readable

        yields tuples (new, pkt), ends iteration on timeout or readable fds
        """

        self.expect_eof = expect_eof

        abs_start = time.time()
        abs_delay = abs_start + (delay or float("inf"))
        abs_until = abs_until or float("inf")
        deadline = min(abs_until, abs_delay)

        fds = list(fds or [])
        if self._pdmlfd is not None:
            os.set_blocking(self._pdmlfd, False)
            fds.append(self._pdmlfd)

        for pkt in self.packets:
            yield (False, pkt)

        while True:
            # always do at least one cycle to get some progress
            timeout: Optional[float] = max(deadline - time.time(), 0)
            if timeout == float("inf"):
                timeout = None
            rd, _, _ = select.select(fds, [], [], timeout)

            if self._pdmlfd and self._pdmlfd in rd:
                rd.remove(self._pdmlfd)

                is_eof = yield from self._pdml_read(self._pdmlfd)
                if is_eof:
                    return []

            if rd or time.time() >= deadline:
                return rd

    def close(self):
        if self._pdmlfd is not None:
            os.close(self._pdmlfd)
            self._pdmlfd = None
        if self._pdml_pp is not None:
            self._pdml_pp.close()
            self._pdml_pp = None


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)5s: %(message)s"
    )

    if len(sys.argv) >= 2:
        # pylint: disable=consider-using-with
        pdml_rd_buf = open(sys.argv[1], encoding="utf-8")
        pdml_rd = pdml_rd_buf.fileno()
    else:
        import subprocess

        pdml_rd, pdml_wr = os.pipe()
        # pylint: disable=consider-using-with
        tshark_proc = subprocess.Popen(
            ["tshark", "-q", "-T", "pdml", "-l"], stdout=pdml_wr
        )
        os.close(pdml_wr)

    liveshark = LiveShark(pdml_rd)
    for x in liveshark.run(delay=3.0):
        print(repr(x))
    for x in liveshark.run(delay=3.0):
        print(repr(x))
