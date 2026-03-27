#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Scapy packet-sending integration for topotato.
"""

import logging

from typing import (
    Any,
    Optional,
)

import pytest

from .assertions import TopotatoModifier

logger = logging.getLogger("topotato")

try:
    # pylint: disable=no-name-in-module
    from scapy.all import Ether  # type: ignore
    from .scapyext import NetnsL2Socket

    scapy_exc = None

except ImportError as e:
    logger.error("scapy not available: %r", e)
    Ether = None  # type: ignore
    NetnsL2Socket = None  # type: ignore
    scapy_exc = e

__all__ = ["ScapySend"]


class ScapySend(TopotatoModifier):
    _rtr: Any
    _iface: str
    _pkt: Any
    _repeat: Optional[int]
    _interval: Optional[float]

    # pylint: disable=arguments-differ,protected-access,too-many-arguments
    @classmethod
    def from_parent(cls, parent, name, rtr, iface, pkt, *, repeat=None, interval=None):
        path = "/".join([l.__name__ for l in pkt.layers()])
        self = super().from_parent(
            parent, name="%s:%s/scapy[%s/%s]" % (name, rtr.name, iface, path)
        )
        self._rtr = rtr
        self._iface = iface
        self._repeat = repeat
        self._interval = interval

        # this is intentionally here so we don't have a hard dependency on
        # scapy.

        if not isinstance(pkt, Ether):
            pkt = Ether() / pkt

        self._pkt = pkt
        return self

    def __call__(self):
        if scapy_exc:
            pytest.skip(scapy_exc)

        router = self.instance.routers[self._rtr.name]
        with router:
            sock = NetnsL2Socket(iface=self._iface, promisc=False)
            sock.send(self._pkt)

        if self._repeat:
            for _ in range(1, self._repeat):
                self.timeline.sleep(self._interval)
                with router:
                    sock.send(self._pkt)

        sock.close()
