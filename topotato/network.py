#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023  David Lamparter for NetDEF, Inc.
"""
Test network for topotato.
"""

import typing
from typing import (
    Dict,
    Callable,
)

from .timeline import Timeline
from .osdep import NetworkInstance

if typing.TYPE_CHECKING:
    from . import toponom


class TopotatoNetwork(NetworkInstance):
    """
    Main network representation & interface.
    """

    timeline: Timeline
    router_factories: Dict[str, Callable[[str], NetworkInstance.RouterNS]]

    def make(self, name):
        maker = self.router_factories.get(name, super().make)
        return maker(name)

    def __init__(self, network: "toponom.Network"):
        super().__init__(network)
        self.timeline = Timeline()
        self.router_factories = {}
