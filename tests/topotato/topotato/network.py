#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023  David Lamparter for NetDEF, Inc.
"""
Test network for topotato.
"""

import typing
from typing import (
    Any,
    Dict,
    Callable,
    List,
    Optional,
    Tuple,
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

    @classmethod
    def __init_subclass__(cls, /, topo=None, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.topo = topo


class Host(TopotatoNetwork.RouterNS):
    def __init__(self, instance: TopotatoNetwork, name: str, frr):
        super().__init__(instance, name)
        _ = frr  # FIXME: remove arg / rework FRR specific setup

    def interactive_state(self) -> Dict[str, Any]:
        return {}

    def report_state(self) -> Optional[Dict[str, Any]]:
        return None

    def start_post(self, timeline, failed: List[Tuple[str, str]]):
        pass
