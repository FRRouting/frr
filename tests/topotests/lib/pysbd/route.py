# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""Multicast routes zebra sends over FPM (`RTA_MRT_EXTRA` carries the flags)."""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple

from .common import PIM_REG_IF_IDX, ntop, zero_address

#: LHR SG(*,G) allowed to switch to the SPT: report JOIN_SPT.
MRT_FLAG_JOIN_SPT_ALLOWED = 0x0001
#: Report DATA_STOP when the traffic stops.
MRT_FLAG_RESTART_DL_TIMER = 0x0002
#: IPv6 route.
MRT_FLAG_ADDR_TYPE_V6 = 0x0008
#: No output interface: drop the traffic.
MRT_FLAG_DUMMY = 0x0020
#: Remove the route after its traffic stops.
MRT_FLAG_DL_TIMER = 0x0040

FLAG_NAMES = [
    (MRT_FLAG_JOIN_SPT_ALLOWED, "JOIN_SPT_ALLOWED"),
    (MRT_FLAG_RESTART_DL_TIMER, "RESTART_DL_TIMER"),
    (MRT_FLAG_ADDR_TYPE_V6, "ADDR_TYPE_V6"),
    (MRT_FLAG_DUMMY, "DUMMY"),
    (MRT_FLAG_DL_TIMER, "DL_TIMER"),
]

RouteKey = Tuple[int, bytes, bytes]


class Route:
    def __init__(self, family: int, source: bytes, group: bytes) -> None:
        self.family = family
        #: Source address (zero for a SG(*,G)).
        self.source = source
        self.group = group
        #: Input interface index (0 for none, `PIM_REG_IF_IDX` for `pimreg`).
        self.iif = 0
        #: Output interface indexes (`PIM_REG_IF_IDX` means registers).
        self.oifs: List[int] = []
        #: Notification interface index (0 for none).
        self.notif = 0
        self.flags = 0
        self.spt_threshold = 0
        #: Register source and destination (the RP).
        self.local = zero_address(family)
        self.remote = zero_address(family)

        #: Whether the route is in the kernel (`DL_TIMER` may remove it).
        self.installed = False
        #: Last time traffic arrived for the route (or when installed).
        self.last_activity = 0.0
        #: DATA_STOP was reported since the last traffic.
        self.stop_reported = False

    @property
    def key(self) -> RouteKey:
        return (self.family, self.source, self.group)

    @property
    def is_star(self) -> bool:
        return self.source == zero_address(self.family)

    @property
    def registers(self) -> bool:
        """Sends the traffic in registers to the RP."""
        return (
            not self.is_star
            and PIM_REG_IF_IDX in self.oifs
            and self.remote != zero_address(self.family)
        )

    @property
    def forwarding_oifs(self) -> List[int]:
        return [oif for oif in self.oifs if oif != PIM_REG_IF_IDX]

    def has_flag(self, flag: int) -> bool:
        return bool(self.flags & flag)

    def flag_names(self) -> List[str]:
        return [name for flag, name in FLAG_NAMES if self.flags & flag]

    def same_forwarding(self, other: Route) -> bool:
        return self.iif == other.iif and self.notif == other.notif

    def describe(self, ifname: Any) -> Dict[str, Any]:
        """JSON friendly description (`ifname` maps indexes to names)."""

        def _interface(index: int) -> Dict[str, Any]:
            if index == PIM_REG_IF_IDX:
                return {"index": index, "name": "pimreg"}
            return {"index": index, "name": ifname(index) if index else None}

        return {
            "source": "*" if self.is_star else ntop(self.family, self.source),
            "group": ntop(self.family, self.group),
            "iif": _interface(self.iif),
            "oifs": [_interface(oif) for oif in self.oifs],
            "notif": _interface(self.notif),
            "flags": self.flag_names(),
            "local": ntop(self.family, self.local),
            "remote": ntop(self.family, self.remote),
            "installed": self.installed,
        }


class RouteTable:
    """The routes zebra installed (the kernel may lack the removed ones)."""

    def __init__(self) -> None:
        self._routes: Dict[RouteKey, Route] = {}

    def get(self, family: int, source: bytes, group: bytes) -> Optional[Route]:
        return self._routes.get((family, source, group))

    def star(self, family: int, group: bytes) -> Optional[Route]:
        return self._routes.get((family, zero_address(family), group))

    def set(self, route: Route) -> None:
        self._routes[route.key] = route

    def pop(self, key: RouteKey) -> Optional[Route]:
        return self._routes.pop(key, None)

    def __iter__(self) -> Iterator[Route]:
        return iter(list(self._routes.values()))

    def __len__(self) -> int:
        return len(self._routes)
