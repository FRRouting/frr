# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Data plane event emulation: watch the multicast traffic arriving on the
interfaces and act on it the way FRR expects from a vendor data plane (see
"Multicast routes" in doc/user/pim.rst):

- `DATA_START` when the traffic arrives on the notification interface of a
  route, or on the input interface of a route asking for `DATA_STOP` (the
  data plane reports when the traffic of those routes starts and stops).
- `DATA_STOP` when the traffic of a `RESTART_DL_TIMER` route stops.
- `JOIN_SPT` when a `JOIN_SPT_ALLOWED` SG(*,G) forwards a source.
- `WRONG_IF` when the traffic arrives on an output interface (assert).
- Remove `DL_TIMER` routes once their traffic stops.
- Send the traffic of the registering routes in PIM registers to the RP, and
  forward the traffic of the registers the RP receives.

The kernel still reports the cache misses (`DATA_START` of new traffic).
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .common import PIM_REG_IF_IDX, Buffer, debug_emulation, ntop, out
from .packet import data_packet_flow
from .pim import (
    EVENT_NAMES,
    MRT_EVENT_DATA_START,
    MRT_EVENT_DATA_STOP,
    MRT_EVENT_JOIN_SPT,
    MRT_EVENT_WRONG_IF,
)
from .route import (
    MRT_FLAG_DL_TIMER,
    MRT_FLAG_JOIN_SPT_ALLOWED,
    MRT_FLAG_RESTART_DL_TIMER,
    Route,
    RouteTable,
)

#: Minimum seconds between two WRONG_IF of a flow (like the kernel asserts).
WRONG_IF_INTERVAL = 3.0
#: Inactive flows are forgotten after this many timeouts.
FLOW_EXPIRY_TIMEOUTS = 10

FlowKey = Tuple[int, bytes, bytes, int]

#: Sends an event: (family, event type, interface index, source, group).
Report = Callable[[int, int, int, bytes, bytes], None]


class Flow:
    """Traffic of a (S,G) arriving on an interface."""

    def __init__(self, family: int, source: bytes, group: bytes, ifindex: int) -> None:
        self.family = family
        self.source = source
        self.group = group
        self.ifindex = ifindex
        self.packets = 0
        self.last_seen = 0.0
        self.active = False
        #: Events reported while their condition holds (reset when it stops).
        self.reported: Set[int] = set()
        self.last_wrong_if = -WRONG_IF_INTERVAL

    def describe(
        self, now: float, ifname: Callable[[int], Optional[str]]
    ) -> Dict[str, Any]:
        return {
            "source": ntop(self.family, self.source),
            "group": ntop(self.family, self.group),
            "interface": ifname(self.ifindex),
            "ifindex": self.ifindex,
            "packets": self.packets,
            "active": self.active,
            "idle": round(now - self.last_seen, 1),
            "reported": sorted(EVENT_NAMES[event] for event in self.reported),
        }


class Emulator:
    def __init__(
        self,
        routes: RouteTable,
        report: Report,
        register: Callable[[Route, bytes], None],
        decapsulate: Callable[[int, bytes], None],
        remove_route: Callable[[Route], None],
        timeout: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.routes = routes
        self.report = report
        self.register = register
        self.decapsulate = decapsulate
        self.remove_route = remove_route
        self.timeout = timeout
        self.clock = clock
        self.flows: Dict[FlowKey, Flow] = {}
        self.registers_sent = 0
        self.registers_decapsulated = 0

    def _log(self, text: str) -> None:
        if debug_emulation():
            out("emulation: " + text)

    def _flows_of(self, family: int, source: bytes, group: bytes) -> List[Flow]:
        return [
            flow
            for flow in self.flows.values()
            if flow.family == family and flow.source == source and flow.group == group
        ]

    def _report(self, flow: Flow, event: int, ifindex: int, once: bool = True) -> None:
        if once:
            if event in flow.reported:
                return
            flow.reported.add(event)
        self._log(
            "{} if {} SG({}, {})".format(
                EVENT_NAMES[event],
                ifindex,
                ntop(flow.family, flow.source),
                ntop(flow.family, flow.group),
            )
        )
        self.report(flow.family, event, ifindex, flow.source, flow.group)

    def _condition(self, flow: Flow, event: int, holds: bool) -> bool:
        """Report-once bookkeeping: forget the event when its condition stops."""
        if not holds:
            flow.reported.discard(event)
        return holds

    #
    # Traffic.
    #
    def observe(self, family: int, packet: Buffer, ifindex: int) -> None:
        """A packet arrived on the interface `ifindex`."""
        sg = data_packet_flow(family, packet)
        if sg is None:
            return
        source, group = sg

        now = self.clock()
        key = (family, source, group, ifindex)
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(family, source, group, ifindex)
            self.flows[key] = flow
        flow.packets += 1
        flow.last_seen = now
        if not flow.active:
            flow.active = True
            flow.reported.clear()
            self._log(
                "flow SG({}, {}) started on {}".format(
                    ntop(family, source), ntop(family, group), ifindex
                )
            )

        route = self.routes.get(family, source, group)
        if route is not None and not route.installed:
            route = None
        star = self.routes.star(family, group)
        if star is not None and not star.installed:
            star = None

        if route is not None:
            on_input = ifindex == route.iif
            on_notif = route.notif != 0 and ifindex == route.notif
            if on_input or on_notif:
                route.last_activity = now
                route.stop_reported = False

            if route.registers and on_input:
                self.registers_sent += 1
                self.register(route, bytes(packet))

            starting = on_notif or (
                on_input and route.has_flag(MRT_FLAG_RESTART_DL_TIMER)
            )
            if self._condition(flow, MRT_EVENT_DATA_START, starting):
                self._report(flow, MRT_EVENT_DATA_START, ifindex)

        # The SG(*,G) forwards the source and may switch it to the SPT.
        switch = (
            star is not None
            and star.has_flag(MRT_FLAG_JOIN_SPT_ALLOWED)
            and ifindex == star.iif
            and (route is None or route.iif == star.iif)
        )
        if self._condition(flow, MRT_EVENT_JOIN_SPT, switch):
            self._report(flow, MRT_EVENT_JOIN_SPT, ifindex)

        # Traffic on an output interface: another router forwards it too.
        forwarding = route if route is not None else star
        if (
            forwarding is not None
            and ifindex != forwarding.iif
            and ifindex in forwarding.forwarding_oifs
            and now - flow.last_wrong_if >= WRONG_IF_INTERVAL
        ):
            flow.last_wrong_if = now
            self._report(flow, MRT_EVENT_WRONG_IF, ifindex, once=False)

    def register_received(self, family: int, packet: bytes) -> None:
        """The RP got a register carrying `packet`: forward it."""
        sg = data_packet_flow(family, packet)
        if sg is None:
            return

        route = self.routes.get(family, sg[0], sg[1])
        if route is None or not route.installed or route.iif != PIM_REG_IF_IDX:
            return

        route.last_activity = self.clock()
        route.stop_reported = False
        self.registers_decapsulated += 1
        self.decapsulate(family, packet)

    #
    # Routes.
    #
    def route_changed(self, route: Route, previous: Optional[Route]) -> None:
        """A route was installed or updated (`previous` is the old one)."""
        if previous is not None and previous.installed and previous.iif == route.iif:
            route.last_activity = previous.last_activity
            route.stop_reported = previous.stop_reported
        else:
            route.last_activity = self.clock()
            route.stop_reported = False

    def route_removed(self, route: Route) -> None:
        """Events about the route may be reported again."""
        for flow in self._flows_of(route.family, route.source, route.group):
            flow.reported.discard(MRT_EVENT_DATA_START)
        if route.is_star:
            for flow in self.flows.values():
                if flow.family == route.family and flow.group == route.group:
                    flow.reported.discard(MRT_EVENT_JOIN_SPT)

    #
    # Timers.
    #
    def tick(self) -> None:
        """Find the traffic that stopped."""
        now = self.clock()
        for key, flow in list(self.flows.items()):
            idle = now - flow.last_seen
            if flow.active and idle >= self.timeout:
                flow.active = False
                flow.reported.clear()
                self._log(
                    "flow SG({}, {}) stopped on {}".format(
                        ntop(flow.family, flow.source),
                        ntop(flow.family, flow.group),
                        flow.ifindex,
                    )
                )
            elif not flow.active and idle >= self.timeout * FLOW_EXPIRY_TIMEOUTS:
                del self.flows[key]

        for route in self.routes:
            if not route.installed or route.is_star:
                continue
            if now - route.last_activity < self.timeout:
                continue

            if route.has_flag(MRT_FLAG_RESTART_DL_TIMER) and not route.stop_reported:
                route.stop_reported = True
                ifindex = route.iif if route.iif != PIM_REG_IF_IDX else route.notif
                self._log(
                    "DATA_STOP if {} SG({}, {})".format(
                        ifindex,
                        ntop(route.family, route.source),
                        ntop(route.family, route.group),
                    )
                )
                self.report(
                    route.family,
                    MRT_EVENT_DATA_STOP,
                    ifindex,
                    route.source,
                    route.group,
                )

            if route.has_flag(MRT_FLAG_DL_TIMER):
                self._log(
                    "remove idle SG({}, {})".format(
                        ntop(route.family, route.source),
                        ntop(route.family, route.group),
                    )
                )
                self.remove_route(route)

    def describe(self, ifname: Callable[[int], Optional[str]]) -> Dict[str, Any]:
        now = self.clock()
        return {
            "timeout": self.timeout,
            "registersSent": self.registers_sent,
            "registersDecapsulated": self.registers_decapsulated,
            "flows": [
                flow.describe(now, ifname)
                for flow in sorted(
                    self.flows.values(),
                    key=lambda f: (f.family, f.group, f.source, f.ifindex),
                )
            ],
        }
