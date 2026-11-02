# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""Daemon start up, command line and operator commands."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import sys
from typing import Any, Callable, Dict, List, Optional

from .common import (
    DEBUG_EMULATION,
    DEBUG_FPM_DUMP,
    DEBUG_NAMES,
    DEBUG_NETLINK,
    DEBUG_NETLINK_PROXY,
    DEBUG_NETLINK_PROXY_DUMP,
    DEBUG_PACKETS,
    DEBUG_PACKETS_DUMP,
    ConfigError,
    debug,
    err,
    ntop,
    out,
    strtonum,
)
from .console import console
from .dataplane import DataPlane
from .emulation import Emulator
from .fpm import Fpm
from .interface import Interface, Interfaces
from .mroute import (
    KERNEL_NOCACHE,
    OSPF_GROUPS,
    KernelEvent,
    MulticastRouting,
    join_groups,
)
from .netlink import NetlinkMonitor
from .netlink_proxy import NetlinkProxy
from .pim import MRT_EVENT_DATA_START, MRT_EVENT_WRONG_IF, PimSouthbound
from .rip import Rip
from .route import Route, RouteTable

DESCRIPTION = "Southbound daemon: simulates a software OS/data plane for FRR."

EPILOG = """\
The FPM, PIM and PIMv6 addresses are 'type:addr[:port]' with the types
'ipv4', 'ipv6' and 'unix' (listen) or 'ipv4c', 'ipv6c' and 'unixc' (connect),
IPv6 addresses go inside brackets (example: 'ipv6:[::1]:2651').

Commands (type 'help'): fpm, mrt, mrt6, netlink, show, debug.
"""

COMMANDS_HELP = """\
available commands:
 * mrt data-start|data-stop|join-spt|wrong-if SRC GRP IFINDEX
 * mrt6 data-start|data-stop|join-spt|wrong-if SRC GRP IFINDEX
 * fpm sync
 * netlink address add ADDRESS IFINDEX (with -X)
 * show interfaces|connections|routes|flows|debug [json]
 * debug [all|{flags}] [on|off]""".format(
    flags="|".join(DEBUG_NAMES)
)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pysbd",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-D", dest="debug_packets_dump", action="store_true", help="debug packets dump"
    )
    parser.add_argument(
        "-N", dest="debug_netlink", action="store_true", help="debug netlink messages"
    )
    parser.add_argument(
        "-M",
        dest="debug_netlink_proxy",
        action="store_true",
        help="debug netlink proxy messages",
    )
    parser.add_argument(
        "-P", dest="debug_packets", action="store_true", help="debug packets"
    )
    parser.add_argument(
        "-O",
        dest="debug_netlink_proxy_dump",
        action="store_true",
        help="dump netlink proxy packets",
    )
    parser.add_argument(
        "-F",
        dest="debug_fpm_dump",
        action="store_true",
        help="dump FPM messages exchanged",
    )
    parser.add_argument(
        "-E",
        dest="debug_emulation",
        action="store_true",
        help="debug the data plane emulation",
    )
    parser.add_argument(
        "-I",
        dest="fpm_install_unicast",
        action="store_true",
        help="send FPM unicast routes and EVPN neighbors to southbound "
        "(useful when testing southbound production mode)",
    )
    parser.add_argument(
        "-f",
        dest="fpm",
        metavar="type:addr[:port]",
        help="listen for FPM client (example: 'ipv4:127.0.0.1:1234')",
    )
    parser.add_argument(
        "-p",
        dest="pim",
        metavar="type:addr[:port]",
        help="open connection with PIM daemon (example: 'ipv4:127.0.0.1:1234')",
    )
    parser.add_argument(
        "-q",
        dest="pim6",
        metavar="type:addr[:port]",
        help="open connection with PIM6 daemon (example: 'ipv6:[::]:1234')",
    )
    parser.add_argument(
        "-r",
        dest="rp_ifindex",
        metavar="index",
        default="1",
        help="index of the interface that receives the traffic of the "
        "registers (default is 1 - loopback, only useful when router is RP)",
    )
    parser.add_argument(
        "-a",
        dest="auto",
        action="store_true",
        help="emulate the data plane: report DATA_START, DATA_STOP, JOIN_SPT "
        "and WRONG_IF from the traffic, remove the idle DL_TIMER routes, and "
        "send (and decapsulate) the traffic in registers",
    )
    parser.add_argument(
        "-t",
        dest="data_timeout",
        metavar="seconds",
        type=float,
        default=10.0,
        help="traffic stops after this many seconds without packets "
        "(emulation, default 10)",
    )
    parser.add_argument(
        "-m",
        dest="manual_mode",
        action="store_true",
        help="manual mode: don't report the kernel DATA_START events "
        "(use the 'mrt'/'mrt6' commands instead)",
    )
    parser.add_argument(
        "-X",
        dest="netlink_proxy",
        action="store_true",
        help="run the netlink proxy (127.0.0.1 port 2630)",
    )
    parser.add_argument(
        "-n",
        dest="no_stdin",
        action="store_true",
        help="don't read commands from the standard input",
    )
    parser.add_argument(
        "-c",
        dest="control",
        metavar="path",
        help="listen for commands on a unix socket (see `send_command`)",
    )
    args = parser.parse_args(argv)
    if args.data_timeout <= 0:
        parser.error("the data timeout must be positive")
    return args


def _format_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


class Daemon:
    """Creates and connects the components (see `run`)."""

    def __init__(self, args: argparse.Namespace, rp_ifindex: int) -> None:
        self.args = args
        self.rp_ifindex = rp_ifindex
        self.done: Optional[asyncio.Future] = None
        self.control: Optional[asyncio.AbstractServer] = None
        self.routes = RouteTable()
        self.pim = PimSouthbound(socket.AF_INET)
        self.pim6 = PimSouthbound(socket.AF_INET6)
        # Created by `run` (they need the event loop or sockets).
        self.dataplane: Optional[DataPlane] = None
        self.interfaces: Optional[Interfaces] = None
        self.netlink: Optional[NetlinkMonitor] = None
        self.fpm: Optional[Fpm] = None
        self.rip: Optional[Rip] = None
        self.emulator: Optional[Emulator] = None
        self.proxy: Optional[NetlinkProxy] = None

    def _pim_of(self, family: int) -> PimSouthbound:
        return self.pim if family == socket.AF_INET else self.pim6

    #
    # Interface hooks.
    #
    def interface_added(self, interface: Interface) -> None:
        assert self.dataplane is not None
        self.dataplane.interface_added(interface)

    def interface_removed(self, interface: Interface) -> None:
        assert self.dataplane is not None
        self.dataplane.interface_removed(interface)

    def interface_ipv4_enabled(self, interface: Interface) -> None:
        assert self.dataplane is not None and self.rip is not None
        join_groups(
            self.dataplane.ospf_sock,
            interface.index,
            interface.addresses[0],
            OSPF_GROUPS,
        )
        self.rip.interface_enabled(interface)

    #
    # Data plane events.
    #
    def kernel_event(self, event: KernelEvent) -> None:
        assert self.interfaces is not None
        if event.family == socket.AF_INET:
            ifindex = self.interfaces.vif2ifi(event.mif)
        else:
            ifindex = self.interfaces.mif2ifi(event.mif)
        out(
            "kernel: {} if {} SG({}, {})".format(
                "NOCACHE" if event.kind == KERNEL_NOCACHE else "WRONGIF",
                ifindex,
                ntop(event.family, event.source),
                ntop(event.family, event.group),
            )
        )
        if self.args.manual_mode:
            return

        event_type = (
            MRT_EVENT_DATA_START if event.kind == KERNEL_NOCACHE else MRT_EVENT_WRONG_IF
        )
        self._pim_of(event.family).send(event_type, ifindex, event.source, event.group)

    def report(
        self, family: int, event_type: int, ifindex: int, source: bytes, group: bytes
    ) -> None:
        """Emulated data plane event."""
        self._pim_of(family).send(event_type, ifindex, source, group)

    def register(self, route: Route, data: bytes) -> None:
        assert self.dataplane is not None
        self.dataplane.register_send(route.family, route.local, route.remote, data)

    def null_register(self, route: Route) -> None:
        assert self.dataplane is not None
        if route.family == socket.AF_INET:
            self.dataplane.pim_send_register(
                route.local, route.remote, route.source, route.group
            )
        else:
            self.dataplane.pim6_send_register(route.remote, route.source, route.group)

    def remove_route(self, route: Route) -> None:
        assert self.fpm is not None
        self.fpm.kernel_remove(route)

    def _tick(self) -> None:
        assert self.emulator is not None and self.done is not None
        if self.done.done():
            return
        self.emulator.tick()
        asyncio.get_running_loop().call_later(self._tick_interval(), self._tick)

    def _tick_interval(self) -> float:
        return min(1.0, self.args.data_timeout / 4)

    #
    # Commands.
    #
    def command(self, line: str) -> None:
        """Handle one operator command line."""
        tokens = line.split()
        if not tokens:
            return

        handlers: Dict[str, Callable[[List[str]], None]] = {
            "mrt": self.pim.stdin,
            "mrt6": self.pim6.stdin,
            "show": self.show,
            "debug": self.debug,
            "help": lambda _: out(COMMANDS_HELP),
        }
        if self.fpm is not None:
            handlers["fpm"] = self.fpm.stdin
        if self.proxy is not None:
            handlers["netlink"] = self.proxy.stdin

        handler = handlers.get(tokens[0])
        if handler is None:
            out("unrecognized input: {}".format(tokens[0]))
            out(COMMANDS_HELP)
            return

        handler(tokens[1:])

    def _ifname(self, index: int) -> Optional[str]:
        return self.interfaces.name(index) if self.interfaces else None

    def describe(self, what: str) -> Any:
        """Data of `show WHAT` (`None` when unknown)."""
        if what == "interfaces":
            return self.interfaces.describe() if self.interfaces else []
        if what == "connections":
            connections: Dict[str, Any] = {}
            if self.args.pim:
                connections["pim"] = self.pim.describe()
            if self.args.pim6:
                connections["pim6"] = self.pim6.describe()
            if self.fpm is not None and self.args.fpm:
                connections["fpm"] = self.fpm.endpoint.describe()
            if self.proxy is not None:
                connections["netlinkProxy"] = {"clients": len(self.proxy.clients)}
            return connections
        if what == "routes":
            return [route.describe(self._ifname) for route in self.routes]
        if what == "flows":
            if self.emulator is None:
                return {"emulation": False}
            description = self.emulator.describe(self._ifname)
            description["emulation"] = True
            return description
        if what == "debug":
            return {name: debug.enabled(flag) for name, flag in DEBUG_NAMES.items()}
        return None

    def show(self, tokens: List[str]) -> None:
        if not tokens:
            out("use: show interfaces|connections|routes|flows|debug [json]")
            return

        data = self.describe(tokens[0])
        if data is None:
            out("unknown command: show {}".format(tokens[0]))
            return
        if tokens[1:2] == ["json"]:
            out(_format_json(data))
            return

        if tokens[0] == "interfaces":
            out(
                "{:<16} {:>6} {:>4} {:>4}  {}".format(
                    "NAME", "INDEX", "VIF", "MIF", "ADDRESSES"
                )
            )
            for interface in data:
                out(
                    "{:<16} {:>6} {:>4} {:>4}  {}".format(
                        interface["name"],
                        interface["index"],
                        interface["vif"],
                        interface["mif"],
                        " ".join(interface["addresses"]),
                    )
                )
        elif tokens[0] == "routes":
            for route in data:
                out(
                    "SG({source}, {group}) iif:{iif} oifs:[{oifs}] notif:{notif} "
                    "flags:{flags} installed:{installed}".format(
                        source=route["source"],
                        group=route["group"],
                        iif=route["iif"]["name"],
                        oifs=",".join(str(oif["name"]) for oif in route["oifs"]),
                        notif=route["notif"]["name"],
                        flags="|".join(route["flags"]) or "-",
                        installed="yes" if route["installed"] else "no",
                    )
                )
        elif tokens[0] == "flows" and data.get("emulation"):
            for flow in data["flows"]:
                out(
                    "SG({source}, {group}) on {interface}: {packets} packets, "
                    "{state} (idle {idle}s) reported:{reported}".format(
                        state="active" if flow["active"] else "stopped",
                        reported=",".join(flow["reported"]) or "-",
                        **flow,
                    )
                )
        else:
            out(_format_json(data))

    def debug(self, tokens: List[str]) -> None:
        if not tokens:
            for name, flag in DEBUG_NAMES.items():
                out("{}: {}".format(name, "on" if debug.enabled(flag) else "off"))
            return

        enable = tokens[1:2] != ["off"]
        if tokens[0] == "all":
            flags = list(DEBUG_NAMES.values())
        elif tokens[0] in DEBUG_NAMES:
            flags = [DEBUG_NAMES[tokens[0]]]
        else:
            out("unknown debug: {}".format(tokens[0]))
            out(COMMANDS_HELP)
            return

        for flag in flags:
            debug.set(flag, enable)
        out("debug {} {}".format(tokens[0], "on" if enable else "off"))

    #
    # Life cycle.
    #
    def stdin_eof(self) -> None:
        out("EOF - exiting.")
        self.shutdown()

    def shutdown(self) -> None:
        if self.done is not None and not self.done.done():
            self.done.set_result(None)

    async def run(self) -> int:
        loop = asyncio.get_running_loop()
        self.done = loop.create_future()

        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            loop.add_signal_handler(signum, self.shutdown)

        dataplane = DataPlane(loop)
        self.dataplane = dataplane
        routing = MulticastRouting(
            dataplane.igmp_sock,
            dataplane.mld_sock,
            lambda: interfaces.ifi2vif(self.rp_ifindex),
            lambda: interfaces.ifi2mif(self.rp_ifindex),
        )
        interfaces = Interfaces(routing, self)
        self.interfaces = interfaces
        self.rip = Rip(dataplane, loop)
        netlink = NetlinkMonitor(interfaces, loop)
        self.netlink = netlink

        if self.args.auto:
            self.emulator = Emulator(
                self.routes,
                self.report,
                self.register,
                dataplane.decapsulate,
                self.remove_route,
                self.args.data_timeout,
            )
            dataplane.observe = self.emulator.observe
            dataplane.register_received = self.emulator.register_received
        dataplane.kernel_event = self.kernel_event

        self.fpm = Fpm(
            self.routes,
            routing,
            interfaces,
            netlink.enqueue,
            None if self.args.auto else self.null_register,
            self.emulator,
            install_unicast=self.args.fpm_install_unicast,
        )

        dataplane.start()
        self.rip.start()
        netlink.start()

        if self.args.netlink_proxy:
            self.proxy = NetlinkProxy(loop, lambda: netlink.pid)
            await self.proxy.start()
        if self.args.pim:
            await self.pim.start(self.args.pim)
        if self.args.pim6:
            await self.pim6.start(self.args.pim6)
        if self.args.fpm:
            await self.fpm.start(self.args.fpm)
        if self.emulator is not None:
            loop.call_later(self._tick_interval(), self._tick)

        if self.args.control:
            self.control = await console.start_control(self.args.control, self.command)

        # Commands are only read once everything is running.
        if not self.args.no_stdin:
            console.start_stdin(loop, self.command, self.stdin_eof)

        out("Waiting for packets...")
        await self.done

        for endpoint in (self.pim, self.pim6, self.fpm, self.proxy):
            if endpoint is not None:
                endpoint.close()
        return 0

    def teardown(self) -> None:
        console.teardown()
        if self.interfaces is not None:
            self.interfaces.shutdown()

        if self.control is not None:
            self.control.close()
            try:
                os.unlink(self.args.control)
            except OSError:
                pass


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    rp_ifindex, errp = strtonum(args.rp_ifindex, 1, 0x7FFFFFFF)
    if errp:
        err("pysbd: invalid RP interface index: {}".format(errp))
        return 1

    for enabled, flag in (
        (args.debug_packets_dump, DEBUG_PACKETS_DUMP),
        (args.debug_netlink_proxy, DEBUG_NETLINK_PROXY),
        (args.debug_netlink, DEBUG_NETLINK),
        (args.debug_netlink_proxy_dump, DEBUG_NETLINK_PROXY_DUMP),
        (args.debug_packets, DEBUG_PACKETS),
        (args.debug_fpm_dump, DEBUG_FPM_DUMP),
        (args.debug_emulation, DEBUG_EMULATION),
    ):
        debug.set(flag, enabled)

    if os.getuid() != 0:
        err("pysbd: you must be root to run this")
        return 1

    # Log files get the time of each message.
    console.timestamps = not sys.stdout.isatty()

    daemon = Daemon(args, rp_ifindex)
    try:
        return asyncio.run(daemon.run())
    except ConfigError as error:
        err("pysbd: {}".format(error))
        return 1
    finally:
        daemon.teardown()
