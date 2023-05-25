#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Linux implementation of topotato instances, based on nswrap
"""
# pylint: disable=duplicate-code

import json
import os
import sys
import shlex
import re
import tempfile
import time
import logging

from typing import Union, Dict, List, Any, Optional

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal  # type: ignore

import pytest

import scapy.all  # type: ignore
import scapy.config  # type: ignore

from .defer import subprocess
from .utils import exec_find, EnvcheckResult
from .nswrap import LinuxNamespace
from .toponom import LAN, LinkIface, Network
from . import topobase


_logger = logging.getLogger(__name__)


def ifname(host: str, iface: str) -> str:
    """
    make short interface names

    normally we use host_iface, but if iface starts with "host-" then just
    use straight iface.  we're on a 15 char limit...
    """
    if iface.startswith(host + "-"):
        return iface
    return "%s_%s" % (host, iface)


def proc_write(path: str, value: str):
    return [
        "test ! -f %s || echo %s > %s" % (path, value, path),
    ]


class NetworkInstance(topobase.NetworkInstance):
    """
    represent a test setup with all its routers & switches
    """

    # TODO: replace this hack with something better (it only works because
    # _exec actually references the same dict from LinuxNamespace)
    # pylint: disable=protected-access
    _exec = LinuxNamespace._exec
    _exec.update(
        {
            "ip": None,
        }
    )

    _bridge_settings = [
        "forward_delay",
        "0",
        "mcast_snooping",
        "0",
        "nf_call_iptables",
        "0",
        "nf_call_ip6tables",
        "0",
        "nf_call_arptables",
        "0",
    ]

    # pylint: disable=unused-argument
    @classmethod
    @pytest.hookimpl()
    def pytest_topotato_envcheck(cls, session, result: EnvcheckResult):
        for name, cur in cls._exec.items():
            if cur is None:
                cls._exec[name] = cur = exec_find(name)
            if cur is None:
                result.error("%s is required to run on Linux systems", name)

    class BaseNS(LinuxNamespace, topobase.BaseNS):
        """
        a netns with some extra functions for topotato
        """

        instance: "NetworkInstance"
        tempdir: str

        # broken json output from "ip -j route list"
        iproute_json_re = re.compile(
            rb'(?<!:)"(anycast|broadcast|unicast|local|multicast|throw|unreachable|prohibit|blackhole|nat)"'
        )

        def __init__(self, _instance, name: str):
            super().__init__(name)
            self.instance = _instance
            self.tempdir = _instance.tempfile(name)
            os.mkdir(self.tempdir)
            _logger.debug(
                "%r temp-subdir for %r created: %s", _instance, self, self.tempdir
            )

        def __repr__(self):
            return "<%s: %r>" % (self.__class__.__name__, self.name)

        def tempfile(self, name: str) -> str:
            return os.path.join(self.tempdir, name)

        def start(self):
            super().start()
            self.check_call([self._exec.get("ip", "ip"), "link", "set", "lo", "up"])

        def end_prep(self):
            pass

        def routes(
            self, af: Union[Literal[4], Literal[6]] = 4, local=False
        ) -> Dict[str, Any]:
            """
            get a json representation of all IPvX kernel routes

            af is 4 or 6
            if local is True, also include routes for the router's own
            addresses (useful for consistency checks across multiple routers,
            no need to special-case each router's own address)
            """

            assert af in [4, 6]
            ret: Dict[str, List[Any]] = {}

            def add(arr):
                for route in arr:
                    dst = route["dst"]
                    if dst == "default":
                        dst = "0.0.0.0/0"
                    if "/" not in dst:
                        dst = dst + ("/32" if af == 4 else "/128")
                    ret.setdefault(dst, []).append(route)

            def ip_r_call(extra=None):
                text = self.check_output(
                    [self._exec.get("ip", "ip"), "-%d" % af, "-j", "route", "list"]
                    + (extra or [])
                )
                text = self.iproute_json_re.sub(rb'"type":"\1"', text)
                try:
                    return json.loads(text)
                except json.decoder.JSONDecodeError as e:
                    raise SystemError("invalid JSON from iproute2: %r" % text) from e

            add(ip_r_call())
            if local:
                add(ip_r_call(["table", "local"]))

            for net in list(ret.keys()):
                if net.startswith("fe80:") or net.startswith("ff00:"):
                    del ret[net]

            return ret

        def status(self):
            print("##### status for %s #####" % self.name)
            self.check_call(
                [
                    "/bin/sh",
                    "-x",
                    "-c",
                    "hostname; ip addr list; ip route list; ip -6 route list; ps axuf",
                ],
                stderr=sys.stdout,
            )

    class SwitchyNS(BaseNS, topobase.SwitchyNS):
        """
        namespace used for switching between the various routers

        note only ONE of these is used.  multiple bridges are created in here
        to cover multiple switches with one namespace.  no IP addresses exist
        in this at all, it's just doing switching.

        most bridges represent p2p links and have only 2 member interfaces.
        however, it is intentional that these still go through a bridge
        because that (a) makes things consistent (b) allows us to attach
        tcpdump from the switch NS and (c) allows setting links down on the
        bridge side so the router gets "carrier down"
        """

        def start(self):
            """
            switch ns init:

            - kill br-nftables because that really fucks things up.
            - disable ipv6 everywhere because we don't want linklocals on
              these interfaces
            """
            super().start()

            calls = []
            calls.append("ip link set lo up")
            calls.extend(
                proc_write("/proc/sys/net/bridge/bridge-nf-call-iptables", "0")
            )
            calls.extend(
                proc_write("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "0")
            )
            calls.extend(
                proc_write("/proc/sys/net/bridge/bridge-nf-call-arptables", "0")
            )
            calls.extend(proc_write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1"))
            calls.extend(
                proc_write("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1")
            )

            self.check_call(["/bin/sh", "-e", "-c", "; ".join(calls)])

    class RouterNS(BaseNS, topobase.RouterNS):
        """
        a (FRR) router namespace.  maybe change the name.

        one of these corresponds to 1 router in the topology
        """

        def start(self):
            """
            router ns init:

            - turn on IP forwarding just in case
            - kill DAD because it just slows down tests
            - create all the interfaces from the topology
            - add the addresses the topology contains
            """
            super().start()

            calls = []
            calls.extend(proc_write("/proc/sys/net/ipv4/ip_forward", "1"))
            calls.extend(proc_write("/proc/sys/net/ipv6/conf/all/forwarding", "1"))
            calls.extend(proc_write("/proc/sys/net/ipv6/conf/default/forwarding", "1"))
            calls.extend(proc_write("/proc/sys/net/ipv6/conf/all/accept_dad", "0"))
            calls.extend(proc_write("/proc/sys/net/ipv6/conf/default/accept_dad", "0"))

            for ip4 in self.instance.network.routers[self.name].lo_ip4:
                calls.append("ip -4 addr add %s dev lo scope global" % ip4)
            for ip6 in self.instance.network.routers[self.name].lo_ip6:
                calls.append("ip -6 addr add %s dev lo" % ip6)

            self.check_call(["/bin/sh", "-e", "-c", "; ".join(calls)])

            parentcalls = []
            calls = []

            for iface in self.instance.network.routers[self.name].ifaces:
                parentcalls.append(
                    "ip link add name %s address %s netns %d up type veth peer name %s netns %d"
                    % (
                        shlex.quote(iface.ifname),
                        shlex.quote(iface.macaddr),
                        self.pid,
                        shlex.quote(ifname(self.name, iface.ifname)),
                        self.instance.switch_ns.pid,
                    )
                )

                for ip4 in iface.ip4:
                    calls.append(
                        "ip -4 addr add %s dev %s" % (ip4, shlex.quote(iface.ifname))
                    )
                for ip6 in iface.ip6:
                    calls.append(
                        "ip -6 addr add %s dev %s" % (ip6, shlex.quote(iface.ifname))
                    )

            subprocess.check_call(["/bin/sh", "-e", "-c", "; ".join(parentcalls)])
            self.check_call(["/bin/sh", "-e", "-c", "; ".join(calls)])

        def link_set(self, iface: LinkIface, state: bool):
            """
            take an interface on this router up/down for poking things

            this changes the interface state on the switch NS since that gets
            propagated to the router NS as carrier state, so we get carrier
            down inside the router.  matches an unplugged LAN cable pretty
            well.
            """
            assert iface.ifname is not None
            assert self.instance.switch_ns is not None

            ifn = ifname(self.name, iface.ifname)
            self.instance.switch_ns.check_call(
                [
                    str(self._exec.get("ip", "ip")),
                    "link",
                    "set",
                    ifn,
                    "up" if state else "down",
                ]
            )

    network: Network
    switch_ns: Optional[SwitchyNS]
    routers: Dict[str, RouterNS]
    bridges: List[str]
    scapys: Dict[str, scapy.config.conf.L2socket]

    def __init__(self, network: Network):
        super().__init__(network)
        self.bridges = []

        # pylint: disable=consider-using-with
        self.tempdir = tempfile.TemporaryDirectory()
        os.chmod(self.tempdir.name, 0o755)
        _logger.debug("%r tempdir created: %s", self, self.tempdir.name)

    def tempfile(self, name):
        return os.path.join(self.tempdir.name, name)

    # pylint: disable=too-many-branches
    def start(self):
        """
        kick everything up

        also add the various interfaces to the bridges in the switch-NS.
        """

        self.switch_ns.start()
        for rns in self.routers.values():
            rns.start()

        # def linkinfo(iface):
        #    if isinstance(iface.endpoint, LAN):
        #        pid = self.switch_ns.pid
        #    else:
        #        pid = self.routers[iface.endpoint.name].pid
        #    name = iface.ifname
        #    mac = iface.macaddr
        #    return (str(pid), name, mac)

        for links in self.network.links.values():
            for link in links:
                if isinstance(link.a.endpoint, LAN):
                    continue
                if isinstance(link.b.endpoint, LAN):
                    continue
                brname = "%s_%s" % (link.a.endpoint.name, link.b.endpoint.name)
                if link.parallel_num != 0:
                    brname += "_%d" % (link.parallel_num)
                self.bridges.append(brname)
                self.switch_ns.check_call(
                    [
                        self._exec.get("ip", "ip"),
                        "link",
                        "add",
                        "name",
                        brname,
                        "up",
                        "type",
                        "bridge",
                    ]
                    + self._bridge_settings
                )
                self.switch_ns.check_call(
                    [
                        self._exec.get("ip", "ip"),
                        "link",
                        "set",
                        ifname(link.a.endpoint.name, link.a.ifname),
                        "up",
                        "master",
                        brname,
                    ]
                )
                self.switch_ns.check_call(
                    [
                        self._exec.get("ip", "ip"),
                        "link",
                        "set",
                        ifname(link.b.endpoint.name, link.b.ifname),
                        "up",
                        "master",
                        brname,
                    ]
                )

        for lan in self.network.lans.values():
            brname = lan.name
            self.bridges.append(brname)
            self.switch_ns.check_call(
                [
                    self._exec.get("ip", "ip"),
                    "link",
                    "add",
                    "name",
                    brname,
                    "up",
                    "type",
                    "bridge",
                ]
                + self._bridge_settings
            )
            for iface in lan.ifaces:
                self.switch_ns.check_call(
                    [
                        self._exec.get("ip", "ip"),
                        "link",
                        "set",
                        ifname(iface.other.endpoint.name, iface.other.ifname),
                        "up",
                        "master",
                        brname,
                    ]
                )

        self.scapys = {}
        args = []

        with self.switch_ns:
            for br in self.bridges:
                args.extend(["-i", br])

                self.scapys[br] = scapy.config.conf.L2socket(iface=br)
                os.set_blocking(self.scapys[br].fileno(), False)

    def stop(self):
        for rns in self.routers.values():
            rns.end_prep()
        for rns in self.routers.values():
            rns.end()
        self.switch_ns.end()

    def status(self):
        self.switch_ns.status()
        for rns in self.routers.values():
            rns.status()


def test():
    # pylint: disable=import-outside-toplevel
    from . import toponom

    net = toponom.test()

    instance = NetworkInstance(net)
    instance.prepare()
    try:
        instance.start()
    except subprocess.CalledProcessError as e:
        print(e)
        time.sleep(60)
        raise
    print("--- r1 ---")
    instance.routers["r1"].check_call(["ip", "addr", "list"])
    print("--- r2 ---")
    instance.routers["r2"].check_call(["ip", "addr", "list"])

    return instance


if __name__ == "__main__":
    _instance = test()

    time.sleep(30)
    _instance.stop()
