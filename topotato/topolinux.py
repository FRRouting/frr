#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Linux implementation of topotato instances, based on nswrap
"""

import json
import os
import sys
import shlex
import re
import select
import signal
import subprocess
import tempfile
import time

from typing import Union, Dict, List, Any, Optional
from typing_extensions import Literal

from .nswrap import LinuxNamespace, find_child
from .toponom import LAN, LinkIface, Network


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


class NetworkInstance:
    """
    represent a test setup with all its routers & switches
    """

    class BaseNS(LinuxNamespace):
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

        def tempfile(self, name: str) -> str:
            return os.path.join(self.tempdir, name)

        def start(self):
            super().start()
            self.check_call(["ip", "link", "set", "lo", "up"])

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
                    ["ip", "-%d" % af, "-j", "route", "list"] + (extra or [])
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

    class SwitchyNS(BaseNS):
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

        also dumpcap runs inside the switch NS to get a pcap file of all the
        traffic (it runs in multi-iface mode so you get 1 pcap file with all
        interfaces.)
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

    class RouterNS(BaseNS):
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
                ["ip", "link", "set", ifn, "up" if state else "down"]
            )

    network: Network
    switch_ns: Optional[SwitchyNS]
    routers: Dict[str, RouterNS]
    bridges: List[str]
    pcapfile: Optional[str]
    dumpcap: Optional[subprocess.Popen]

    def __init__(self, network: Network):
        self.network = network
        self.switch_ns = None
        self.routers = {}
        self.bridges = []
        self.pcapfile = None
        self.dumpcap = None

        # pylint: disable=R1732
        self.tempdir = tempfile.TemporaryDirectory()
        os.chmod(self.tempdir.name, 0o755)

    def tempfile(self, name):
        return os.path.join(self.tempdir.name, name)

    def prepare(self):
        self.switch_ns = self.SwitchyNS(self, "switch-ns")
        for r in self.network.routers.values():
            self.routers[r.name] = self.RouterNS(self, r.name)

    def start(self):
        """
        kick everything up

        also add the various interfaces to the bridges in the switch-NS, and
        finally start up dumpcap for a pcap file.
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
                        "ip",
                        "link",
                        "add",
                        "name",
                        brname,
                        "up",
                        "type",
                        "bridge",
                        "forward_delay",
                        "0",
                        "mcast_snooping",
                        "0",
                    ]
                )
                self.switch_ns.check_call(
                    [
                        "ip",
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
                        "ip",
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
                    "ip",
                    "link",
                    "add",
                    "name",
                    brname,
                    "up",
                    "type",
                    "bridge",
                    "forward_delay",
                    "0",
                ]
            )
            for iface in lan.ifaces:
                self.switch_ns.check_call(
                    [
                        "ip",
                        "link",
                        "set",
                        ifname(iface.other.endpoint.name, iface.other.ifname),
                        "up",
                        "master",
                        brname,
                    ]
                )

        self.pcapfile = self.tempfile("dump.pcapng")
        args = []
        for br in self.bridges:
            args.extend(["-i", br])
        self.dumpcap = self.switch_ns.popen(
            ["dumpcap", "-B", "1", "-t", "-q", "-w", self.pcapfile] + args,
            stderr=subprocess.PIPE,
        )

        # starting dumpcap has been shown to take a few seconds on a loaded
        # CI box... to the point of tests completing before dumpcap even
        # started, which in turn caused hangs because dumpcap then couldn't
        # be killed :S

        start = time.time()
        timeout = 15.0

        os.set_blocking(self.dumpcap.stderr.fileno(), False)
        out = ""

        while time.time() < start + timeout:
            r = select.select(
                [self.dumpcap.stderr], [], [], start + timeout - time.time()
            )
            if len(r[0]) == 0:
                raise TimeoutError("failed to start dumpcap")
            out += self.dumpcap.stderr.read(4096).decode("UTF-8")
            if out.find("Capturing on") >= 0:
                break

    def stop(self):
        dumpcap_pid = find_child(self.dumpcap.pid)
        os.kill(dumpcap_pid, signal.SIGINT)
        self.dumpcap.wait()

        for rns in self.routers.values():
            rns.end()
        self.switch_ns.end()

    def status(self):
        self.switch_ns.status()
        for rns in self.routers.values():
            rns.status()


def test():
    # pylint: disable=C0415
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
