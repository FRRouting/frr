#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
FreeBSD implementation of topotato instances, based on jailwrap
"""
# pylint: disable=duplicate-code

import os
import time
import tempfile
import json

from typing import (
    Dict,
    List,
    Optional,
)

from .defer import subprocess
from .jailwrap import FreeBSDJail
from .toponom import LAN, Network
from . import topobase


def ifname(host, iface):
    """
    make short interface names

    normally we use host_iface, but if iface starts with "host-" then just
    use straight iface.  we're on a 15 char limit...
    """
    if iface.startswith(host + "-"):
        return iface
    return "%s_%s" % (host, iface)


class NetworkInstance(topobase.NetworkInstance):
    """
    represent a test setup with all its routers & switches
    """

    class BaseNS(FreeBSDJail, topobase.BaseNS):
        """
        a netns with some extra functions for topotato
        """

        def __init__(self, instance, name):
            super().__init__(name)
            self.instance = instance
            self.tempdir = instance.tempfile(name)
            os.mkdir(self.tempdir)

        def tempfile(self, name):
            return os.path.join(self.tempdir, name)

        def start(self):
            super().start()
            self.check_call(["ifconfig", "lo0", "up"])

        def end_prep(self):
            pass

        def routes(self, af=4, local=False):
            """
            get a json representation of all IPvX kernel routes

            af is 4 or 6
            if local is True, also include routes for the router's own
            addresses (useful for consistency checks across multiple routers,
            no need to special-case each router's own address)
            """

            assert af in [4, 6]
            ret = {}

            jsroutes = json.loads(
                self.check_output(["netstat", "--libxo=json,pretty", "-rn"]).decode(
                    "US-ASCII"
                )
            )
            jsroutes = jsroutes["statistics"]["route-information"]["route-table"][
                "rt-family"
            ]
            afstr = "Internet" if af == 4 else "Internet6"
            jsroutes = [
                afroutes
                for afroutes in jsroutes
                if afroutes.get("address-family") == afstr
            ][0]["rt-entry"]

            remap = {(4, "default"): "0.0.0.0/0", (6, "default"): "::/0"}

            for entry in jsroutes:
                dst = remap.get((af, entry["destination"]), entry["destination"])
                if "/" not in dst:
                    dst = "%s/%d" % (dst, 32 if af == 4 else 128)
                if dst.startswith("fe80::"):
                    continue
                if (
                    entry.get("gateway", "").startswith("link#")
                    and entry["interface-name"] == "lo0"
                ):
                    if not local:
                        continue
                ret[dst] = entry
            return ret

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

        also dumpcap runs inside the switch NS to get a pcap file of all the
        traffic (it runs in multi-iface mode so you get 1 pcap file with all
        interfaces.)
        """

        # pylint: disable=useless-super-delegation
        def start(self):
            """
            switch ns init:

            - kill br-nftables because that really fucks things up.
            - disable ipv6 everywhere because we don't want linklocals on
              these interfaces
            """
            super().start()

            # nothing special for freebsd yet

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

            for ip4 in self.instance.network.routers[self.name].lo_ip4:
                self.check_call(["ifconfig", "lo0", "inet", "alias", str(ip4)])
            for ip6 in self.instance.network.routers[self.name].lo_ip6:
                self.check_call(["ifconfig", "lo0", "inet6", "alias", str(ip6)])

            for iface in self.instance.network.routers[self.name].ifaces:
                epairname = (
                    subprocess.check_output(["ifconfig", "epair", "create"])
                    .decode("US-ASCII")
                    .strip()
                )
                assert epairname.endswith("a")
                epairother = epairname[:-1] + "b"

                subprocess.check_call(["ifconfig", epairname, "ether", iface.macaddr])
                subprocess.check_call(["ifconfig", epairname, "vnet", "%d" % self.jid])
                self.check_call(["ifconfig", epairname, "name", iface.ifname, "up"])

                for ip4 in iface.ip4:
                    self.check_call(
                        ["ifconfig", iface.ifname, "inet", "alias", str(ip4)]
                    )
                for ip6 in iface.ip6:
                    self.check_call(
                        ["ifconfig", iface.ifname, "inet6", "no_dad", "alias", str(ip4)]
                    )

                subprocess.check_call(
                    ["ifconfig", epairother, "name", ifname(self.name, iface.ifname)]
                )
                subprocess.check_call(
                    [
                        "ifconfig",
                        ifname(self.name, iface.ifname),
                        "vnet",
                        "%d" % self.instance.switch_ns.jid,
                    ]
                )

        def link_set(self, iface, state):
            """
            take an interface on this router up/down for poking things

            this changes the interface state on the switch NS since that gets
            propagated to the router NS as carrier state, so we get carrier
            down inside the router.  matches an unplugged LAN cable pretty
            well.
            """
            ifn = ifname(self.name, iface.ifname)
            self.instance.switch_ns.check_call(
                ["ifconfig", ifn, "up" if state else "down"]
            )

    network: Network
    switch_ns: Optional[SwitchyNS]
    routers: Dict[str, RouterNS]
    bridges: List[str]
    pcapfile: Optional[str]

    def __init__(self, network):
        super().__init__(network)
        # pylint: disable=consider-using-with
        self.tempdir = tempfile.TemporaryDirectory()
        os.chmod(self.tempdir.name, 0o755)

    def tempfile(self, name):
        return os.path.join(self.tempdir.name, name)

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
        #     if isinstance(iface.endpoint, LAN):
        #         pid = self.switch_ns.pid
        #     else:
        #         pid = self.routers[iface.endpoint.name].pid
        #     name = iface.ifname
        #     mac = iface.macaddr
        #     return (str(pid), name, mac)

        self.bridges = []
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
                brcreated = (
                    self.switch_ns.check_output(["ifconfig", "bridge", "create"])
                    .decode("US-ASCII")
                    .strip()
                )
                self.switch_ns.check_call(["ifconfig", brcreated, "name", brname])
                self.switch_ns.check_call(
                    [
                        "ifconfig",
                        ifname(link.a.endpoint.name, link.a.ifname),
                        "inet6",
                        "ifdisabled",
                        "up",
                    ]
                )
                self.switch_ns.check_call(
                    [
                        "ifconfig",
                        ifname(link.b.endpoint.name, link.b.ifname),
                        "inet6",
                        "ifdisabled",
                        "up",
                    ]
                )
                self.switch_ns.check_call(
                    [
                        "ifconfig",
                        brname,
                        "addm",
                        ifname(link.a.endpoint.name, link.a.ifname),
                        "addm",
                        ifname(link.b.endpoint.name, link.b.ifname),
                        "up",
                    ]
                )

        for lan in self.network.lans.values():
            brname = lan.name
            self.bridges.append(brname)
            brcreated = (
                self.switch_ns.check_output(["ifconfig", "bridge", "create"])
                .decode("US-ASCII")
                .strip()
            )
            self.switch_ns.check_call(["ifconfig", brcreated, "name", brname])
            addm = []
            for iface in lan.ifaces:
                self.switch_ns.check_call(
                    [
                        "ifconfig",
                        ifname(iface.other.endpoint.name, iface.other.ifname),
                        "inet6",
                        "ifdisabled",
                        "up",
                    ]
                )
                addm.extend(
                    ["addm", ifname(iface.other.endpoint.name, iface.other.ifname)]
                )
            self.switch_ns.check_call(["ifconfig", brname] + addm + ["up"])

        self.pcapfile = self.tempfile("dump.pcapng")
        args = []
        for br in self.bridges:
            args.extend(["-i", br])
        # self.dumpcap = self.switch_ns.popen(['dumpcap', '-B', '1', '-t', '-w', self.pcapfile] + args)

    def stop(self):
        for rtr in self.routers.values():
            rtr.end_prep()
        for rtr in self.routers.values():
            rtr.end()
        self.switch_ns.end()
        # self.dumpcap.send_signal(signal.SIGINT)
        # self.dumpcap.wait()


# pylint: disable=import-outside-toplevel
def test():
    from . import toponom
    from pprint import pprint

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
    pprint(instance.routers["r1"].routes(4))
    print("--- r2 ---")
    pprint(instance.routers["r2"].routes(4))

    return instance


if __name__ == "__main__":
    test_instance = test()

    time.sleep(30)
    test_instance.stop()
