#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
Test against unexpected delays in PIMv6 prune propagation across routers.
"""

from topotato.v1 import *
from topotato.multicast import MulticastReceiver
from topotato.scapy import ScapySend
from scapy.all import (
    IPv6,
    UDP,
)


@topology_fixture()
def topo1(topo):
    """
    [ r1 ]--[ r2 ]--[ r3 ]--[ r4 ]
      |                       |
    { lan1 }                { lan4 }
      |                       |
    [ h1 ]                  [ h4 ]
    """


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3", "r4"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    debug zebra events
    #% endblock
    """

    staticd = """
    #% extends "boilerplate.conf"
    #% block main
    {{ frr.static_route_for(topo.lans['lan1'].ip6[0]) }}
    {{ frr.static_route_for(topo.lans['lan4'].ip6[0]) }}
    #% endblock
    """

    pim6d = """
    #% extends "boilerplate.conf"
    #% block main
    debug mld
    debug pimv6 trace
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ipv6 pim
     ipv6 pim hello 1 5
     ipv6 mld
     ipv6 mld query-max-response-time 3
     ipv6 mld query-interval 5
    !
    #%   endfor
    #% endblock
    """


class PIM6PrunePropagate(TestBase, AutoFixture, topo=topo1, configs=Configs):
    """
    IPv6 PIM prune propagation test.

    This test primarily checks two things:

    - prunes must not be delayed unnecessarily
    - MFIB state must be removed in response to prunes

    As a necessity, this sets up a traffic flow first.
    """

    @topotatofunc(include_startup=True)
    def prepare(self, topo, r1, r2, r3, r4, h1, h4):
        """
        Wait for PIM neighbors to come up.
        """
        self.srcaddr = h1.iface_to("lan1").ip6[0].ip

        for rtr in [r1, r2, r3, r4]:
            expect = {}
            for iface, nbriface, _ in rtr.neighbors(
                rtr_filter=lambda rtr: rtr.name.startswith("r")
            ):
                jsif = expect.setdefault(iface.ifname, {})
                jsif[str(nbriface.ll6)] = {}

            yield from AssertVtysh.make(
                rtr, "pim6d", "show ipv6 pim neighbor json", expect, maxwait=5.0
            )

    def assert_join_state(self, rtr, iface, state=None, **kwargs):
        if state is None:
            expect_if = None
        else:
            expect_if = {
                "ff35::2345": {
                    str(self.srcaddr): {
                        "channelJoinName": state,
                    },
                },
            }

        expect = {iface: expect_if}
        yield from AssertVtysh.make(
            rtr, "pim6d", "show ipv6 pim join json", expect, **kwargs
        )

    def pkt_send(self, h1, **kwargs):
        ip = IPv6(hlim=255, src=self.srcaddr, dst="ff35::2345")
        udp = UDP(sport=9999, dport=9999)

        yield from ScapySend.make(h1, "h1-lan1", pkt=ip / udp, **kwargs)

    @topotatofunc
    def join_traffic(self, topo, r1, r2, r3, r4, h1, h4):
        """
        Join S,G and push some traffic through.
        """
        self.receiver = MulticastReceiver(h4, h4.iface_to("lan4"))
        srcaddr = self.srcaddr

        yield from self.pkt_send(h1, repeat=2, interval=0.2)
        # TODO: negative check, packet must NOT be forwarded
        # TODO: same test without these packets, so join happens before traffic

        yield from self.receiver.join("ff35::2345", srcaddr)

        yield from AssertLog.make(
            r4,
            "pim6d",
            f"[MLD default:r4-lan4 ({srcaddr},ff35::2345)] NOINFO => JOIN",
            maxwait=2.0,
        )
        for rtr in [r3, r2, r1]:
            yield from AssertLog.make(
                rtr,
                "pim6d",
                f"recv_join: join (S,G)=({srcaddr},ff35::2345)",
                maxwait=2.0,
            )

        # need > 30s here, stats fetch from kernel is needed to start KAT
        # note 4 packets is only 3x the interval between...
        yield from self.pkt_send(h1, repeat=4, interval=11)

        def expect_pkt(ipv6: IPv6, udp: UDP):
            return (
                ipv6.src == str(srcaddr)
                and ipv6.dst == "ff35::2345"
                and udp.dport == 9999
            )

        yield from AssertPacket.make("lan4", pkt=expect_pkt)

        yield from self.assert_join_state(r1, "r1-r2", "JOIN", maxwait=2.0)
        yield from self.assert_join_state(r2, "r2-r3", "JOIN", maxwait=2.0)
        yield from self.assert_join_state(r3, "r3-r4", "JOIN", maxwait=2.0)
        # MLD join is not a PIM join => NOINFO
        yield from self.assert_join_state(r4, "r4-lan4", "NOINFO", maxwait=2.0)

    @topotatofunc
    def mld_wait(self, topo, r1, r2, r3, r4, h1, h4):
        """
        Give MLD 10 seconds to age out the join.

        (Timing: query-max-response-time + robustness * interval)
        """
        yield from self.receiver.leave("ff35::2345", self.srcaddr)
        yield from AssertLog.make(
            r4,
            "pim6d",
            f"[MLD default:r4-lan4 ({self.srcaddr},ff35::2345)] JOIN => JOIN_EXPIRING",
            maxwait=2.0,
        )
        yield from AssertLog.make(
            r4,
            "pim6d",
            f"[MLD default:r4-lan4 ({self.srcaddr},ff35::2345)] JOIN_EXPIRING => NOINFO",
            maxwait=12.0,
        )

    @topotatofunc
    def prune(self, topo, r1, r2, r3, r4, h1, h4):
        """
        Ensure the PIM prune propagates and applies without unexpected delays.
        """
        # r2 & r3 go through NOINFO for a little while for prune handling
        yield from self.assert_join_state(r1, "r1-r2", "NOINFO", maxwait=1.0)
        yield from self.assert_join_state(r2, "r2-r3", "NOINFO", maxwait=1.0)
        yield from self.assert_join_state(r3, "r3-r4", "NOINFO", maxwait=1.0)
        # MLD state is gone
        yield from self.assert_join_state(r4, "r4-lan4", None, maxwait=1.0)

	# send some follow-on packets that should NOT get forwarded
        yield from self.pkt_send(h1, repeat=3, interval=1)

        # r2-4 should completely ditch source MFIB state
        yield from AssertVtysh.make(
            r4, "pim6d", "show ipv6 mroute json", {"ff35::2345": None}, maxwait=4.0
        )
        yield from AssertVtysh.make(
            r3, "pim6d", "show ipv6 mroute json", {"ff35::2345": None}, maxwait=4.0
        )
        yield from AssertVtysh.make(
            r2, "pim6d", "show ipv6 mroute json", {"ff35::2345": None}, maxwait=4.0
        )

        # r1 remembers the source but must have an empty OIL now
        yield from AssertVtysh.make(
            r1,
            "pim6d",
            "show ipv6 mroute json",
            {
                "ff35::2345": {
                    str(self.srcaddr): {
                        "oilSize": 0,
                    },
                },
            },
            maxwait=4.0,
        )

        yield from self.pkt_send(h1, repeat=2, interval=0.2)

        # TODO: negative check, packet must NOT be forwarded
