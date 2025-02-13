#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
# original test:
# Copyright (c) 2021  Network Device Education Foundation, Inc. ("NetDEF")
"""
PIM IPv4 neighbor up/down convergence test.
"""

from topotato.v1 import *
from topotato.multicast import MulticastReceiver
from topotato.scapy import ScapySend
from scapy.all import (
    IP,
    UDP,
)

__topotests_replaces__ = {
    "pim_basic_topo2/": "a53c08bc131c02f4a20931d7aa9f974194ab16e7",
}


@topology_fixture()
def topology(topo):
    """
    [ r1 ]----{     }
              { sw1 }
    [    ]----{     }
    [    ]
    [ r2 ]----{ sw3 }----[ r4 ]
    [    ]
    [    ]----{     }
              { sw2 }
    [ r3 ]----{     }
    """


class Configs(FRRConfigs):
    zebra = """
    #% extends "boilerplate.conf"
    """

    bfdd = """
    #% extends "boilerplate.conf"
    #% block main
    bfd
    #%   if router.name == 'r1'
     profile fast-tx
      receive-interval 250
      transmit-interval 250
     !
    #%   endif
    !
    #% endblock
    """

    pimd = """
    #% extends "boilerplate.conf"
    #% block main
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
    ##
     ip pim
     ip pim hello 1 5
    #%     if router.name == 'r1'
     ip pim bfd profile fast-tx
    #%     else
     ip pim bfd
    #%     endif
    !
    #%   endfor
    ##
    #%   if router.name == 'r2'
    ip pim join-prune-interval 5
    #%   endif
    #% endblock
    """


# TODO: move this into topotato
def iter_lan_nbrs(rtr):
    for iface in rtr.ifaces:
        lan = iface.other.endpoint
        for lanif in lan.ifaces:
            otherrtr = lanif.other.endpoint
            if otherrtr == rtr:
                continue
            yield (iface, otherrtr, lanif.other)


class PIMTopo2Test(TestBase, AutoFixture, topo=topology, configs=Configs):
    """
    Sequence of checks exercising PIM and BFD neighbor establishing.
    """

    @topotatofunc
    def pim_neigh_up(self, topo, r1, r2, r3, r4):
        """All pimd processes should see all of each other."""
        # pim_basic_topo2/test_pim_basic_topo2.py::test_wait_pim_convergence()
        for rtr in [r1, r2, r3, r4]:
            expect = {}
            for iface, otherrtr, otheriface in iter_lan_nbrs(rtr):
                jsif = expect.setdefault(iface.ifname, {})
                jsif[str(otheriface.ip4[0].ip)] = {}

            yield from AssertVtysh.make(
                rtr, "pimd", "show ip pim neighbor json", expect, maxwait=3.0
            )

    @topotatofunc
    def bfd_neigh_up(self, topo, r1, r2, r3, r4):
        """All bfdd processes should see all of each other."""
        # pim_basic_topo2/test_pim_basic_topo2.py::test_bfd_peers()
        for rtr in [r1, r2, r3, r4]:
            expect = [
                JSONCompareListKeyedDict("peer"),
            ]
            for iface, otherrtr, otheriface in iter_lan_nbrs(rtr):
                expect.append(
                    {
                        "peer": str(otheriface.ip4[0].ip),
                        "status": "up",
                    }
                )
            yield from AssertVtysh.make(
                rtr, "bfdd", "enable\nshow bfd peers json", expect, maxwait=3.0
            )

    @topotatofunc
    def reconverge_after_linkflap(self, topo, r1, r2, r3, r4):
        """Check neighbors while flapping r2--r4 link down and back up again."""
        # pim_basic_topo2/test_pim_basic_topo2.py::test_pim_reconvergence()

        yield from ModifyLinkStatus.make(r4, r4.iface_to("sw3"), False)

        yield from AssertVtysh.make(
            r4, "pimd", "show ip pim neighbor json", {}, maxwait=1.0
        )
        expect = {
            r2.iface_to("sw3").ifname: {},
        }
        yield from AssertVtysh.make(
            r2, "pimd", "show ip pim neighbor json", expect, maxwait=5.0
        )

        yield from ModifyLinkStatus.make(r4, r4.iface_to("sw3"), True)

        expect = {
            r4.iface_to("sw3").ifname: {
                str(r2.iface_to("sw3").ip4[0].ip): {},
            },
        }
        yield from AssertVtysh.make(
            r4, "pimd", "show ip pim neighbor json", expect, maxwait=8.0
        )

        expect = {
            r2.iface_to("sw3").ifname: {
                str(r4.iface_to("sw3").ip4[0].ip): {},
            },
        }
        yield from AssertVtysh.make(
            r2, "pimd", "show ip pim neighbor json", expect, maxwait=8.0
        )

    @topotatofunc
    def verify_bfd_profile(self, topo, r1, r2, r3, r4):
        """Check proper BFD profile propagates from PIM to BFD."""
        # pim_basic_topo2/test_pim_basic_topo2.py::test_pim_bfd_profile()

        expect = [
            JSONCompareListKeyedDict("peer"),
            {
                "peer": str(r2.iface_to("sw1").ip4[0].ip),
                "receive-interval": 250,
                "transmit-interval": 250,
            },
        ]
        yield from AssertVtysh.make(
            r1, "bfdd", "enable\nshow bfd peers json", expect, maxwait=3.0
        )

        expect[1]["peer"] = str(r1.iface_to("sw1").ip4[0].ip)
        yield from AssertVtysh.make(
            r2, "bfdd", "enable\nshow bfd peers json", expect, maxwait=3.0
        )
