#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
"""
IPv4 PIM + BFD test.

TBD: incomplete, mostly used to test topotato ModifyLinkStatus.
"""

from topotato.v1 import *


@topology_fixture()
def pim_bfd_topo(topo):
    """
    [ r1 ]
       |
    [ r2 ]--[ r3 ]
       |
    [ r4 ]
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
    !
    interface {{ iface.ifname }}
     ip pim
     ip pim hello 1 3
    #%     if router.name == 'r1'
     ip pim bfd profile fast-tx
    #%     else
     ip pim bfd
    #%     endif
    #%   endfor
    #% endblock
    """


@config_fixture(Configs)
def pim_bfd_configs(config, pim_bfd_topo):
    return config


@instance_fixture()
def pim_bfd_testenv(pim_bfd_configs):
    instance = FRRNetworkInstance(pim_bfd_configs.topology, pim_bfd_configs)
    instance.prepare()
    return instance


class PIMBFDTest(TestBase):
    instancefn = pim_bfd_testenv

    @topotatofunc
    def test(self, topo, r1, r2, r3, r4):
        def expect_neighbor(rtr, ifname, peer, deadline):
            js = {
                ifname: {
                    str(peer.ip4[0].ip): JSONCompareIgnoreContent(),
                },
            }
            yield from AssertVtysh.make(
                rtr, "pimd", "show ip pim neighbor json", js, maxwait=deadline
            )

        def expect_neighbor_down(rtr, ifname, peer, deadline):
            js = {
                ifname: {
                    str(peer.ip4[0].ip): None,
                },
            }
            yield from AssertVtysh.make(
                rtr, "pimd", "show ip pim neighbor json", js, maxwait=deadline
            )

        def expect_bfd_peer(rtr, peer, deadline):
            js = [
                {
                    "peer": str(peer.ip4[0].ip),
                    "status": "up",
                }
            ]
            yield from AssertVtysh.make(
                rtr, "bfdd", "enable\nshow bfd peers json", js, maxwait=deadline
            )

        # PIM neighbors
        yield from expect_neighbor(r2, "r2-r1", r1.iface_to("r2"), 5.0)
        yield from expect_neighbor(r1, "r1-r2", r2.iface_to("r1"), 5.0)
        yield from expect_neighbor(r2, "r2-r3", r3.iface_to("r2"), 5.0)
        yield from expect_neighbor(r3, "r3-r2", r2.iface_to("r3"), 5.0)
        yield from expect_neighbor(r2, "r2-r4", r4.iface_to("r2"), 5.0)
        yield from expect_neighbor(r4, "r4-r2", r2.iface_to("r4"), 5.0)

        # BFD sessions
        yield from expect_bfd_peer(r2, r1.iface_to("r2"), 6.0)
        yield from expect_bfd_peer(r1, r2.iface_to("r1"), 6.0)
        yield from expect_bfd_peer(r2, r3.iface_to("r2"), 6.0)
        yield from expect_bfd_peer(r3, r2.iface_to("r3"), 6.0)
        yield from expect_bfd_peer(r2, r4.iface_to("r2"), 6.0)
        yield from expect_bfd_peer(r4, r2.iface_to("r4"), 6.0)

        # flip r4 off
        yield from ModifyLinkStatus.make(r4, r4.iface_to("r2"), False)
        yield from expect_neighbor_down(r2, "r2-r4", r4.iface_to("r2"), 9.0)

        # and back on
        yield from ModifyLinkStatus.make(r4, r4.iface_to("r2"), True)
        yield from expect_neighbor(r2, "r2-r4", r4.iface_to("r2"), 12.0)
        yield from expect_neighbor(r4, "r4-r2", r2.iface_to("r4"), 12.0)

        js = [
            {
                "peer": str(r2.iface_to("r1").ip4[0].ip),
                "receive-interval": 250,
                "transmit-interval": 250,
            }
        ]
        yield from AssertVtysh.make(r1, "bfdd", "enable\nshow bfd peers json", js)

        js = [
            {
                "peer": str(r1.iface_to("r2").ip4[0].ip),
                "remote-receive-interval": 250,
                "remote-transmit-interval": 250,
            }
        ]
        yield from AssertVtysh.make(r2, "bfdd", "enable\nshow bfd peers json", js)
