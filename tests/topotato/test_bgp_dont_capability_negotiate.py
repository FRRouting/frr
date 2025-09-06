#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

from topotato import *

"""
Test if BGP connection is established if at least one peer
sets `dont-capability-negotiate`.
"""


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }
      |
    [ r2 ]

    """

    topo.router("r2").lo_ip4.append("172.16.16.1/32")
    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    interface lo
     ip address {{ routers.r1.lo_ip4[0] }}
    !
    #%   endif
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
    !
    #%   endfor
    ip forwarding
    !
    #% endblock
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} dont-capability-negotiate
    !
    #%   endif
    #% endblock
    """


class BGPDontCapabilityNegotiate(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, topo, r1, r2):
        expected = {
            "peers": {
                "192.168.1.2": {
                    "pfxRcd": 2,
                    "pfxSnt": 2,
                    "state": "Established",
                    "peerState": "OK",
                }
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast summary json",
            maxwait=5.0,
            compare=expected,
        )
