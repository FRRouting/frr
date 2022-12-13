# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

"""
Test if route-map extcommunity none works:

route-map <name> permit 10
 set extcommunity none
"""

__topotests_file__ = "bgp_rmap_extcommunity_none/test_bgp_rmap_extcommunity_none.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

# pylint: disable=wildcard-import, unused-wildcard-import, trailing-whitespace

from topotato import *


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
    #%   if router.name == 'r2'
    interface lo
     ip address {{ routers.r2.lo_ip4[0] }} 
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
     neighbor 192.168.1.1 remote-as external
     address-family ipv4 unicast
      redistribute connected
      neighbor 192.168.1.1 route-map r1 out
     exit-address-family
    !
    route-map r1 permit 10
     set community 123:123
     set extcommunity bandwidth 200
    !
    #%   elif router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor 192.168.1.2 remote-as external
    !
    route-map r2 permit 10
     set extcommunity none
    !
    #%   endif
    #% endblock
    """


class TestBGPExtCommunity(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, _, r1):
        expected = {
            "prefix": "172.16.16.1/32",
            "paths": [
                {
                    "community": {
                        "string": "123:123",
                    },
                    "extendedCommunity": {"string": "LB:65002:25000000 (200.000 Mbps)"},
                }
            ],
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            "show bgp ipv4 unicast 172.16.16.1/32 json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_extcommunity_strip(self, _, r1):
        expected = {
            "prefix": "172.16.16.1/32",
            "paths": [
                {
                    "community": {
                        "string": "123:123",
                    },
                    "extendedCommunity": None,
                }
            ],
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            """
            enable
            configure terminal
            router bgp 65001
                    address-family ipv4 
                        neighbor 192.168.1.2 route-map r2 in
            """,
            compare="",
        )
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            "show bgp ipv4 unicast 172.16.16.1/32 json",
            maxwait=5.0,
            compare=expected,
        )
