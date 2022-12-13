# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar


"""
Test if we can match BGP prefixes by next-hop which is
specified by an IPv6 Access-list, prefix-list or just an address.
"""

__topotests_file__ = (
    "bgp_route_map_match_ipv6_nexthop/test_bgp_route_map_match_ipv6_nexthop.py"
)
__topotests_gitrev__ = "c75d6ccbfe95d2708618ade7cc7198e46ee467dd"

# pylint: disable=wildcard-import, unused-wildcard-import

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

    topo.router("r1").iface_to("s1").ip6.append("2001:db8::1/64")
    topo.router("r2").iface_to("s1").ip6.append("2001:db8::2/64")


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    interface r1-eth0
     ipv6 address 2001:db8::1/64
    !
    #%   endif
    #%   if router.name == 'r2'
    interface lo
     ipv6 address 2001:db8:1::1/128
     ipv6 address 2001:db8:2::1/128
     ipv6 address 2001:db8:3::1/128
     ipv6 address 2001:db8:4::1/128
     ipv6 address 2001:db8:5::1/128
    !
    interface r2-eth0
     ip address 2001:db8::2/64
    !
    #%   endif
    #% endblock
    """

    bgpd = """
  #% block main
    #%   if router.name == 'r2'
    !
    bgp send-extra-data zebra
    !
    router bgp 65002
     bgp router-id 10.10.10.2
     no bgp ebgp-requires-policy
     neighbor 2001:db8::1 remote-as external
     address-family ipv6 unicast
      redistribute connected
      neighbor 2001:db8::1 activate
      neighbor 2001:db8::1 route-map r1 out
     exit-address-family
    !
    ipv6 prefix-list p1 permit 2001:db8:1::1/128
    ipv6 prefix-list p2 permit 2001:db8:2::1/128
    ipv6 prefix-list p3 permit 2001:db8:3::1/128
    ipv6 prefix-list p4 permit 2001:db8:4::1/128
    ipv6 prefix-list p5 permit 2001:db8:5::1/128
    !
    route-map r1 permit 10
     match ipv6 address prefix-list p1
     set ipv6 next-hop global 2001:db8:1::1
    route-map r1 permit 20
     match ipv6 address prefix-list p2
     set ipv6 next-hop global 2001:db8:2::1
    route-map r1 permit 30
     match ipv6 address prefix-list p3
     set ipv6 next-hop global 2001:db8:3::1
    route-map r1 permit 40
     match ipv6 address prefix-list p4
     set ipv6 next-hop global 2001:db8:4::1
    route-map r1 permit 50
     match ipv6 address prefix-list p5
     set ipv6 next-hop global 2001:db8:5::1
    !
    #%   elif router.name == 'r1'
    !
    bgp send-extra-data zebra
    !
    ipv6 access-list nh1 permit 2001:db8:1::/64
    ipv6 access-list nh2 permit 2001:db8:2::/64
    ipv6 access-list nh3 permit 2001:db8:3::/64
    !
    ipv6 prefix-list nh4 permit 2001:db8:5::/64 le 128
    !
    router bgp 65001
     bgp router-id 10.10.10.1
     no bgp ebgp-requires-policy
     neighbor 2001:db8::2 remote-as external
     address-family ipv6 unicast
      neighbor 2001:db8::2 activate
      neighbor 2001:db8::2 route-map r2 in
     exit-address-family
    !
    route-map r2 permit 10
     match ipv6 next-hop nh1
     set community 65002:1
    route-map r2 permit 20
     match ipv6 next-hop nh2
     set community 65002:2
    route-map r2 permit 30
     match ipv6 next-hop nh3
     set community 65002:3
    route-map r2 permit 40
     match ipv6 next-hop address 2001:db8:4::1
     set community 65002:4
    route-map r2 permit 50
     match ipv6 next-hop prefix-list nh4
     set community 65002:5
    !
    #%   endif
  #% endblock
  """


class TestBGPRouteMapMatchIPV6NextHopAccessList(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, _, r1):
        expected = {
            "2001:db8:1::1/128": [
                {
                    "communities": "65002:1",
                }
            ],
            "2001:db8:2::1/128": [
                {
                    "communities": "65002:2",
                }
            ],
            "2001:db8:3::1/128": [
                {
                    "communities": "65002:3",
                }
            ],
            "2001:db8:4::1/128": [
                {
                    "communities": "65002:4",
                }
            ],
            "2001:db8:5::1/128": [
                {
                    "communities": "65002:5",
                }
            ],
        }
        yield from AssertVtysh.make(
            r1, "zebra", "show ipv6 route json", maxwait=6.0, compare=expected
        )
