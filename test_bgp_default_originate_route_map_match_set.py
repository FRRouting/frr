#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

"""
Test if default-originate works with match operations.
And verify if set operations work as well.
"""

__topotests_file__ = "bgp_default_route_route_map_match_set/test_bgp_default-originate_route-map_match_set.py"
__topotests_gitrev__ = "68d4b72ff37eb2d6d851b0dcd9e69e7a248b6cec"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation

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
    topo.router("r1").lo_ip4.append("172.16.255.254/32")
    topo.router("r1").iface_to("s1").ip4.append("192.168.255.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.255.2/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    interface lo
     ip address {{ routers.r1.lo_ip4[0] }}
    !
    ip route 192.168.13.0./24 Null0
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
    router bgp 65001
      no bgp ebgp-requires-policy
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as 65000
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 3 10
      address-family ipv4 unicast
        redistribute connected
      exit-address-family
    !
    #%   elif router.name == 'r1'
    router bgp 65000
      no bgp ebgp-requires-policy
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as 65001
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 3 10
      address-family ipv4 unicast
        redistribute connected
        network 192.168.13.0/24 route-map internal
        neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} default-originate route-map default
      exit-address-family
    !
    bgp community-list standard default seq 5 permit 65000:1
    !
    route-map default permit 10
      match community default
      set metric 123
      set as-path prepend 65000 65000 65000
    !
    route-map internal permit 10
      set community 65000:1
    !
    #%   endif
    #% endblock
    """


class BGPDefaultOriginateRouteMapMatchSet(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    # Establish BGP connection
    @topotatofunc
    def bgp_converge(self, _, r1, r2):
        expected = {
            str(r1.ifaces[0].ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r1.ifaces[0].ip4[0].ip} json",
            maxwait=3.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_default_route_has_metric(self, _, r2):

        expected = {
            "paths": [
                {
                    "aspath": {"string": "65000 65000 65000 65000"},
                    "metric": 123,
                    "community": None,
                }
            ]
        }
        yield from AssertVtysh.make(
            r2, "bgpd", f"show ip bgp 0.0.0.0/0 json", maxwait=5.0, compare=expected
        )
