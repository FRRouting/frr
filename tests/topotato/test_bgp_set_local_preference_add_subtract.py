#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar for NetDEF, Inc.

"""
bgp_set_local-preference_add_subtract.py:
Test if we can add/subtract the value to/from an existing
LOCAL_PREF in route-maps.
"""

__topotests_file__ = "bgp_set_local_preference_add_subtract/test_bgp_set_local-preference_add_subtract.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }--[ r3 ]
      |
    [ r2 ]

    """
    topo.router("r2").lo_ip4.append("172.16.255.254/32")
    topo.router("r3").lo_ip4.append("172.16.255.254/32")

    topo.router("r1").iface_to("s1").ip4.append("192.168.255.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.255.2/24")
    topo.router("r3").iface_to("s1").ip4.append("192.168.255.3/24")

    topo.router("r2").lo_ip4.append("10.10.10.2/32")
    topo.router("r3").lo_ip4.append("10.10.10.3/32")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
    !
    #%   endfor
    #% endblock
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r1'
    router bgp 65000
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} timers 3 10
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65000
     no bgp ebgp-requires-policy
     no bgp network import-check
     network {{ routers.r2.lo_ip4[1].ip }} route-map l2
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4
      redistribute connected
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} route-map r1-out out
     exit-address-family
    !
    route-map r1-out permit 10
     set local-preference +50
    route-map l2 permit 10
     set local-preference +10
    !
    #%   elif router.name == 'r3'
    router bgp 65000
     no bgp ebgp-requires-policy
     no bgp network import-check
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
     network {{ routers.r3.lo_ip4[1].ip }} route-map l3
     address-family ipv4
      redistribute connected
      neighbor{{ routers.r1.iface_to('s1').ip4[0].ip }} route-map r1-out out
     exit-address-family
    !
    route-map r1-out permit 10
     set local-preference -50
    route-map l3 permit 10
     set local-preference -10
    !
    #%   endif
    #% endblock
    """


class TestBGPSetLocalPreferenceAddSubtract(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, r1, r2, r3):
        expected = {
            str(r2.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 4}},
            },
            str(r3.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 4}},
            },
        }

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show ip bgp neighbor json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_local_preference(self, r1, r2, r3):
        expected = {
            "routes": {
                "10.10.10.2/32": [{"locPrf": 150}],
                "10.10.10.3/32": [{"locPrf": 100}],
                "172.16.255.254/32": [
                    {
                        "locPrf": 100,
                        "nexthops": [{"ip": str(r3.iface_to("s1").ip4[0].ip)}],
                    },
                    {
                        "locPrf": 150,
                        "nexthops": [{"ip": str(r2.iface_to("s1").ip4[0].ip)}],
                    },
                ],
            }
        }

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=5.0,
            compare=expected,
        )
