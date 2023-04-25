# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

"""
Test if default-originate works without route-map.
"""

__topotests_file__ = "bgp_default_route/test_bgp_default-originate.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

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
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 3 10
     exit-address-family
    !
    #%   elif router.name == 'r1'
    router bgp 65000
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as 65001
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} default-originate
     exit-address-family
    !
    #%   endif
    #% endblock
    """


class BGPDefaultOriginate(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_check_if_received(self, _, r1, r2):
        expected = {
            f"{r1.ifaces[0].ip4[0].ip}": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 1}},
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r1.ifaces[0].ip4[0].ip} json",
            maxwait=2.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_if_originated(self, _, r1, r2):
        expected = {
            "ipv4Unicast": {"peers": {f"{r2.ifaces[0].ip4[0].ip}": {"pfxSnt": 1}}}
        }
        yield from AssertVtysh.make(
            r1, "bgpd", f"show ip bgp summary json", maxwait=0.5, compare=expected
        )

    @topotatofunc
    def bgp_default_route_is_valid(self, _, r2):
        expected = {"paths": [{"valid": True}]}
        yield from AssertVtysh.make(
            r2, "bgpd", f"show ip bgp 0.0.0.0/0 json", maxwait=0.5, compare=expected
        )
