# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

"""
Test if neighbor <neighbor> sender-as-path-loop-detection
command works as expeced.
"""

__topotests_file__ = (
    "bgp_sender_as_path_loop_detection/test_bgp_sender-as-path-loop-detection.py"
)
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }--[ r3 ]
      |       |
    [ r2 ]--{ s2 }
    """


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

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
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 65002
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} route-map prepend out
      redistribute connected
     exit-address-family
    !
    route-map prepend permit 10
     set as-path prepend 65003
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 65001
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} solo
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} remote-as 65003
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} timers 3 10
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} solo
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} sender-as-path-loop-detection
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} remote-as 65002
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} timers 3 10
    !
    #%   endif
    #% endblock
    """


class BGPSenderAspathLoopDetection(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, _, r1, r2):
        expected = {
            str(r1.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r1.iface_to('s1').ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_has_route_from_r1(self, _, r1, r2):
        expected = {
            "paths": [
                {
                    "aspath": {
                        "segments": [{"type": "as-sequence", "list": [65001, 65003]}],
                        "length": 2,
                    }
                }
            ]
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp {r1.lo_ip4[0]} json",
            maxwait=1.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_suppress_route_to_r3(self, _, r2, r3):
        expected = {"totalPrefixCounter": 0}
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r3.iface_to('s1').ip4[0].ip} advertised-routes json",
            maxwait=2.0,
            compare=expected,
        )
