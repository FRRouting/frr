# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

"""
Test if AddPath RX direction is not negotiated via AddPath capability.
"""


__topotests_file__ = "bgp_disable_addpath_rx/test_disable_addpath_rx.py"
__topotests_gitrev__ = "e82b531df94b9fd7bc456df8a1b7c58f2770eff9"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }  [ r3 ]
      |       |
    [ r2 ]--{ s2 }
              |
            [ r4 ]
    """

    topo.router("r3").lo_ip4.append("172.16.16.254/32")
    topo.router("r4").lo_ip4.append("172.16.16.254/32")
    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")
    topo.router("r2").iface_to("s2").ip4.append("192.168.2.2/24")
    topo.router("r3").iface_to("s2").ip4.append("192.168.2.3/24")
    topo.router("r4").iface_to("s2").ip4.append("192.168.2.4/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3", "r4"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r3'
    interface lo
     ip address {{ routers.r3.lo_ip4[0] }}
    !
    #%   elif router.name == 'r4'
    interface lo
     ip address {{ routers.r4.lo_ip4[0] }}
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
     timers 3 10
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers connect 5
     address-family ipv4 unicast
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} disable-addpath-rx
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     timers 3 10
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers connect 5
     neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} remote-as external
     neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} timers connect 5
     neighbor {{ routers.r4.iface_to('s2').ip4[0].ip }} remote-as external
     neighbor {{ routers.r4.iface_to('s2').ip4[0].ip }} timers connect 5
     address-family ipv4 unicast
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} addpath-tx-all-paths
     exit-address-family
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     timers 3 10
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} timers connect 5
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r4'
    router bgp 65004
     timers 3 10
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} timers connect 5
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   endif
    #% endblock
    """


class BGPDisableAddpathRx(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def check_bgp_advertised_routes(self, _, r1, r2):
        expected = {
            "advertisedRoutes": {
                "172.16.16.254/32": {
                    "addrPrefix": "172.16.16.254",
                    "prefixLen": 32,
                },
                "192.168.2.0/24": {
                    "addrPrefix": "192.168.2.0",
                    "prefixLen": 24,
                },
            },
            "totalPrefixCounter": 2,
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 unicast neighbor {r1.iface_to('s1').ip4[0].ip} advertised-routes json",
            maxwait=2.0,
            compare=expected,
        )

    @topotatofunc
    def check_bgp_disabled_addpath_rx(self, _, r1, r2):
        expected = {
            str(r2.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "addPath": {
                        "ipv4Unicast": {"txReceived": True, "rxReceived": True}
                    },
                },
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp neighbor {r2.iface_to('s1').ip4[0].ip} json",
            maxwait=2.0,
            compare=expected,
        )
