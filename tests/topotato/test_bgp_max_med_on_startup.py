# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test whether `bgp max-med on-startup (5-86400) [(0-4294967295)]` is working
correctly.
"""

__topotests_file__ = "bgp_max_med_on_startup/test_bgp_max_med_on_startup.py"
__topotests_gitrev__ = "acddc0ed3ce0833490b7ef38ed000d54388ebea4"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument

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
     bgp max-med on-startup 5 777
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 65002
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 65001
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
    !
    #%   endif
    #% endblock
  """


class BGPMaxMedOnStartup(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, _, r1, r2):
        expected = {str(r1.iface_to("s1").ip4[0].ip): {"bgpState": "Established"}}
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r1.iface_to('s1').ip4[0].ip} json",
            maxwait=2.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_has_routes(self, _, r1, r2):
        expected = {"routes": {str(r1.lo_ip4[0]): [{"metric": 777}]}}
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r1.iface_to('s1').ip4[0].ip} routes json",
            maxwait=2.0,
            compare=expected,
        )
