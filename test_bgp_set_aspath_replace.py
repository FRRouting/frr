# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

"""
Test if `set as-path replace` is working correctly for route-maps.
"""

__topotests_file__ = "bgp_set_aspath_replace/test_bgp_set_aspath_replace.py"
__topotests_gitrev__ = "77e3d82167b97a1ff4abe59d6e4f12086a61d9f9"

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

    topo.router("r3").lo_ip4.append("172.16.255.31/32")
    topo.router("r3").lo_ip4.append("172.16.255.32/32")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r3'
    interface lo
     ip address {{ routers.r3.lo_ip4[0] }}
     ip address {{ routers.r3.lo_ip4[0] }}
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
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} route-map r2 in
     exit-address-family
    !
    ip prefix-list p1 seq 5 permit {{ routers.r3.lo_ip4[0] }}
    !
    route-map r2 permit 10
     match ip address prefix-list p1
     set as-path replace 65003
    route-map r2 permit 20
     set as-path replace any
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
     neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} remote-as external
     neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} timers 3 10
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   endif
  #% endblock
  """


class BGPSetAspathReplace(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, _, r1, r3):
        expected = {
            "routes": {
                str(r3.lo_ip4[0]): [{"path": "65002 65001"}],
                str(r3.lo_ip4[1]): [{"path": "65001 65001"}],
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=5.0,
            compare=expected,
        )
