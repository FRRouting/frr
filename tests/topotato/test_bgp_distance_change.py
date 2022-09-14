# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Jugroo Jesvin Brian

# pylint: disable=too-few-public-methos, invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string

"""
bgp_distance_change.py:
Test if works the following commands:
router bgp 65031
  address-family ipv4 unicast
    distance bgp 123 123 123
Changed distance should reflect to RIB after changes.
"""

__topotests_file__ = "bgp_distance_change/test_bgp_distance_change.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

from topotato import *


@topology_fixture()
def allproto_topo(topo):
    """
    [ r1 ]
       |
    { s1 }
       |
    [ r2 ]
    """
    topo.router("r2").lo_ip4.append("172.16.255.254/32")


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%  if router.name == 'r2'
    interface lo
        ip address {{ routers.r2.lo_ip4[0] }}
    !
    #%  endif
    #%  for iface in router.ifaces
    interface {{ iface.ifname }}
        ip address {{ iface.ip4[0] }}
    !
    #%  endfor
    ip forwarding
    !
    #% endblock
    """

    bgpd = """
    #% block main
    #%  if router.name == 'r2'
    router bgp 65001
      no bgp ebgp-requires-policy
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as 65000
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 3 10
      address-family ipv4 
        redistribute connected
      exit-address-family
    #%   elif router.name == 'r1'
    router bgp 65000
      no bgp ebgp-requires-policy
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as 65001
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 3 10
      exit-address-family
     !
    #%   endif
    #% endblock
    """


@config_fixture(Configs)
def configs(config, allproto_topo):
    return config


@instance_fixture()
def testenv(configs):
    return FRRNetworkInstance(configs.topology, configs).prepare()


class BGPDistanceChange(TestBase):
    instancefn = testenv

    @topotatofunc
    def bgp_converge(self, topo, r1, r2):
        expected = {
            str(r2.ifaces[0].ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show ip bgp neighbor {r2.ifaces[0].ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def _bgp_check_distance_change(self, topo, r1, r2):
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            """
            enable
            configure terminal
            router bgp 65000
                    address-family ipv4 unicast
                        distance bgp 123 123 123
            """,
            compare="",
        )
        expected = {str(r2.lo_ip4[0]): [{"protocol": "bgp", "distance": 123}]}
        yield from AssertVtysh.make(
            r1,
            "zebra",
            f"show ip route {r2.lo_ip4[0]} json",
            maxwait=10.0,
            compare=expected,
        )
