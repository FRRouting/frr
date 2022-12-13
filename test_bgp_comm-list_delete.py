#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Noah Krishnamoorty

"""
Test if works the following commands:
route-map test permit 10
  set comm-list <arg> delete
"""

__topotests_file__ = "bgp_comm_list_delete/test_bgp_comm-list_delete.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

# pylint: disable=wildcard-import,unused-import,unused-wildcard-import
from topotato.v1 import *


@topology_fixture()
def bgp_comm_list_delete_topo(topo):
    """
    [ r1 ]
      |
    { s1 }
      |
    [ r2 ]

    """
    topo.router("r1").lo_ip4.append("172.16.255.254/32")


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #% if router.name == 'r1'
    interface lo
     ip address {{ router.lo_ip4[0] }}
    !
    #% endif
    #% for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
    !
    #% endfor
    ip forwarding
    !
    #% endblock
    """

    bgpd = """
    #% extends "boilerplate.conf"
    #% block main
    #% if router.name == 'r1'
    router bgp 65000
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as 65001
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      redistribute connected route-map r2-out
     exit-address-family
    !
    route-map r2-out permit 10
     set community 111:111 222:222 333:333 444:444
    !
    #% elif router.name == 'r2'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 3 10
     address-family ipv4
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} route-map r1-in in
     exit-address-family
    !
    bgp community-list standard r1 permit 333:333
    !
    route-map r1-in permit 10
     set comm-list r1 delete
    !
    #% endif
    #% endblock
    """


@config_fixture(Configs)
def configs(config, bgp_comm_list_delete_topo):
    return config


@instance_fixture()
def testenv(configs):  # pylint: disable=redefined-outer-name
    return FRRNetworkInstance(configs.topology, configs).prepare()


class BGPCommListDeleteTest(TestBase):

    instancefn = testenv

    @topotatofunc
    def _bgp_converge_bgpstate(self, topo, r1, r2):

        expected = {str(r1.ifaces[0].ip4[0].ip): {"bgpState": "Established"}}
        print(r1.__dict__)
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor { r1.ifaces[0].ip4[0].ip } json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def _bgp_converge_prefixCounter(self, topo, r1, r2):

        expected = {
            str(r1.ifaces[0].ip4[0].ip): {
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}}
            }
        }

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor { r1.ifaces[0].ip4[0].ip } json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def _bgp_comm_list_delete(self, topo, r1, r2):

        expected = {
            "paths": [{"community": {"list": ["111:111", "222:222", "444:444"]}}]
        }

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp { r1.lo_ip4[0] } json",
            maxwait=5.0,
            compare=expected,
        )
