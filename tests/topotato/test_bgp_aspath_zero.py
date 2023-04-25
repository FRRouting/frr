# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar for NetDEF, Inc.

"""
Test if BGP UPDATE with AS-PATH attribute with value zero (0)
is threated as withdrawal.
"""

__topotests_file__ = "bgp_aspath_zero/test_bgp_aspath_zero.py"
__topotests_gitrev__ = "a53c08bc131c02f4a20931d7aa9f974194ab16e7"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument, attribute-defined-outside-init
from topotato import *
from topotato.exabgp import ExaBGP


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }---[ peer1 ]
    """


class Configs(FRRConfigs):
    routers = ["r1", "peer1"]

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
    router bgp 65534
     no bgp ebgp-requires-policy
     neighbor {{ routers.peer1.ifaces[0].ip4[0].ip }} remote-as 65001
     neighbor {{ routers.peer1.ifaces[0].ip4[0].ip }} timers 3 10
    !
    #%   endif
    #% endblock
    """


class BGPAggregatorZero(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def prepare(self, peer1):

        configuration = """
neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} {
  router-id {{ routers.peer1.ifaces[0].ip4[0].ip }};
  local-address {{ routers.peer1.ifaces[0].ip4[0].ip }};
  local-as 65001;
  peer-as 65534;

  static {
    route 192.168.100.101/32 {
      next-hop {{ routers.peer1.ifaces[0].ip4[0].ip }};
    }

    route 192.168.100.102/32 {
      as-path [65000 0 65001];
      next-hop {{ routers.peer1.ifaces[0].ip4[0].ip }};
    }
  }
}
      """
        self.peer1 = ExaBGP(peer1, configuration)
        yield from self.peer1.start()

    @topotatofunc
    def bgp_converge(self, r1, peer1):

        expected = {
            f"{peer1.ifaces[0].ip4[0].ip}": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 1}},
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show ip bgp neighbor {peer1.ifaces[0].ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_has_correct_routes_without_asn_0(self, r1):

        expected = {"routes": {"192.168.100.101/32": [{"valid": True}]}}

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            "show ip bgp json",
            maxwait=5.0,
            compare=expected,
        )
