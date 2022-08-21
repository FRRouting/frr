# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  Bruno Bernard for NetDEF, Inc.

"""
Demo testing of ExaBGP
"""
# pylint: disable=unused-wildcard-import,wildcard-import,unused-argument,redefined-outer-name,attribute-defined-outside-init
from topotato import *
from topotato.exabgp import ExaBGP


@topology_fixture()
def allproto_topo(topo):
    """
    [ r1 ]
      |
    { s1 }---[ r3 ]
      |
    [ r2 ]

    """


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
    ip forwarding
    !
    #% endblock
    """

    bgpd = """
  #% block main
    #%   if router.name == 'r1'
    router bgp 65534
      no bgp ebgp-requires-policy
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as 65001
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 3 10
      neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} remote-as 65002
      neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} timers 3 10
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


class BGPDefaultOriginate(TestBase):
    instancefn = testenv

    @topotatofunc
    def prepare(self, topo, r1, r2, r3):

        configuration = """
neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} {
    router-id {{ routers.r2.ifaces[0].ip4[0].ip }}; 
    local-address {{ routers.r2.ifaces[0].ip4[0].ip }}; 
    local-as 65001;
    peer-as 65534;
}
      """
        self.peer = ExaBGP(r2, configuration)
        yield from self.peer.start()

        configuration2 = """
neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} {
    router-id {{ routers.r3.ifaces[0].ip4[0].ip }}; 
    local-address {{ routers.r3.ifaces[0].ip4[0].ip }}; 
    local-as 65002;
    peer-as 65534;
}
      """
        self.peer2 = ExaBGP(r3, configuration2)
        yield from self.peer2.start()

    @topotatofunc
    def bgp_check(self, topo, r1, r2, r3):

        expected = {
            "ipv4Unicast": {
                "peers": {
                    f"{r2.ifaces[0].ip4[0].ip}": {"state": "Established"},
                    f"{r3.ifaces[0].ip4[0].ip}": {"state": "Established"},
                }
            }
        }
        yield from AssertVtysh.make(
            r1, "bgpd", "show ip bgp summary json", maxwait=5.0, compare=expected
        )

    @topotatofunc
    def exabgp_announcement(self, topo, r1, r2, r3):

        yield from self.peer2.execute(
            f"neighbor {r1.ifaces[0].ip4[0].ip} announce route 100.10.0.0/24 next-hop self"
        )

        expected = {
            "routes": {
                "100.10.0.0/24": [
                    {
                        "valid": True,
                        "network": "100.10.0.0/24",
                        "peerId": "10.101.0.3",
                        "path": "65002",
                        "origin": "IGP",
                        "nexthops": [
                            {
                                "ip": "10.101.0.3",
                            }
                        ],
                    }
                ]
            }
        }
        yield from AssertVtysh.make(
            r1, "bgpd", "show ip bgp json", maxwait=5.0, compare=expected
        )
