# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar


"""
rfc6286: Autonomous-System-Wide Unique BGP Identifier for BGP-4
Test if 'Bad BGP Identifier' notification is sent only to
internal peers (autonomous-system-wide). eBGP peers are not
affected and should work.
"""

__topotests_file__ = "bgp_as_wide_bgp_identifier/test_bgp_as_wide_bgp_identifier.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

# pylint: disable=wildcard-import, unused-wildcard-import

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

    topo.router("r1").iface_to("s1").ip4.append("192.168.255.2/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.255.1/24")
    topo.router("r3").iface_to("s1").ip4.append("192.168.255.3/24")


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
    router bgp 65001
      bgp router-id 10.10.10.10
      no bgp ebgp-requires-policy
      neighbor 192.168.255.1 remote-as 65002
      neighbor 192.168.255.1 timers 3 10
    !
    #%   elif router.name == 'r2'
    router bgp 65002
      bgp router-id 10.10.10.10
      no bgp ebgp-requires-policy
      neighbor 192.168.255.2 remote-as 65001
      neighbor 192.168.255.2 timers 3 10
      neighbor 192.168.255.3 remote-as 65002
      neighbor 192.168.255.3 timers 3 10
    !
    #%   elif router.name == 'r3'
    router bgp 65002
      bgp router-id 10.10.10.10
      no bgp ebgp-requires-policy
      neighbor 192.168.255.1 remote-as 65002
      neighbor 192.168.255.1 timers 3 10
    !
    #%   endif
    #% endblock
  """


class TestBGPAsWideBGPIdentifier(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, _, r1):
        expected = {"192.168.255.1": {"bgpState": "Established"}}
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            "show ip bgp neighbor 192.168.255.1 json",
            maxwait=2.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_failed(self, _, r3):
        expected = {
            "192.168.255.1": {
                "lastNotificationReason": "OPEN Message Error/Bad BGP Identifier"
            }
        }
        yield from AssertVtysh.make(
            r3,
            "bgpd",
            "show ip bgp neighbor 192.168.255.1 json",
            maxwait=2.0,
            compare=expected,
        )
