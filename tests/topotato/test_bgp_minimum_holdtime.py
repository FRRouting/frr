#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

"""
Test if minimum-holdtime works.
"""

__topotests_file__ = "bgp_minimum_holdtime/test_bgp_minimum_holdtime.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

# pylint: disable=wildcard-import, unused-wildcard-import

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

    topo.router("r1").iface_to("s1").ip4.append("192.168.255.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.255.2/24")


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
     neighbor 192.168.255.1 remote-as 65000
     neighbor 192.168.255.1 timers 3 10
    !
    #%   elif router.name == 'r1'
    router bgp 65000
     bgp minimum-holdtime 20
     neighbor 192.168.255.2 remote-as 65001
     neighbor 192.168.255.2 timers 3 10
     neighbor 192.168.255.2 timers connect 10
    !
    #%   endif
    #% endblock
    """


class TestBGPMinimumHoldtime(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_neighbor_check_if_notification_sent(self, _, r1):
        expected = {
            "192.168.255.2": {
                "connectionsEstablished": 0,
                "lastNotificationReason": "OPEN Message Error/Unacceptable Hold Time",
                "lastResetDueTo": "BGP Notification send",
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            "show ip bgp neighbor 192.168.255.2 json",
            maxwait=3.0,
            compare=expected,
        )
