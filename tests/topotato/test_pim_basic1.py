#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
"""
Basic IPv4 PIM test.

TBD: Currently uses BGP to set up routes.  Should probably be removed and
replaced with static routes.
"""

from topotato.v1 import *
from topotato.multicast import MulticastReceiver
from topotato.scapy import ScapySend
from scapy.all import (
    IP,
    UDP,
)


@topology_fixture()
def pim_topo1(topo):
    """
    [ rp ]
       |
    { lan1 }
       |
    [ r1             ]
       |         |
    { lan2 }  { lan3 }
       |         |
    [ r2   ]  [ r3   ]
    """


class Configs(FRRConfigs):
    zebra = """
    #% extends "boilerplate.conf"
    """

    bgpd = """
    #% extends "boilerplate.conf"
    #% block main
    ##
    #%   if router.name == 'rp'
    router bgp 65000
    #%   else
    router bgp 65001
    #%   endif
    ##
     no bgp ebgp-requires-policy
     neighbor {{ router.flip("rp", "r1").iface_to("lan1").ip4[0].ip }} remote-as external
     neighbor {{ router.flip("rp", "r1").iface_to("lan1").ip4[0].ip }} timers 3 10
     neighbor {{ router.flip("rp", "r1").iface_to("lan1").ip4[0].ip }} timers connect 1
     redistribute connected
    #% endblock
    """
    bgpd_routers = ["rp", "r1"]

    pimd = """
    #% extends "boilerplate.conf"
    #% block main
    ##
    #%   if router.name in ['r1', 'rp']
    interface lo
     ip pim
    ##
    #%     for iface in router.ifaces
    !
    interface {{ iface.ifname }}
    ## no IGMP on RP
    #%       if router.name == 'r1'
     ip igmp
    #%       endif
    ##
     ip pim
     ip pim hello 1 5
    #%     endfor
    ##
    ##
    !
    ip pim rp {{ routers["rp"].lo_ip4[0].ip }}
    #%      if router.name == 'rp'
    ip pim register-accept-list ACCEPT

    ip prefix-list ACCEPT seq 5 permit 10.102.0.0/24 le 32
    #%      endif
    #%   endif
    #% endblock
    """


@config_fixture(Configs)
def pim_topo1_configs(config, pim_topo1):
    return config


@instance_fixture()
def pim_topo1_testenv(pim_topo1_configs):
    instance = FRRNetworkInstance(pim_topo1_configs.topology, pim_topo1_configs)
    instance.prepare()
    return instance


class PIMTopo1Test(TestBase):
    instancefn = pim_topo1_testenv

    @topotatofunc
    def test(self, topo, rp, r1, r2, r3):
        r2_addr = str(r2.iface_to("lan2").ip4[0].ip)
        r3_addr = str(r3.iface_to('lan3').ip4[0].ip)

        # wait for BGP to come up
        js = {
            str(rp.lo_ip4[0]): JSONCompareIgnoreContent(),
        }
        yield from AssertKernelRoutesV4.make(r1.name, js, maxwait=10.0)

        js = {
            str(rp.lo_ip4[0].ip): [
                {
                    "outboundInterface": "r1-lan1",
                    "group": "224.0.0.0/4",
                    "source": "Static",
                },
            ],
        }
        yield from AssertVtysh.make(
            r1, "pimd", "show ip pim rp-info json", js, maxwait=15.0
        )

        r2_pkt = IP(ttl=255, src=r2_addr, dst='229.1.1.1') / UDP(sport=9999, dport=9999)
        r3_pkt = IP(ttl=255, src=r3_addr, dst='229.1.1.1') / UDP(sport=9999, dport=9999)

        for rtr, pkt, iface in [(r2, r2_pkt, "r2-lan2"), (r3, r3_pkt, "r3-lan3")]:
            yield from ScapySend.make(rtr, iface, pkt=pkt, repeat=3, interval=0.5)

        js = {
            "229.1.1.1": {
                r2_addr: {
                    "firstHopRouter": 1,
                    "joinState": "NotJoined",
                    "regState": "RegPrune",
                    "inboundInterface": "r1-lan2",
                }
            }
        }
        yield from AssertVtysh.make(r1, "pimd", "show ip pim upstream json", js)

        js = {
            "229.1.1.1": {
                r2_addr: {
                    "sourceStream": True,
                    "inboundInterface": "rp-lan1",
                    "rpfAddress": r2_addr,
                    "source": r2_addr,
                    "group": "229.1.1.1",
                    "state": "NotJ",
                    "joinState": "NotJoined",
                    "regState": "RegNoInfo",
                    "resetTimer": "--:--:--",
                    "refCount": 1,
                    "sptBit": 0,
                }
            }
        }
        yield from AssertVtysh.make(rp, "pimd", "show ip pim upstream json", js)

    @topotatofunc
    def test_join(self, topo, rp, r1, r2, r3):
        r3_addr = str(r3.iface_to('lan3').ip4[0].ip)

        receiver = MulticastReceiver(r2, r2.iface_to('lan2'))
        yield from receiver.join('229.1.1.2')

        js = {
            "229.1.1.2": {
                "*": {
                    "sourceIgmp": 1,
                    "joinState": "Joined",
                    "regState": "RegNoInfo",
                    "sptBit": 0,
                }
            }
        }
        yield from AssertVtysh.make(
            r1, "pimd", "show ip pim upstream json", js, maxwait=20.0
        )

        r3_pkt = IP(ttl=255, src=r3_addr, dst='229.1.1.2') / UDP(sport=9999, dport=9999)

        for rtr, pkt, iface in [(r3, r3_pkt, "r3-lan3")]:
            yield from ScapySend.make(rtr, iface, pkt=pkt, repeat=3, interval=0.5)

        def expect_pkt(ip: IP, udp: UDP):
            return ip.src == str(r3_addr) and ip.dst == '229.1.1.2' \
                and udp.dport == 9999
        yield from AssertPacket.make("lan2", maxwait=1.0, pkt=expect_pkt)
