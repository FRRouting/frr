#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
"""
Simple demo test for topotato.

TBD: check that the other protocols are up & running, to make it fully
equivalent to topotests "all_startup"
"""

from topotato.v1 import *


@topology_fixture()
def allproto_topo(topo):
    """
    [ r1 ]---[ noprot ]
    [    ]
    [    ]---[ rip ]
    [    ]
    [    ]---[ ripng ]
    [    ]
    [    ]---[ ospfv2 ]
    [    ]
    [    ]---[ ospfv3 ]
    [    ]
    [    ]---[ isisv4 ]
    [    ]
    [    ]---[ isisv6 ]
    """
    topo.router("r1").iface_to("ripng").ip6.append("fc00:0:0:1::1/64")


class Configs(FRRConfigs):
    routers = ["r1"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     description {{ iface.other.endpoint.name }}
     no link-detect
    !
    #%   endfor
    !
    ip forwarding
    ipv6 forwarding
    !
    #% endblock
    """

    ripd = """
    #% extends "boilerplate.conf"
    #% block main
    debug rip events
    debug rip zebra
    !
    router rip
     version 2
     network {{ router.iface_to('rip').ip4[0].network }}
    #% endblock
    """

    ripngd = """
    #% extends "boilerplate.conf"
    #% block main
    debug ripng events
    debug ripng zebra
    !
    router ripng
     network {{ router.iface_to('ripng').ip6[0].network }}
    #% endblock
    """


@config_fixture(Configs)
def configs(config, allproto_topo):
    return config


@instance_fixture()
def testenv(configs):
    return FRRNetworkInstance(configs.topology, configs).prepare()


class AllStartupTest(TestBase):
    """
    docstring here
    """
    instancefn = testenv

    @topotatofunc
    def test_running(self, topo, r1):
        """
        just check that all daemons are running
        """
        for daemon in Configs.daemons:
            if not hasattr(Configs, daemon):
                continue
            yield from AssertVtysh.make(r1, daemon, command="show version")

    @topotatofunc
    def test_ripd(self, topo, r1):
        compare = r"""
        Routing Protocol is "rip"
          Sending updates every 30 seconds with +/-50%, next due in $$\d+$$ seconds
          Timeout after 180 seconds, garbage collect after 120 seconds
          Outgoing update filter list for all interface is not set
          Incoming update filter list for all interface is not set
          Default redistribution metric is 1
          Redistributing:
          Default version control: send version 2, receive version 2 
            Interface        Send  Recv   Key-chain
            $$=router.iface_to('rip').ifname $$ 2     2      
          Routing for Networks:
            $$=router.iface_to('rip').ip4[0].network$$
          Routing Information Sources:
            Gateway          BadPackets BadRoutes  Distance Last Update
          Distance: (default is 120)
        """
        yield from AssertVtysh.make(
            r1, "ripd", "show ip rip status", maxwait=5.0, compare=compare
        )

    @topotatofunc
    def test_ripngd(self, topo, r1):
        compare = r"""
        Routing Protocol is "RIPng"
          Sending updates every 30 seconds with +/-50%, next due in $$\d+$$ seconds
          Timeout after 180 seconds, garbage collect after 120 seconds
          Outgoing update filter list for all interface is not set
          Incoming update filter list for all interface is not set
          Default redistribution metric is 1
          Redistributing:
          Default version control: send version 1, receive version 1 
            Interface        Send  Recv
            $$=router.iface_to('ripng').ifname $$ 1     1  
          Routing for Networks:
            $$=router.iface_to('ripng').ip6[0].network$$
          Routing Information Sources:
            Gateway          BadPackets BadRoutes  Distance Last Update
        """
        yield from AssertVtysh.make(
            r1, "ripngd", "show ip ripng status", maxwait=5.0, compare=compare
        )

    def test_other(self, configs):
        print(repr(list(configs["r1"].keys())))


if __name__ == "__main__":
    pass
#    cfgs = Configs()
#    cfgs.generate()
#
#    from pprint import pprint
#    pprint(cfgs)
#
#    import code
#    code.interact(local = locals())
