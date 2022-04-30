import pytest

from topotato import *


@topology_fixture()
def rip_topo(topo):
    """
    [    ]--{ stub1 }
    [    ]
    [ r1 ]--{ stub2 }
    [    ]
    [    ]--{ stub3 }
       |
    { lan1 }
       |
    [ r2 ]
       |
    { lan2 }
       |
    [ r3 ]
       |
    { lan3 }
       |
    [ rtsta ]--{ lansta }
    """
    topo.lan("lan1").ip4.append("193.1.1.0/26")
    topo.lan("lan2").ip4.append("193.1.2.0/26")

    topo.noauto_v6 = True
    topo.lo_v4 = False


class Configs(FRRConfigs):
    zebra_rtrs = ["r1", "r2", "r3"]
    zebra = """
    #% extends "boilerplate.conf"
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     no link-detect
    #%   endfor
    """

    ripd_rtrs = ["r1", "r2", "r3"]
    ripd = """
    #% extends "boilerplate.conf"
    #% block main
    router rip
     version 2
     timers basic 5 180 5
    ##
    #%   if router.name == 'r1'
     network 193.1.1.0/26
     network r1-stub2
     network r1-stub3
     passive-interface r1-stub3
    ##
    #%   elif router.name == 'r2'
     network 193.1.1.0/26
     network 193.1.2.0/24
    ##
    #%   elif router.name == 'r3'
     redistribute connected
     redistribute static
     network 193.1.2.0/24
    #%   endif
    #% endblock
    """

    staticd_rtrs = ["r3"]
    staticd = """
    #% extends "boilerplate.conf"
    #% block main
    ip route 10.104.0.0/16 10.103.0.4
    #% endblock
    """


@config_fixture(Configs)
def rip_configs(config, rip_topo):
    return config


@instance_fixture()
def rip_testenv(rip_configs):
    instance = FRRNetworkInstance(rip_configs.topology, rip_configs)
    instance.prepare()
    return instance


class RIPBasic(TestBase):
    instancefn = rip_testenv

    @topotatofunc
    def test(self, topo, r1, r2, r3, rtsta):
        compare = r"""
            Routing Protocol is "rip"
              Sending updates every 5 seconds with +/-50%, next due in $$\d+$$ seconds
              Timeout after 180 seconds, garbage collect after 5 seconds
              Outgoing update filter list for all interface is not set
              Incoming update filter list for all interface is not set
              Default redistribution metric is 1
              Redistributing:
              Default version control: send version 2, receive version 2 
                Interface        Send  Recv   Key-chain
                r1-lan1          2     2      
                r1-stub2         2     2      
                r1-stub3         2     2      
              Routing for Networks:
                193.1.1.0/26
                r1-stub2
                r1-stub3
              Passive Interface(s):
                r1-stub3
              Routing Information Sources:
                Gateway          BadPackets BadRoutes  Distance Last Update
                193.1.1.2                0         0       120   $$[0-9:]+$$
              Distance: (default is 120)
        """
        yield from AssertVtysh.make(
            r1, "ripd", "show ip rip status", compare, maxwait=6.0
        )

        compare = r"""
            Routing Protocol is "rip"
              Sending updates every 5 seconds with +/-50%, next due in $$\d+$$ seconds
              Timeout after 180 seconds, garbage collect after 5 seconds
              Outgoing update filter list for all interface is not set
              Incoming update filter list for all interface is not set
              Default redistribution metric is 1
              Redistributing:
              Default version control: send version 2, receive version 2 
                Interface        Send  Recv   Key-chain
                r2-lan1          2     2      
                r2-lan2          2     2      
              Routing for Networks:
                193.1.1.0/26
                193.1.2.0/24
              Routing Information Sources:
                Gateway          BadPackets BadRoutes  Distance Last Update
                193.1.1.1                0         0       120   $$[0-9:]+$$
                193.1.2.3                0         0       120   $$[0-9:]+$$
              Distance: (default is 120)
        """
        yield from AssertVtysh.make(
            r2, "ripd", "show ip rip status", compare, maxwait=6.0
        )

        compare = r"""
            Routing Protocol is "rip"
              Sending updates every 5 seconds with +/-50%, next due in $$\d+$$ seconds
              Timeout after 180 seconds, garbage collect after 5 seconds
              Outgoing update filter list for all interface is not set
              Incoming update filter list for all interface is not set
              Default redistribution metric is 1
              Redistributing: connected static
              Default version control: send version 2, receive version 2 
                Interface        Send  Recv   Key-chain
                r3-lan2          2     2      
              Routing for Networks:
                193.1.2.0/24
              Routing Information Sources:
                Gateway          BadPackets BadRoutes  Distance Last Update
                193.1.2.2                0         0       120   $$[0-9:]+$$
              Distance: (default is 120)
        """
        yield from AssertVtysh.make(
            r3, "ripd", "show ip rip status", compare, maxwait=6.0
        )

        compare = r"""
            Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP
            Sub-codes:
                  (n) - normal, (s) - static, (d) - default, (r) - redistribute,
                  (i) - interface

                 Network            Next Hop         Metric From            Tag Time
            R(n) 10.103.0.0/16      193.1.1.2             3 193.1.1.2         0 $$[0-9:]+$$
            R(n) 10.104.0.0/16      193.1.1.2             3 193.1.1.2         0 $$[0-9:]+$$
            C(i) 10.106.0.0/16      0.0.0.0               1 self              0
            C(i) 10.107.0.0/16      0.0.0.0               1 self              0
            C(i) 193.1.1.0/26       0.0.0.0               1 self              0
            R(n) 193.1.2.0/26       193.1.1.2             2 193.1.1.2         0 $$[0-9:]+$$
        """
        yield from AssertVtysh.make(r1, "ripd", "show ip rip", compare, maxwait=10.0)

        compare = r"""
            Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP
            Sub-codes:
                  (n) - normal, (s) - static, (d) - default, (r) - redistribute,
                  (i) - interface

                 Network            Next Hop         Metric From            Tag Time
            R(n) 10.103.0.0/16      193.1.2.3             2 193.1.2.3         0 $$[0-9:]+$$
            R(n) 10.104.0.0/16      193.1.2.3             2 193.1.2.3         0 $$[0-9:]+$$
            R(n) 10.106.0.0/16      193.1.1.1             2 193.1.1.1         0 $$[0-9:]+$$
            R(n) 10.107.0.0/16      193.1.1.1             2 193.1.1.1         0 $$[0-9:]+$$
            C(i) 193.1.1.0/26       0.0.0.0               1 self              0
            C(i) 193.1.2.0/26       0.0.0.0               1 self              0
        """
        yield from AssertVtysh.make(r2, "ripd", "show ip rip", compare, maxwait=10.0)

        compare = r"""
            Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP
            Sub-codes:
                  (n) - normal, (s) - static, (d) - default, (r) - redistribute,
                  (i) - interface

                 Network            Next Hop         Metric From            Tag Time
            C(r) 10.103.0.0/16      0.0.0.0               1 self              0
            S(r) 10.104.0.0/16      10.103.0.4            1 self              0
            R(n) 10.106.0.0/16      193.1.2.2             3 193.1.2.2         0 $$[0-9:]+$$
            R(n) 10.107.0.0/16      193.1.2.2             3 193.1.2.2         0 $$[0-9:]+$$
            R(n) 193.1.1.0/26       193.1.2.2             2 193.1.2.2         0 $$[0-9:]+$$
            C(i) 193.1.2.0/26       0.0.0.0               1 self              0
        """
        yield from AssertVtysh.make(r3, "ripd", "show ip rip", compare, maxwait=10.0)
