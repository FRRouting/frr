from topotato import *

"""
Test if `set as-path replace` is working correctly for route-maps.
"""


@topology_fixture()
def allproto_topo(topo):
    """
    [ r1 ]
      |
    { s1 }--[ r3 ]
      |       |
    [ r2 ]--{ s2 }


    """
    topo.router("r3").lo_ip4.append("172.16.255.31/32")
    topo.router("r3").lo_ip4.append("172.16.255.32/32")
    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")
    topo.router("r2").iface_to("s2").ip4.append("192.168.2.2/24")
    topo.router("r3").iface_to("s1").ip4.append("192.168.2.1/24")


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
     no bgp ebgp-requires-policy
     neighbor 192.168.1.2 remote-as external
     neighbor 192.168.1.2 timers 3 10
     address-family ipv4 unicast
      neighbor 192.168.1.2 route-map r2 in
     exit-address-family
    !
    ip prefix-list p1 seq 5 permit 172.16.255.31/32
    !
    route-map r2 permit 10
     match ip address prefix-list p1
     set as-path replace 65003
    route-map r2 permit 20
     set as-path replace any
    !
    #%   endif
    #%   if router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor 192.168.1.1 remote-as external
     neighbor 192.168.1.1 timers 3 10
     neighbor 192.168.2.1 remote-as external
     neighbor 192.168.2.1 timers 3 10
    !
    #%   endif
    #%   if router.name == 'r3'
    router bgp 65003
     no bgp ebgp-requires-policy
     neighbor 192.168.2.2 remote-as external
     neighbor 192.168.2.2 timers 3 10
     address-family ipv4 unicast
      redistribute connected
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


class BGPSetAspathReplace(TestBase):
    instancefn = testenv

    @topotatofunc
    def bgp_converge(self, topo, r1, r2, r3):
        expected = {
            "routes": {
                "172.16.255.31/32": [{"path": "65002 65001"}],
                "172.16.255.32/32": [{"path": "65001 65001"}],
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=6.0,
            compare=expected,
        )
