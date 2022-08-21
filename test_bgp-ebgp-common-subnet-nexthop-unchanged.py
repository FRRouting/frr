from topotato import *

"""
https://tools.ietf.org/html/rfc4271

Check if NEXT_HOP attribute is not changed if peer X shares a
common subnet with this address.

- Otherwise, if the route being announced was learned from an
  external peer, the speaker can use an IP address of any
  adjacent router (known from the received NEXT_HOP attribute)
  that the speaker itself uses for local route calculation in
  the NEXT_HOP attribute, provided that peer X shares a common
  subnet with this address.  This is a second form of "third
  party" NEXT_HOP attribute.
"""


@topology_fixture()
def allproto_topo(topo):
    """
    [ r1 ]
      |
    { s1 }--[ r3 ]
      |
    [ r2 ]

    """
    topo.router("r1").lo_ip4.append("172.16.1.1/32")
    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.1.103/24")
    topo.router("r3").iface_to("s1").ip4.append("192.168.1.101/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    interface lo
     ip address {{ routers.r1.lo_ip4[0] }} 
    !
    interface r1-eth0
    ip address {{ routers.r1.ifaces[0].ip4[0].ip }}
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
    router bgp 65103
     no bgp ebgp-requires-policy
     neighbor 192.168.1.101 remote-as external
    !
    #%   elif router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor 192.168.1.101 remote-as external
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r3'
    router bgp 65000
     bgp router-id 192.168.1.101
     no bgp ebgp-requires-policy
     neighbor 192.168.1.1 remote-as external
     neighbor 192.168.1.103 remote-as external
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


class BGPEbgpCommonSubnetNhUnchanged(TestBase):
    instancefn = testenv

    @topotatofunc
    def bgp_converge(self, topo, r1, r2, r3):
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.1.1": {"state": "Established"},
                    "192.168.1.103": {"state": "Established"},
                }
            }
        }
        yield from AssertVtysh.make(
            r3,
            "bgpd",
            f"show ip bgp summary json",
            maxwait=3.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_nh_unchanged(self, topo, r1, r2):
        expected = {"paths": [{"nexthops": [{"ip": "192.168.1.1"}]}]}
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp 172.16.1.1/32 json",
            maxwait=3.0,
            compare=expected,
        )
