# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Nathan Mangar

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


__topotests_file__ = (
    "bgp_ebgp_common_subnet_nexthop_unchanged/test_bgp-ebgp-common-subnet-nexthop-unchanged.py"
)
__topotests_gitrev__ = "a53c08bc131c02f4a20931d7aa9f974194ab16e7"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

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


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

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
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65103
     no bgp ebgp-requires-policy
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   elif router.name == 'r3'
    router bgp 65000
     bgp router-id {{ routers.r3.iface_to('s1').ip4[0].ip }}
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   endif
    #% endblock
    """


class BGPEbgpCommonSubnetNexthopUnchanged(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, _, r1, r2, r3):
        expected = {
            "ipv4Unicast": {
                "peers": {
                    str(r1.iface_to("s1").ip4[0].ip): {"state": "Established"},
                    str(r2.iface_to("s1").ip4[0].ip): {"state": "Established"},
                }
            }
        }
        yield from AssertVtysh.make(
            r3,
            "bgpd",
            f"show ip bgp summary json",
            maxwait=2.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_nh_unchanged(self, _, r1, r2):
        expected = {"paths": [{"nexthops": [{"ip": str(r1.iface_to("s1").ip4[0].ip)}]}]}
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp {r1.lo_ip4[0]} json",
            maxwait=3.0,
            compare=expected,
        )     
