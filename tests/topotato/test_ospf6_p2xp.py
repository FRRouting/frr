#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
OSPFv3 basic point-to-multipoint test
"""

from topotato.v1 import *


@topology_fixture()
def topology(topo):
    """
    { lan }
    {     }---[ r1 ]
    {     }
    {     }---[ r2 ]
    {     }
    {     }---[ r3 ]---[ lsdb ]
    """


class Configs(FRRConfigs):
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

    ospf6d = """
    #% extends "boilerplate.conf"
    #% block main
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     description {{ iface.other.endpoint.name }}
     ipv6 ospf6 area 0.0.0.0
    #%     if iface.other.endpoint.name == "lan"
     ipv6 ospf6 network point-to-multipoint
    #%     endif
     ipv6 ospf6 hello-interval 1
     ipv6 ospf6 dead-interval 2
     ipv6 ospf6 retransmit-interval 3
    #%   endfor
    !
    !
    router ospf6
     log-adjacency-changes
     ospf6 router-id {{ router.lo_ip4[0].ip }}
    #% endblock
    """


class PtMPBasic(TestBase, AutoFixture, topo=topology, configs=Configs):
    # intra_64 = connected-prefix include/exclude
    def lsdb_reference(self, routers, intra_64=set()):
        lsas = [
            JSONCompareIgnoreExtraListitems(),
            JSONCompareListKeyedDict("advertisingRouter", "type", "linkStateId"),
        ]
        for rtr in routers:
            neighbors = []
            for other in routers:
                if rtr == other:
                    continue
                neighbors.append(
                    {
                        "type": "Point-To-Point",
                        "neighborRouterId": str(other.lo_ip4[0].ip),
                    }
                )
            lsas.append(
                {
                    "type": "Router",
                    "linkStateId": "0.0.0.0",
                    "advertisingRouter": str(rtr.lo_ip4[0].ip),
                    "bits": "--------",
                    "options": "--|-|--|-|-|--|R|-|--|E|V6",
                    "lsaDescription": neighbors,
                }
            )

            prefixes = [
                {
                    "prefixOption": "--|--|--|LA|--",
                    "prefix": str(rtr.iface_to("lan").ip6[0].ip) + "/128",
                }
            ]
            if rtr.name in intra_64:
                prefixes.append(
                    {
                        "prefixOption": "--|--|--|--|--",
                        "prefix": str(rtr.iface_to("lan").ip6[0].network),
                    }
                )

            lsas.append(
                {
                    "type": "Intra-Prefix",
                    "advertisingRouter": str(rtr.lo_ip4[0].ip),
                    "numberOfPrefix": len(prefixes),
                    "reference": "Router",
                    "referenceId": "0.0.0.0",
                    "prefix": prefixes,
                }
            )

        return {
            "areaScopedLinkStateDb": [
                JSONCompareIgnoreExtraListitems(),
                JSONCompareListKeyedDict("areaId"),
                {"areaId": "0.0.0.0", "lsa": lsas},
            ]
        }

    @topotatofunc
    def bringup(self, topo, r1, r2, r3, lsdb):
        """
        Wait for all OSPFv3 neighbors to be up before running actual tests.

        This includes P2MP bringup since link-type is included in initial
        config.
        """
        # "lsdb" router is only used as separate router to check LSDB on
        ptmp_routers = [r1, r2, r3]
        all_routers = ptmp_routers + [lsdb]

        for rtr in ptmp_routers:
            ifname = rtr.iface_to("lan").ifname
            neighbors = []
            for other in ptmp_routers:
                if other != rtr:
                    neighbors.append(
                        {
                            "interfaceName": ifname,
                            "neighborId": str(other.lo_ip4[0].ip),
                            "state": "Full",
                            "ifState": "PtMultipoint",
                            "interfaceState": "PtMultipoint",
                        }
                    )

            yield from AssertVtysh.make(
                rtr,
                "ospf6d",
                "show ipv6 ospf neighbor json",
                {
                    "neighbors": neighbors,
                },
                maxwait=5.0,
            )

        # make sure it's fully up before checking LSDB on "lsdb" router
        yield from AssertVtysh.make(
            lsdb,
            "ospf6d",
            "show ipv6 ospf neighbor json",
            {
                "neighbors": [
                    {
                        "interfaceName": lsdb.iface_to("r3").ifname,
                        "state": "Full",
                    },
                ],
            },
            maxwait=5.0,
        )

        expected_lsdb = self.lsdb_reference(ptmp_routers)
        for rtr in all_routers:
            yield from AssertVtysh.make(
                rtr,
                "ospf6d",
                "show ipv6 ospf6 database detail json",
                expected_lsdb,
                maxwait=10.0,
            )

    @topotatofunc
    def connected_pfx_r1(self, topo, r1, r2, r3, lsdb):
        """
        Enable advertising connected prefix on P2MP link on r1 and check result.
        """
        ptmp_routers = [r1, r2, r3]
        all_routers = ptmp_routers + [lsdb]

        # advertise connected prefix on r1
        yield from ReconfigureFRR.make(
            r1,
            "ospf6d",
            "\n".join(
                [
                    "interface %s" % r1.iface_to("lan").ifname,
                    "ipv6 ospf6 p2p-p2mp connected-prefixes include",
                ]
            ),
        )

        expected_lsdb = self.lsdb_reference(ptmp_routers, {"r1"})
        for rtr in all_routers:
            yield from AssertVtysh.make(
                rtr,
                "ospf6d",
                "show ipv6 ospf6 database detail json",
                expected_lsdb,
                maxwait=5.0,
            )

    @topotatofunc
    def connected_pfx_r3(self, topo, r1, r2, r3, lsdb):
        """
        Enable advertising connected prefix on P2MP link on r3 and check result.
        """
        ptmp_routers = [r1, r2, r3]
        all_routers = ptmp_routers + [lsdb]

        # advertise connected prefix on r1
        yield from ReconfigureFRR.make(
            r3,
            "ospf6d",
            "\n".join(
                [
                    "interface %s" % r3.iface_to("lan").ifname,
                    "ipv6 ospf6 p2p-p2mp connected-prefixes include",
                ]
            ),
        )

        expected_lsdb = self.lsdb_reference(ptmp_routers, {"r1", "r3"})
        for rtr in all_routers:
            yield from AssertVtysh.make(
                rtr,
                "ospf6d",
                "show ipv6 ospf6 database detail json",
                expected_lsdb,
                maxwait=3.0,
            )
