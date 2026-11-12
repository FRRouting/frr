#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if BGP SoO per neighbor works correctly. Routes having SoO
extended community MUST be rejected if the neighbor is configured
with soo (neighbor soo).

test_bgp_soo() validates the core SoO functionality:
- PE1 attaches SoO 65000:1 to routes received from CPE1
- PE2 imports these routes via VPN
- When PE2 has "neighbor soo 65000:1" configured for CPE2, routes
  with matching SoO are filtered (not advertised to CPE2)

test_bgp_soo_peer_group() moves the PE2 -- CPE2 session into a
peer-group and checks that "neighbor soo" set on the peer-group is
applied to a member that is already bound, that a member-level value
overrides the group, and that "no" on the member restores the group
value.

The remaining tests use this SoO/VPN topology to validate the JSON
output format for neighbor routes and advertised-routes commands.
They verify JSON structure and path counts, not SoO behavior.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step, shutdown_bringup_interface_in_kernel

pytestmark = [pytest.mark.bgpd, pytest.mark.ldpd, pytest.mark.ospfd]


def build_topo(tgen):
    tgen.add_router("cpe1")
    tgen.add_router("cpe2")
    tgen.add_router("pe1")
    tgen.add_router("pe2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["cpe1"])
    switch.add_link(tgen.gears["pe1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["pe1"])
    switch.add_link(tgen.gears["pe2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["pe2"])
    switch.add_link(tgen.gears["cpe2"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["cpe2"])
    switch.add_link(tgen.gears["cpe1"])


def setup_module(mod):
    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["pe1"]
    pe2 = tgen.gears["pe2"]

    pe1.run("ip link add RED type vrf table 1001")
    shutdown_bringup_interface_in_kernel(pe1.tgen, pe1.name, "RED", True)
    pe2.run("ip link add RED type vrf table 1001")
    shutdown_bringup_interface_in_kernel(pe2.tgen, pe2.name, "RED", True)
    pe1.run("ip link set pe1-eth0 master RED")
    pe2.run("ip link set pe2-eth1 master RED")

    pe1.run("sysctl -w net.ipv4.ip_forward=1")
    pe2.run("sysctl -w net.ipv4.ip_forward=1")
    pe1.run("sysctl -w net.mpls.conf.pe1-eth0.input=1")
    pe2.run("sysctl -w net.mpls.conf.pe2-eth1.input=1")

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_LDP, os.path.join(CWD, "{}/ldpd.conf".format(rname))
        )

    tgen.start_router()

    for _, (_, router) in enumerate(router_list.items(), 1):
        router.run("sysctl -w net.ipv6.conf.all.forwarding=1")


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_soo():
    tgen = get_topogen()

    pe2 = tgen.gears["pe2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_soo_unconfigured():
        output = json.loads(
            pe2.vtysh_cmd(
                "show bgp vrf RED ipv4 unicast neighbors 192.168.2.1 advertised-routes json"
            )
        )
        expected = {"advertisedRoutes": {"172.16.255.1/32": {"path": "65001 65001"}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_soo_unconfigured)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see BGP convergence in pe2"

    step("Configure SoO (65000:1) for PE2 -- CPE2 session")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      neighbor 192.168.2.1 soo 65000:1
    """
    )

    def _bgp_soo_configured():
        output = json.loads(
            pe2.vtysh_cmd(
                "show bgp vrf RED ipv4 unicast neighbors 192.168.2.1 advertised-routes json"
            )
        )
        expected = {"advertisedRoutes": {"172.16.255.1/32": None}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_soo_configured)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "SoO filtering does not work from pe2"

    step("Configure SoO (65000:2) for PE2 -- CPE2 session")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      neighbor 192.168.2.1 soo 65000:2
    """
    )

    test_func = functools.partial(_bgp_soo_unconfigured)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "SoO filtering does not work from pe2"

    step("Unconfigure SoO for PE2 -- CPE2 session")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      no neighbor 192.168.2.1 soo
    """
    )

    test_func = functools.partial(_bgp_soo_unconfigured)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "SoO filtering does not work from pe2"


def test_bgp_soo_pe1_neighbor_routes_json():
    """
    PE1 (VRF RED): routes learned from CPE1 (192.168.1.1) as full JSON — four
    VPN prefixes with path arrays; totals match RIB size for this view.
    """
    tgen = get_topogen()

    pe1 = tgen.gears["pe1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _pe1_routes_json():
        output = json.loads(
            pe1.vtysh_cmd(
                "show bgp vrf RED ipv4 unicast neighbors 192.168.1.1 routes json"
            )
        )
        expected = {
            "routes": {
                "10.0.0.0/24": [
                    {
                        "valid": True,
                        "bestpath": True,
                        "network": "10.0.0.0/24",
                        "peerId": "192.168.1.1",
                    }
                ],
                "172.16.255.1/32": [
                    {
                        "valid": True,
                        "bestpath": True,
                        "network": "172.16.255.1/32",
                        "peerId": "192.168.1.1",
                    }
                ],
                "192.168.1.0/24": [
                    {
                        "valid": True,
                        "bestpath": True,
                        "network": "192.168.1.0/24",
                        "peerId": "192.168.1.1",
                    }
                ],
                "192.168.2.0/24": [
                    {
                        "valid": True,
                        "bestpath": True,
                        "network": "192.168.2.0/24",
                        "peerId": "192.168.1.1",
                    }
                ],
            },
            "totalRoutes": 4,
            "totalPaths": 8,
            "numRoutes": 4,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_pe1_routes_json)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert (
        result is None
    ), "PE1 vrf RED neighbor 192.168.1.1 routes json missing expected prefixes or totals"


def test_bgp_soo_pe1_neighbor_routes_brief_json():
    """
    PE1 (VRF RED): neighbor routes json brief — per-prefix pathCount, multipath
    aggregate, and bestPathExists under routes{}.
    """
    tgen = get_topogen()

    pe1 = tgen.gears["pe1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _pe1_routes_brief_json():
        output = json.loads(
            pe1.vtysh_cmd(
                "show bgp vrf RED ipv4 unicast neighbors 192.168.1.1 "
                "routes json brief"
            )
        )
        expected = {
            "routes": {
                "10.0.0.0/24": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 1,
                    "multiPathCount": 1,
                },
                "172.16.255.1/32": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 1,
                    "multiPathCount": 1,
                },
                "192.168.1.0/24": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 1,
                    "multiPathCount": 1,
                },
                "192.168.2.0/24": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 1,
                    "multiPathCount": 1,
                },
            },
            "totalRoutes": 4,
            "totalPaths": 8,
            "numRoutes": 4,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_pe1_routes_brief_json)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert (
        result is None
    ), "PE1 vrf RED neighbor routes json brief does not match expected shape"


def test_bgp_soo_cpe1_neighbor_ipv6_routes_json():
    """
    CPE1 (default vrf): IPv6 neighbor routes JSON from iBGP peer cpe2
    (2001:db8:10::2). PE vrf RED may have no IPv6 CE session; this topology
    still exercises neighbor routes json on CPE. Remote 2001:db8:2::/64 is
    best; peering 2001:db8:10::/64 is valid from peer but has no best path in
    this neighbor view (local connected / duplicate resolution).
    """
    tgen = get_topogen()

    cpe1 = tgen.gears["cpe1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _cpe1_routes_v6_json():
        output = json.loads(
            cpe1.vtysh_cmd(
                "show bgp vrf default ipv6 unicast neighbors 2001:db8:10::2 "
                "routes json"
            )
        )
        expected = {
            "routes": {
                "2001:db8:2::/64": [
                    {
                        "valid": True,
                        "bestpath": True,
                        "network": "2001:db8:2::/64",
                        "peerId": "2001:db8:10::2",
                    }
                ],
                "2001:db8:10::/64": [
                    {
                        "valid": True,
                        "bestpath": None,
                        "network": "2001:db8:10::/64",
                        "peerId": "2001:db8:10::2",
                    }
                ],
            },
            "totalRoutes": 2,
            "totalPaths": 5,
            "numRoutes": 2,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_cpe1_routes_v6_json)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, (
        "CPE1 default ipv6 neighbor 2001:db8:10::2 routes json does not match "
        "expected prefixes or totals"
    )


def test_bgp_soo_cpe1_neighbor_ipv6_routes_json_brief():
    """CPE1 (default): neighbor IPv6 routes json brief — two-prefix iBGP view."""
    tgen = get_topogen()

    cpe1 = tgen.gears["cpe1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _cpe1_routes_v6_brief():
        output = json.loads(
            cpe1.vtysh_cmd(
                "show bgp vrf default ipv6 unicast neighbors 2001:db8:10::2 "
                "routes json brief"
            )
        )
        expected = {
            "routes": {
                "2001:db8:2::/64": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 1,
                    "multiPathCount": 1,
                },
                "2001:db8:10::/64": {
                    "flags": {"bestPathExists": False},
                    "pathCount": 1,
                    "multiPathCount": 0,
                },
            },
            "totalRoutes": 2,
            "totalPaths": 5,
            "numRoutes": 2,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_cpe1_routes_v6_brief)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert (
        result is None
    ), "CPE1 default ipv6 neighbor routes json brief does not match expected shape"


def test_bgp_soo_ipv4_advertised_routes_brief_json():
    """
    CPE1 (vrf default): neighbor advertised-routes json brief lists redistributed
    and learned prefixes with flags and path counts.
    """
    tgen = get_topogen()

    cpe1 = tgen.gears["cpe1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _ipv4_adv_brief():
        output = json.loads(
            cpe1.vtysh_cmd(
                "show bgp vrf default ipv4 unicast neighbors 192.168.1.2 "
                "advertised-routes json brief"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.0.0.0/24": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 2,
                    "multiPathCount": 1,
                },
                "172.16.255.1/32": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 1,
                    "multiPathCount": 1,
                },
                "192.168.1.0/24": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 1,
                    "multiPathCount": 1,
                },
                "192.168.2.0/24": {
                    "flags": {"bestPathExists": True},
                    "pathCount": 1,
                    "multiPathCount": 1,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_ipv4_adv_brief)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert (
        result is None
    ), "IPv4 advertised-routes json brief on cpe1 does not match expected prefixes/shape"


def test_bgp_soo_ipv6_advertised_routes_brief_json():
    """
    CPE2 runs BGP in vrf default; IPv6 eBGP to PE2 (2001:db8:2::2). Redistributed
    connected 2001:db8:2::/64 appears in neighbor advertised-routes json brief.
    """
    tgen = get_topogen()

    cpe2 = tgen.gears["cpe2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _ipv6_adv_brief():
        output = json.loads(
            cpe2.vtysh_cmd(
                "show bgp vrf default ipv6 unicast neighbors 2001:db8:2::2 "
                "advertised-routes json brief"
            )
        )
        expected = {
            "advertisedRoutes": {
                "2001:db8:2::/64": {
                    "flags": {"bestPathExists": "*"},
                    "pathCount": "*",
                    "multiPathCount": "*",
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_ipv6_adv_brief)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert (
        result is None
    ), "IPv6 advertised-routes json brief missing 2001:db8:2::/64 or expected shape on cpe2"


def test_bgp_soo_peer_group():
    """
    SoO configured on a peer-group is applied to a member that is
    already bound to the group; a value configured directly on the
    member overrides the group value, and "no neighbor MEMBER soo"
    restores the value inherited from the group.
    """
    tgen = get_topogen()

    pe2 = tgen.gears["pe2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _adv_routes():
        return pe2.vtysh_cmd(
            "show bgp vrf RED ipv4 unicast neighbors 192.168.2.1 "
            "advertised-routes json"
        )

    def _expect(advertised, message):
        def _check():
            output = json.loads(_adv_routes())
            if advertised:
                expected = {
                    "advertisedRoutes": {"172.16.255.1/32": {"path": "65001 65001"}}
                }
            else:
                expected = {"advertisedRoutes": {"172.16.255.1/32": None}}
            return topotest.json_cmp(output, expected)

        test_func = functools.partial(_check)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
        assert result is None, message

    step("PE2 advertises 172.16.255.1/32 to CPE2 (no SoO configured)")
    _expect(True, "PE2 does not advertise 172.16.255.1/32 to CPE2")

    step("Bind CPE2 to peer-group PG (activate ipv4 unicast on the group first)")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     neighbor PG peer-group
     address-family ipv4 unicast
      neighbor PG activate
     exit-address-family
     neighbor 192.168.2.1 peer-group PG
    """
    )
    _expect(
        True,
        "172.16.255.1/32 is not advertised to CPE2 after binding it to PG",
    )

    step("Set SoO 65000:1 on peer-group PG, the member is already bound")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      neighbor PG soo 65000:1
    """
    )
    _expect(
        False,
        "SoO of the peer-group is not applied to the already bound member",
    )

    step("Change SoO on peer-group PG to 65000:2")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      neighbor PG soo 65000:2
    """
    )
    _expect(
        True,
        "Changed SoO of the peer-group is not applied to the member",
    )

    step("Restore SoO 65000:1 on peer-group PG")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      neighbor PG soo 65000:1
    """
    )
    _expect(
        False,
        "SoO of the peer-group is not applied to the member again",
    )

    step("Override SoO with 65000:2 on the member 192.168.2.1")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      neighbor 192.168.2.1 soo 65000:2
    """
    )
    _expect(True, "SoO of the member does not override the SoO of the group")

    step("Remove SoO from the member, it inherits 65000:1 from PG again")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      no neighbor 192.168.2.1 soo
    """
    )
    _expect(
        False,
        "SoO of the peer-group is not inherited after no on the member",
    )

    step("Remove SoO from peer-group PG")
    pe2.vtysh_cmd(
        """
    configure terminal
    router bgp 65001 vrf RED
     address-family ipv4 unicast
      no neighbor PG soo
    """
    )
    _expect(True, "SoO is not removed from the member by no on the peer-group")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
