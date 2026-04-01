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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


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
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["pe1"]
    pe2 = tgen.gears["pe2"]

    pe1.run("ip link add RED type vrf table 1001")
    pe1.run("ip link set up dev RED")
    pe2.run("ip link add RED type vrf table 1001")
    pe2.run("ip link set up dev RED")
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
        expected = {"advertisedRoutes": {"172.16.255.1/32": {"path": "65001"}}}
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
