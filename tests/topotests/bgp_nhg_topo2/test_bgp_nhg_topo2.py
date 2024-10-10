#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_nhg_topo2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2024 by 6WIND
#

"""
 test_bgp_nhg_topo2.py: Test the FRR BGP daemon with EBGP direct connection
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgpcheck import (
    check_show_bgp_vpn_prefix_found,
    check_show_bgp_vpn_prefix_not_found,
)
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 2 routers.
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["r1"])


def _populate_iface():
    tgen = get_topogen()
    cmds_list_r1 = [
        "ip link add vrf1 type vrf table 10",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
        "ip link set dev vrf1 up",
        "ip link set dev {0}-eth3 master vrf1",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth3/input",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth0/input",
    ]

    for cmd in cmds_list_r1:
        input = cmd.format("r1")
        logger.info("input: " + cmd.format("r1"))
        output = tgen.net["r1"].cmd(cmd.format("r1"))
        logger.info("output: " + output)

    cmds_list_r4 = [
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth0/input",
    ]
    for cmd in cmds_list_r4:
        input = cmd.format("r4")
        logger.info("input: " + cmd.format("r4"))
        output = tgen.net["r4"].cmd(cmd.format("r4"))
        logger.info("output: " + output)


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _populate_iface()
    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
            "--v6-with-v4-nexthops",
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def test_protocols_convergence_ipv4():
    """
    Assert that BGP R1 has converged with IPv4 prefixes
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check that BGP R1 has converged with IPv4")
    router = tgen.gears["r1"]
    expected = json.loads(open("{}/r1/bgp_ipv4.json".format(CWD)).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp ipv4 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = (
        '"{}" JSON output mismatches, BGP R1 has not converged with IPv4'.format(
            router.name
        )
    )
    assert result is None, assertmsg


def check_bgp_nexthop_group_disabled_for_prefix(prefix, router_name):
    """
    Assert that the <prefix> prefix does not use BGP NHG
    because it is resolved over blackhole
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    donna = tgen.gears["r1"].vtysh_cmd(
        "show bgp nexthop-group detail json", isjson=True
    )
    nhg_found = False
    nhg_id = 0
    nb_paths = 0
    for nhg_ctx in donna:
        if "paths" not in nhg_ctx.keys():
            continue
        for path_ctx in nhg_ctx["paths"]:
            if "prefix" not in path_ctx.keys():
                continue
            nb_paths = nb_paths + 1
            if path_ctx["prefix"] == "192.168.2.0/24":
                nhg_found = True
                nhg_id = nhg_ctx["nhgId"]

    assertmsg = '"{}" no NHG paths found'.format(router_name)
    assert nb_paths != 0, assertmsg

    assertmsg = '"{}" 192.168.2.0 prefix found used with NHG {}'.format(
        router_name, nhg_id
    )
    assert nhg_found == False, assertmsg


def test_bgp_nexthop_group_disabled_for_blackhole():
    """
    Assert that the 192.168.2.0/24 prefix does not use BGP NHG
    because it is resolved over blackhole
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Assert that the 192.168.2.0/24 is resolved over blackhole route")
    router = tgen.gears["r1"]
    expected = json.loads(open("{}/r1/ip_route_192_168_2_0.json".format(CWD)).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip route 192.168.2.0/24 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assertmsg = '"{}" JSON output mismatches, 192.168.2.0/24 is not resolved over blackhole route'.format(
        router.name
    )
    assert result is None, assertmsg

    step("Assert that the 192.168.2.0/24 prefix does not use BGP NHG")
    check_bgp_nexthop_group_disabled_for_prefix("192.168.2.0/24", "r1")


def test_bgp_nexthop_group_disabled_for_routes_resolving_over_default_route():
    """
    Assert that the 192.168.1.0/24 prefix does not use BGP NHG
    because it is resolved over default route
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Assert that the 192.168.1.0/24 is resolved over 172.31.0.2 (default route)")
    router = tgen.gears["r1"]
    expected = json.loads(open("{}/r1/ip_route_192_168_1_0.json".format(CWD)).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip route 192.168.1.0/24 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assertmsg = '"{}" JSON output mismatches, 192.168.1.0/24 is not resolved over 172.31.0.2 (default route)'.format(
        router.name
    )
    assert result is None, assertmsg

    step("Assert that the 192.168.1.0/24 prefix does not use BGP NHG")
    check_bgp_nexthop_group_disabled_for_prefix("192.168.1.0/24", "r1")


def test_bgp_nexthop_group_disabled_for_routes_resolving_over_same_prefix():
    """
    Assert that the 192.168.3.0/24 prefix does not use BGP NHG
    because it is resolved over an already present exact same prefix
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Assert that the 192.168.3.0/24 has 2 entries in ZEBRA")
    router = tgen.gears["r1"]
    expected = json.loads(open("{}/r1/ip_route_192_168_3_0.json".format(CWD)).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip route 192.168.3.0/24 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assertmsg = (
        '"{}" JSON output mismatches, 192.168.3.0/24 has not 2 entries in ZEBRA'.format(
            router.name
        )
    )
    assert result is None, assertmsg

    step("Assert that the 192.168.3.0/24 has a nexthop")
    donna = router.vtysh_cmd("show bgp ipv4 192.168.3.0/24 json", isjson=True)
    # look for first available nexthop
    nexthop_to_check = ""
    for path in donna["paths"]:
        if "nexthops" not in path.keys():
            continue
        for nh in path["nexthops"]:
            if "ip" in nh.keys():
                nexthop_to_check = nh["ip"]
                break

    assert (
        nexthop_to_check != ""
    ), '"{}", 192.168.3.0/24 prefix has no valid nexthop'.format(router.name)

    step(
        f"Check that nexthop {nexthop_to_check} is resolved over 192.168.3.0/24 prefix"
    )
    donna = router.vtysh_cmd(f"show bgp nexthop {nexthop_to_check} json", isjson=True)
    if "ipv4" not in donna.keys() or "resolvedPrefix" not in donna["ipv4"].keys():
        assert 0, '"{}", {} nexthop is invalid'.format(router.name, nexthop_to_check)

    assertmsg = '"{}", 192.168.3.0/24 prefix is not resolving over itself'.format(
        router.name
    )
    assert donna["ipv4"]["resolvedPrefix"] == "192.168.3.0/24", assertmsg

    step("Assert that the 192.168.3.0/24 prefix does not use BGP NHG")
    check_bgp_nexthop_group_disabled_for_prefix("192.168.3.0/24", "r1")


def test_bgp_nexthop_group_disabled_for_imported_routes():
    """
    Assert that the 192.168.4.0/24 prefix does not use BGP NHG
    because it is directly imported, connected over an interface
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Assert that the 192.168.4.0/24 is installed")
    router = tgen.gears["r1"]
    expected = json.loads(open("{}/r1/ip_route_192_168_4_0.json".format(CWD)).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip route 192.168.4.0/24 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assertmsg = '"{}" JSON output mismatches, 192.168.4.0/24 is not installed'.format(
        router.name
    )
    assert result is None, assertmsg

    step("Assert that the 192.168.4.0/24 prefix does not use BGP NHG")
    check_bgp_nexthop_group_disabled_for_prefix("192.168.4.0/24", "r1")


def test_bgp_nexthop_group_disabled_for_6pe_routes():
    """
    Assert that the 1001::/64 prefix does not use BGP NHG
    because its nexthop is an IPv4 mapped IPv6 address
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Assert that the 1001::/64 is present on ZEBRA")
    router = tgen.gears["r1"]
    expected = json.loads(open("{}/r1/ipv6_route_1001_64.json".format(CWD)).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ipv6 route 1001::/64 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assertmsg = '"{}" JSON output mismatches, 192.168.4.0/24 is not installed'.format(
        router.name
    )
    assert result is None, assertmsg

    step("Assert that the 1001::/64 prefix does not use BGP NHG")
    check_bgp_nexthop_group_disabled_for_prefix("1001::/64", "r1")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
