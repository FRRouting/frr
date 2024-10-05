#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_vpnv4_ebgp.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2022 by 6WIND
#

"""
 test_bgp_vpnv4_ebgp.py: Test the FRR BGP daemon with EBGP direct connection
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

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])


def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "ip link add vrf1 type vrf table 10",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
        "ip link set dev vrf1 up",
        "ip link set dev {0}-eth1 master vrf1",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth0/input",
    ]

    for cmd in cmds_list:
        input = cmd.format("r1")
        logger.info("input: " + cmd)
        output = tgen.net["r1"].cmd(cmd.format("r1"))
        logger.info("output: " + output)

    for cmd in cmds_list:
        input = cmd.format("r2")
        logger.info("input: " + cmd)
        output = tgen.net["r2"].cmd(cmd.format("r2"))
        logger.info("output: " + output)

    for cmd in cmds_list:
        input = cmd.format("r3")
        logger.info("input: " + cmd)
        output = tgen.net["r3"].cmd(cmd.format("r3"))
        logger.info("output: " + output)


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
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


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    logger.info("Dump some context for r1")
    router.vtysh_cmd("show bgp ipv4 vpn")
    router.vtysh_cmd("show bgp summary")
    router.vtysh_cmd("show bgp vrf vrf1 ipv4")
    router.vtysh_cmd("show running-config")
    router = tgen.gears["r2"]
    logger.info("Dump some context for r2")
    router.vtysh_cmd("show bgp ipv4 vpn")
    router.vtysh_cmd("show bgp summary")
    router.vtysh_cmd("show bgp vrf vrf1 ipv4")
    router.vtysh_cmd("show running-config")

    # Check IPv4 routing tables on r1
    logger.info("Checking IPv4 routes for convergence on r1")
    router = tgen.gears["r1"]
    json_file = "{}/{}/ipv4_routes.json".format(CWD, router.name)
    if not os.path.isfile(json_file):
        logger.info("skipping file {}".format(json_file))
        assert 0, "ipv4_routes.json file not found"
        return

    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip route vrf vrf1 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg

    # Check BGP IPv4 routing tables on r1
    logger.info("Checking BGP IPv4 routes for convergence on r1")
    router = tgen.gears["r1"]
    json_file = "{}/{}/bgp_ipv4_routes.json".format(CWD, router.name)
    if not os.path.isfile(json_file):
        assert 0, "bgp_ipv4_routes.json file not found"

    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp vrf vrf1 ipv4 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg

    # Check BGP IPv4 imported entry is not detected as local
    # "selectionReason": "Locally configured route"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show bgp vrf vrf1 ipv4 172.31.0.10/32 json", isjson=True
    )
    routes = donna["paths"]
    selectionReasonFound = False
    for route in routes:
        if "bestpath" not in route.keys():
            continue
        if "selectionReason" not in route["bestpath"].keys():
            continue

        if "Locally configured route" == route["bestpath"]["selectionReason"]:
            assert 0, "imported prefix has wrong reason detected"

        selectionReasonFound = True

    if not selectionReasonFound:
        assertmsg = '"{}" imported prefix has wrong reason detected'.format(router.name)
        assert False, assertmsg

    # Check BGP IPv4 routing tables on r2 not installed
    logger.info("Checking BGP IPv4 routes for convergence on r2")
    router = tgen.gears["r2"]
    json_file = "{}/{}/bgp_ipv4_routes.json".format(CWD, router.name)
    if not os.path.isfile(json_file):
        assert 0, "bgp_ipv4_routes.json file not found"

    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp vrf vrf1 ipv4 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def test_export_route_target_empty():
    """
    Check that when removing 'rt vpn export' command, exported prefix is removed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, Remove 'rt vpn export 52:100' command")
    router.vtysh_cmd(
        """
configure terminal
router bgp 65500 vrf vrf1
 address-family ipv4 unicast
  no rt vpn export 52:100
"""
    )

    prefix = "172.31.0.1/32"
    logger.info("r1, check that exported prefix {} is removed".format(prefix))
    test_func = partial(
        check_show_bgp_vpn_prefix_not_found,
        router,
        "ipv4",
        prefix,
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {} still present".format(router.name, prefix)


def test_export_route_target_with_routemap_with_export_route_target():
    """
    Check that when removing 'rt vpn export' command, exported prefix is added back
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, configuring route target with route-map with export route target")
    router.vtysh_cmd(
        """
configure terminal
router bgp 65500 vrf vrf1
 address-family ipv4 unicast
  route-map vpn export RMAP
!
route-map RMAP permit 1
 set extcommunity rt 52:100
"""
    )

    prefix = "172.31.0.1/32"
    logger.info("r1, check that exported prefix {} is added back".format(prefix))
    test_func = partial(
        check_show_bgp_vpn_prefix_found,
        router,
        "ipv4",
        prefix,
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {} still not present".format(router.name, prefix)


def test_export_route_target_with_routemap_without_export_route_target():
    """
    Check that when removing 'set extcommunity rt' command, prefix is removed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, removing 'set extcommunity rt 52:100.")
    router.vtysh_cmd(
        """
configure terminal
route-map RMAP permit 1
 no set extcommunity rt
"""
    )

    prefix = "172.31.0.1/32"
    logger.info("r1, check that exported prefix {} is removed".format(prefix))
    test_func = partial(
        check_show_bgp_vpn_prefix_not_found,
        router,
        "ipv4",
        prefix,
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {} still present".format(router.name, prefix)


def test_export_route_target_with_default_command():
    """
    Add back route target with 'rt vpn export' command
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, detach route-map and re-add route target vpn export")
    router.vtysh_cmd(
        """
configure terminal
router bgp 65500 vrf vrf1
 address-family ipv4 unicast
  rt vpn export 52:100
"""
    )
    prefix = "172.31.0.1/32"
    logger.info("r1, check that exported prefix {} is added back".format(prefix))
    test_func = partial(
        check_show_bgp_vpn_prefix_found,
        router,
        "ipv4",
        prefix,
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {} still not present".format(router.name, prefix)


def test_export_suppress_route_target_with_route_map_command():
    """
    Add back route target with 'rt vpn export' command
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, add an extended comm-list to delete 52:100")

    router.vtysh_cmd(
        """
configure terminal
bgp extcommunity-list 1 permit rt 52:100
!
route-map RMAP permit 1
 set extended-comm-list 1 delete
"""
    )
    prefix = "172.31.0.1/32"
    logger.info("r1, check that exported prefix {} is removed".format(prefix))
    test_func = partial(
        check_show_bgp_vpn_prefix_not_found,
        router,
        "ipv4",
        prefix,
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {} still present".format(router.name, prefix)


def test_export_add_route_target_to_route_map_command():
    """
    Add route target with route-map so that route is added back
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, add an additional set extcommunity 52:101")
    router.vtysh_cmd(
        """
configure terminal
route-map RMAP permit 1
 set extcommunity rt 52:101
"""
    )
    prefix = "172.31.0.1/32"
    logger.info("r1, check that exported prefix {} is added back".format(prefix))
    test_func = partial(
        check_show_bgp_vpn_prefix_found,
        router,
        "ipv4",
        prefix,
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {} still not present".format(router.name, prefix)


def test_adj_rib_out_label_change():
    """
    Check that changing the VPN label on r1
    is propagated on r2
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Changing VPN label value to export")
    dump = tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
 router bgp 65500 vrf vrf1
  address-family ipv4 unicast
   label vpn export 102
"""
    )
    # Check BGP IPv4 route entry for 172.31.0.1 on r1
    logger.info("Checking BGP IPv4 routes for convergence on r1")
    router = tgen.gears["r2"]
    json_file = "{}/{}/bgp_ipv4_vpn_route_1723101.json".format(CWD, router.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp ipv4 vpn 172.31.0.1/32 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def test_adj_rib_in_label_change():
    """
    Check that syncinig with ADJ-RIB-in on r2
    permits restoring the initial label value
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enable soft-reconfiguration inbound on r2")

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd(
        """
configure terminal
router bgp 65501
 address-family ipv4 vpn
  neighbor 192.168.0.1 soft-reconfiguration inbound
"""
    )

    logger.info("Applying a deny-all route-map to input on r2")
    r2.vtysh_cmd(
        """
configure terminal
route-map DENY-ALL deny 1
!
router bgp 65501
 address-family ipv4 vpn
  neighbor 192.168.0.1 route-map DENY-ALL in
"""
    )

    # check that 172.31.0.1 should not be present
    logger.info("Check that received update 172.31.0.1 is not present")

    expected = {}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp ipv4 vpn 172.31.0.1/32 json",
        expected,
        exact=True,
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "r2, vpnv4 update 172.31.0.1 still present"


def test_adj_rib_in_label_change_remove_rmap():
    """
    Check that syncinig with ADJ-RIB-in on r2
    permits restoring the initial label value
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing the deny-all route-map from input on r2")

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd(
        """
configure terminal
router bgp 65501
 address-family ipv4 vpn
  no neighbor 192.168.0.1 route-map DENY-ALL in
"""
    )
    # Check BGP IPv4 route entry for 172.31.0.1 on r1
    logger.info(
        "Checking that 172.31.0.1 BGP update is present and has valid label on r2"
    )
    json_file = "{}/{}/bgp_ipv4_vpn_route_1723101.json".format(CWD, r2.name)

    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp ipv4 vpn 172.31.0.1/32 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(r2.name)
    assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
