#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_vpnv4_gr.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2022 by 6WIND
#

"""
 test_bgp_vpnv4_gr.py: Test the FRR BGP daemon with EBGP direct connection and graceful restart
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]

IPTABLE_ADD_DST = (
    "iptables -A INPUT -p tcp --dport 179 -j REJECT --reject-with tcp-reset"
)
IPTABLE_ADD_SRC = (
    "iptables -A INPUT -p tcp --sport 179 -j REJECT --reject-with tcp-reset"
)
IPTABLE_DEL_DST = (
    "iptables -D INPUT -p tcp --dport 179 -j REJECT --reject-with tcp-reset"
)
IPTABLE_DEL_SRC = (
    "iptables -D INPUT -p tcp --sport 179 -j REJECT --reject-with tcp-reset"
)


def build_topo(tgen):
    "Build function"

    # Create 2 routers.
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])


def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "ip link add vrf1 type vrf table 10",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
        "ip link set dev vrf1 up",
        "ip link set dev {0}-eth{1} master vrf1",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth0/input",
    ]

    for cmd in cmds_list:
        input = cmd.format("r1", 1)
        logger.info("input: " + cmd)
        output = tgen.net["r1"].cmd(cmd.format("r1", 1))
        logger.info("output: " + output)

    for cmd in cmds_list:
        for iface in (1, 2):
            input = cmd.format("r2", iface)
            logger.info("input: " + cmd)
            output = tgen.net["r2"].cmd(cmd.format("r2", iface))
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


def check_show_bgp_vpnv4_prefix(router, rd, prefix, stale=True, presence=True):
    """
    * Dump and check 'show bgp ipv4 vpn <prefix> json' output.
    * 'router': the router to check
    * 'rd': expected route distinguisher
    * 'prefix': checked prefix
    * 'stale': if True, the stale flag is set to True, otherwise it is unset
    * 'presence': if True , the prefix is present otherwise, it must be absent
    """

    logger.info(
        "{}, checking BGP IPv4 VPN RD {} prefix {} ".format(router.name, rd, prefix)
    )
    output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn {} json".format(prefix)))
    if presence and stale:
        expected = {rd: {"prefix": prefix, "paths": [{"stale": True, "valid": True}]}}
        return topotest.json_cmp(output, expected)
    if not stale and presence:
        expected = {rd: {"prefix": prefix, "paths": [{"stale": None, "valid": True}]}}
        return topotest.json_cmp(output, expected)
    if not presence:
        expected = {}
        return topotest.json_cmp(output, expected, exact=True)


def check_show_bgp_ipv4_prefix(router, vrf, prefix, presence=True):
    """
    * Dump and check 'show bgp vrf <vrf> ipv4 <prefix> json' output.
    * 'router': the router to check
    * 'vrf': The VRF to look at BGP prefix
    * 'prefix': The prefix expected
    * 'presence': if True, the prefix must be present; otherwise the prefix should not be present
    """

    logger.info(
        "{}, checking BGP IPv4 prefix {} on VRF {}".format(router.name, prefix, vrf)
    )
    output = json.loads(
        router.vtysh_cmd("show bgp vrf {} ipv4 {} json".format(vrf, prefix))
    )
    expected = {
        "prefix": prefix,
        "paths": [{"nexthops": [{"afi": "ipv4", "used": True}]}],
    }
    if presence:
        return topotest.json_cmp(output, expected)
    else:
        ret = topotest.json_cmp(output, expected)
        if ret is None:
            return "not good"
        return None


def check_stale_routes(router):
    """
    * Check that BGP VPN routes are staled
    * 'router': the router to check
    """

    # Check BGP VPNv4 routing tables are in stale routes
    logger.info("Checking BGP IPv4 VPN routes are staled".format(router.name))
    for prefix in ("172.31.0.10/32", "172.31.1.10/32"):
        test_func = partial(check_show_bgp_vpnv4_prefix, router, "444:2", prefix)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # Check BGP IPv4 route from VRF are still present
    logger.info("Checking BGP IPv4 routes are still present".format(router.name))
    for prefix in ("172.31.0.10/32", "172.31.1.10/32"):
        test_func = partial(check_show_bgp_ipv4_prefix, router, "vrf1", prefix)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # Check BGP VPNv4 routing tables
    logger.info("Checking BGP VPNv4 route for convergence on r1")
    json_file = "{}/{}/bgp_vpnv4_routes.json".format(CWD, router.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp ipv4 vpn json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg

    # Check BGP IPv4 routing tables on VRF1
    logger.info("Checking BGP IPv4 routes for convergence on r1")
    json_file = "{}/{}/bgp_ipv4_routes.json".format(CWD, router.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp vrf vrf1 ipv4 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def test_cut_link():
    """
    Unlink the cable in between r1 and r2
    Expectation is that stale routes should be available on r1
    Then at the restart time expiration, routes are removed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # r2.run("nft add rule ip filter INPUT tcp sport 179 reject with tcp reset")
    # r2.run("nft add rule ip filter INPUT tcp dport 179 reject with tcp reset")
    r2.run(IPTABLE_ADD_DST)
    r2.run(IPTABLE_ADD_SRC)

    check_stale_routes(r1)

    # Check BGP VPNv4 routing tables are in stale routes
    logger.info("Checking BGP IPv4 VPN routes are removed".format(r1.name))
    for prefix in ("172.31.0.10/32", "172.31.1.10/32"):
        test_func = partial(
            check_show_bgp_vpnv4_prefix,
            r1,
            "444:2",
            prefix,
            presence=False,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(r1.name)
        assert result is None, assertmsg

    # Check BGP IPv4 route from VRF are removed
    logger.info("Checking BGP IPv4 routes are removed".format(r1.name))
    for prefix in ("172.31.0.10/32", "172.31.1.10/32"):
        test_func = partial(
            check_show_bgp_ipv4_prefix, r1, "vrf1", prefix, presence=False
        )
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=2)
        assertmsg = '"{}" JSON output mismatches'.format(r1.name)
        assert result is None, assertmsg


def test_uncut_link():
    """
    Link the cable in between r1 and r2
    Expectation is that stale routes should be available on r1
    Then at the restart time expiration, routes are removed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r2.run(IPTABLE_DEL_DST)
    r2.run(IPTABLE_DEL_SRC)

    r1 = tgen.gears["r1"]
    # Check BGP VPNv4 routing tables are in stale routes
    logger.info("Checking BGP IPv4 VPN routes are no more staled".format(r1.name))
    for prefix in ("172.31.0.10/32", "172.31.1.10/32"):
        test_func = partial(
            check_show_bgp_vpnv4_prefix,
            r1,
            "444:2",
            prefix,
            stale=False,
            presence=True,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(r1.name)
        assert result is None, assertmsg

    # Check BGP IPv4 route from VRF are present
    logger.info("Checking BGP IPv4 routes are still present".format(r1.name))
    for prefix in ("172.31.0.10/32", "172.31.1.10/32"):
        test_func = partial(check_show_bgp_ipv4_prefix, r1, "vrf1", prefix)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(r1.name)
        assert result is None, assertmsg


def test_cut_link_remove_prefix_and_uncut_link():
    """
    Unlink the cable in between r1 and r2, then unconfigure 172.31.0.10/32.
    Wait stale route presence, then uncut the link
    Expectation is that the 172.31.0.10/32 route is removed
    Expectation is that the 172.31.1.10/32 route is present
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    prefix_1 = "172.31.0.10/32"
    prefix_2 = "172.31.1.10/32"

    logger.info("{}, cutting link between r1 and r2".format(r2.name))
    r2.run(IPTABLE_ADD_DST)
    r2.run(IPTABLE_ADD_SRC)

    # Check BGP VPNv4 routing tables are in stale routes
    # Check BGP IPv4 route from VRF are still present
    check_stale_routes(r1)

    logger.info("{}, removing {} network".format(r2.name, prefix_1))
    r2.vtysh_cmd(
        "configure terminal\ninterface r2-eth1 vrf vrf1\nno ip address {}\n".format(
            prefix_1
        )
    )

    logger.info("{}, uncutting link between r1 and r2".format(r2.name))
    r2.run(IPTABLE_DEL_DST)
    r2.run(IPTABLE_DEL_SRC)

    logger.info(
        "{}, checking BGP IPv4 VPN route {} is removed".format(r1.name, prefix_1)
    )
    test_func = partial(
        check_show_bgp_vpnv4_prefix,
        r1,
        "444:2",
        prefix_1,
        presence=False,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg

    logger.info(
        "{}, checking BGP IPv4 VPN route {} is present".format(r1.name, prefix_2)
    )
    test_func = partial(
        check_show_bgp_vpnv4_prefix,
        r1,
        "444:2",
        prefix_2,
        stale=False,
        presence=True,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg

    # Check BGP IPv4 route 172.31.0.10 from VRF are removed
    logger.info("{}, checking BGP IPv4 route {} is removed".format(r1.name, prefix_1))
    test_func = partial(
        check_show_bgp_ipv4_prefix, r1, "vrf1", prefix_1, presence=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg

    # Check BGP IPv4 route 172.31.1.10 from VRF are removed
    logger.info("{}, checking BGP IPv4 route {} is present".format(r1.name, prefix_2))
    test_func = partial(check_show_bgp_ipv4_prefix, r1, "vrf1", prefix_2, presence=True)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
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
