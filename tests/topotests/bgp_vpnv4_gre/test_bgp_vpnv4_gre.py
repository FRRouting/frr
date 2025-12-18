#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_vpnv4_gre.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by 6WIND
#

"""
 test_bgp_vpnv4_gre.py: Test the FRR BGP daemon with BGP IPv6 interface
 with route advertisements on a separate netns.
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


def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "ip link add vrf1 type vrf table 10",
        "echo 10 > /proc/sys/net/mpls/platform_labels",
        "ip link set dev vrf1 up",
        "ip link set dev {0}-eth1 master vrf1",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth0/input",
        "ip tunnel add {0}-gre0 mode gre ttl 64 dev {0}-eth0 local 10.125.0.{1} remote 10.125.0.{2}",
        "ip link set dev {0}-gre0 up",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-gre0/input",
    ]

    for cmd in cmds_list:
        input = cmd.format("r1", "1", "2")
        logger.info("input: " + cmd)
        output = tgen.net["r1"].cmd(cmd.format("r1", "1", "2"))
        logger.info("output: " + output)

    for cmd in cmds_list:
        input = cmd.format("r2", "2", "1")
        logger.info("input: " + cmd)
        output = tgen.net["r2"].cmd(cmd.format("r2", "2", "1"))
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


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
