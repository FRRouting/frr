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
import re
import time
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import retry
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]

TUNNEL_TYPE = None


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


def _populate_iface(mod):
    global TUNNEL_TYPE

    tgen = get_topogen()

    if "gretap" in mod.__name__:
        TUNNEL_TYPE = "gretap"
    else:
        TUNNEL_TYPE = "gre"

    cmds_list = [
        "ip link add vrf1 type vrf table 10",
        "echo 10 > /proc/sys/net/mpls/platform_labels",
        "ip link set dev vrf1 up",
        "ip link set dev {0}-eth1 master vrf1",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth0/input",
        "ip link add {0}-gre0 type {3} ttl 64 dev {0}-eth0 local 10.125.0.{1} remote 10.125.0.{2}",
        "ip link set dev {0}-gre0 up",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-gre0/input",
    ]

    for cmd in cmds_list:
        input = cmd.format("r1", "1", "2", TUNNEL_TYPE)
        logger.info("input: " + input)
        output = tgen.net["r1"].cmd(cmd.format("r1", "1", "2", TUNNEL_TYPE))
        logger.info("output: " + output)

    for cmd in cmds_list:
        input = cmd.format("r2", "2", "1", TUNNEL_TYPE)
        logger.info("input: " + input)
        output = tgen.net["r2"].cmd(cmd.format("r2", "2", "1", TUNNEL_TYPE))
        logger.info("output: " + output)


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface(mod)

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        bgp_config = (
            f"{rname}/bgpd_{TUNNEL_TYPE}.conf"
            if rname == "r1"
            else f"{rname}/bgpd.conf"
        )
        router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, bgp_config))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


@retry(retry_timeout=10)
def _check_show_bgp_mpls_not_selected(router, vrf, ipv4prefix):
    valid = True
    output = json.loads(router.vtysh_cmd(f"show bgp vrf {vrf} ipv4 {ipv4prefix} json"))
    paths = output["paths"]
    for path in paths:
        if "remoteLabel" in path.keys():
            valid = path.get("valid", False)
    if not valid:
        return True
    return f"MPLS path to {ipv4prefix} in vrf {vrf} not found or considered as valid"


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

    # Check BGP IPv4 convergence on r2
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

    # Check BGP IPv4 route 10.201.0.0/24 on r2 not installed
    logger.info("Checking BGP IPv4 route 10.201.0.0/24 for invalidity on r2")
    success = _check_show_bgp_mpls_not_selected(
        tgen.gears["r2"], "vrf1", "10.201.0.0/24"
    )
    assert success is True, "network 10.201.0.0/24 invalid for MPLS: not found on r2"


def test_promiscuity_no_route_reset():
    """
    Test that promiscuity changes don't cause route resets on GRE tunnel interfaces
    and that the PROMISC flag is correctly displayed.

    This simulates running tcpdump on an interface which sets promiscuous mode.
    Without the fix, this would cause routes to reset their timers.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Test that promiscuity changes (like tcpdump) don't reset routes on GRE interfaces"
    )
    router = tgen.gears["r1"]

    # INTENTIONAL: Wait 3 seconds at the beginning for routes to age
    logger.info("Waiting 3 seconds for routes to age")
    time.sleep(3)

    target_route = "10.201.0.0/24"
    logger.info("Getting route timer before promiscuity change")
    routes_before = router.vtysh_cmd("show ip route vrf vrf1 json")
    routes_json_before = json.loads(routes_before)

    uptime_before_promisc = None
    if target_route in routes_json_before:
        routes_list = routes_json_before[target_route]
        if routes_list and isinstance(routes_list, list):
            uptime_before_promisc = routes_list[0].get("uptime", None)
            logger.info(
                "Route {} timer before promiscuity: {}".format(
                    target_route, uptime_before_promisc
                )
            )

    if not uptime_before_promisc:
        pytest.skip("Route {} not found in VRF vrf1".format(target_route))

    # Toggle promiscuity on r1-eth1
    logger.info("Setting promiscuity on r1-eth1")
    router.run("ip link set r1-eth1 promisc on")

    # Check that PROMISC flag is set on r1-eth1
    def _check_promisc_on():
        output = router.vtysh_cmd("show interface r1-eth1")
        if "PROMISC" in output:
            return None
        return "PROMISC flag not found in output"

    _, result = topotest.run_and_expect(_check_promisc_on, None, count=20, wait=3)
    assert result is None, "PROMISC flag not set after enabling: {}".format(result)
    logger.info("PROMISC flag correctly set on r1-eth1")

    # Turn off promiscuity on r1-eth1
    logger.info("Clearing promiscuity on r1-eth1")
    router.run("ip link set r1-eth1 promisc off")

    # Check that PROMISC flag is cleared
    def _check_promisc_off():
        output = router.vtysh_cmd("show interface r1-eth1")
        flags_match = re.search(r"flags:\s*<([^>]+)>", output)
        if flags_match:
            flags = flags_match.group(1)
            if "PROMISC" not in flags:
                return None
            return "PROMISC flag still present: {}".format(flags)
        return "Could not find flags in output"

    _, result = topotest.run_and_expect(_check_promisc_off, None, count=20, wait=3)
    assert result is None, "PROMISC flag not cleared: {}".format(result)
    logger.info("PROMISC flag correctly cleared on r1-eth1")

    # INTENTIONAL: Wait 3 seconds at the beginning for routes to age
    logger.info("Waiting 3 seconds for routes to age")
    time.sleep(3)

    # Get route timer after promiscuity changes and verify it didn't reset
    logger.info("Verifying route {} timer was not reset".format(target_route))
    routes_after = router.vtysh_cmd("show ip route vrf vrf1 json")
    routes_json_after = json.loads(routes_after)

    uptime_after_promisc = None
    if target_route in routes_json_after:
        routes_list = routes_json_after[target_route]
        if routes_list and isinstance(routes_list, list):
            uptime_after_promisc = routes_list[0].get("uptime", None)

    if not uptime_after_promisc:
        pytest.fail(
            "Route {} disappeared after promiscuity changes".format(target_route)
        )

    logger.info(
        "Route {} timer after promiscuity: {}".format(
            target_route, uptime_after_promisc
        )
    )

    def uptime_to_seconds(uptime_str):
        parts = uptime_str.split(":")
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        return 0

    before_seconds = uptime_to_seconds(uptime_before_promisc)
    after_seconds = uptime_to_seconds(uptime_after_promisc)

    logger.info(
        "Timer before: {}s, Timer after: {}s".format(before_seconds, after_seconds)
    )

    assert (
        after_seconds >= before_seconds
    ), "Route {} timer was reset! Before: {}s ({}), After: {}s ({})".format(
        target_route,
        before_seconds,
        uptime_before_promisc,
        after_seconds,
        uptime_after_promisc,
    )

    logger.info(
        "Route {} remained stable - timer NOT reset by promiscuity changes".format(
            target_route
        )
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
