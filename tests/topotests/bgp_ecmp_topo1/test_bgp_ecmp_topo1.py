#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

#
# test_bgp_ecmp_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_bgp_ecmp_topo1.py: Test BGP topology with ECMP (Equal Cost MultiPath).
"""

import json
import functools
import os
import sys
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


total_ebgp_peers = 20

#####################################################
#
#   Network Topology Definition
#
#####################################################


def build_topo(tgen):
    router = tgen.add_router("r1")

    # Setup Switches - 1 switch per 5 peering routers
    for swNum in range(1, (total_ebgp_peers + 4) // 5 + 1):
        switch = tgen.add_switch("s{}".format(swNum))
        switch.add_link(router)

    # Add 'total_ebgp_peers' number of eBGP ExaBGP neighbors
    for peerNum in range(1, total_ebgp_peers + 1):
        swNum = (peerNum - 1) // 5 + 1

        peer_ip = "10.0.{}.{}".format(swNum, peerNum + 100)
        peer_route = "via 10.0.{}.1".format(swNum)
        peer = tgen.add_exabgp_peer(
            "peer{}".format(peerNum), ip=peer_ip, defaultRoute=peer_route
        )

        switch = tgen.gears["s{}".format(swNum)]
        switch.add_link(peer)


#####################################################
#
#   Tests starting
#
#####################################################


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.start()

    # Starting Hosts and init ExaBGP on each of them
    topotest.sleep(10, "starting BGP on all {} peers".format(total_ebgp_peers))
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        peer.start(peer_dir, env_file)
        logger.info(pname)


def teardown_module(module):
    del module
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    "Test for BGP topology convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Expected result
    router = tgen.gears["r1"]
    if router.has_version("<", "3.0"):
        reffile = os.path.join(CWD, "r1/summary20.txt")
    else:
        reffile = os.path.join(CWD, "r1/summary.txt")

    expected = json.loads(open(reffile).read())

    def _output_summary_cmp(router, cmd, data):
        """
        Runs `cmd` that returns JSON data (normally the command ends
        with 'json') and compare with `data` contents.
        """
        output = router.vtysh_cmd(cmd, isjson=True)
        return topotest.json_cmp(output, data)

    test_func = functools.partial(
        _output_summary_cmp, router, "show ip bgp summary json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = "BGP router network did not converge"
    assert res is None, assertmsg


def test_bgp_ecmp():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect = {
        "routerId": "10.0.255.1",
        "routes": {},
    }

    for net in range(1, 5):
        for subnet in range(0, 10):
            netkey = "10.20{}.{}.0/24".format(net, subnet)
            expect["routes"][netkey] = []
            for _ in range(0, 10):
                peer = {"multipath": True, "valid": True}
                expect["routes"][netkey].append(peer)

    test_func = functools.partial(
        topotest.router_json_cmp, tgen.gears["r1"], "show ip bgp json", expect
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = 'expected multipath routes in "show ip bgp" output'
    assert res is None, assertmsg


def test_nhg_with_interface_flaps_and_nexthop_flush():
    "Test static routes with multiple nexthops and verify BGP routes from peers"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # Configure static routes with multiple nexthops
    router.vtysh_cmd(
        """
        configure terminal
        # First set of routes - Static routes
        ip route 10.1.1.0/24 r1-eth1
        ip route 10.1.1.0/24 r1-eth2
        ip route 10.1.2.0/24 r1-eth2
        ip route 10.1.2.0/24 r1-eth3
        ip route 10.1.3.0/24 r1-eth1
        ip route 10.1.3.0/24 r1-eth3
        ip route 10.1.4.0/24 r1-eth1
        ip route 10.1.4.0/24 r1-eth2
        ip route 10.1.4.0/24 r1-eth3
        exit
    """
    )

    # Verify static routes are installed
    expect_static = {
        "10.1.1.0/24": {
            "nexthops": [
                {"interfaceName": "r1-eth1", "active": True},
                {"interfaceName": "r1-eth2", "active": True},
            ]
        },
        "10.1.2.0/24": {
            "nexthops": [
                {"interfaceName": "r1-eth2", "active": True},
                {"interfaceName": "r1-eth3", "active": True},
            ]
        },
        "10.1.3.0/24": {
            "nexthops": [
                {"interfaceName": "r1-eth1", "active": True},
                {"interfaceName": "r1-eth3", "active": True},
            ]
        },
        "10.1.4.0/24": {
            "nexthops": [
                {"interfaceName": "r1-eth1", "active": True},
                {"interfaceName": "r1-eth2", "active": True},
                {"interfaceName": "r1-eth3", "active": True},
            ]
        },
    }

    def _check_static_routes():
        output = router.vtysh_cmd("show ip route")
        logger.info("Checking static routes. Output:\n%s", output)

        for prefix, data in expect_static.items():
            # Check if route exists
            if prefix not in output:
                logger.error("Static route %s not found in output", prefix)
                return False

            # Count nexthops for this prefix
            nexthop_count = 0
            for nh in data["nexthops"]:
                if nh["interfaceName"] in output:
                    nexthop_count += 1

            if nexthop_count != len(data["nexthops"]):
                logger.error(
                    "Static route %s has wrong number of nexthops. Expected %d, got %d",
                    prefix,
                    len(data["nexthops"]),
                    nexthop_count,
                )
                return False
        return True

    test_func = functools.partial(_check_static_routes)
    _, res = topotest.run_and_expect(test_func, True, count=20, wait=3)
    assertmsg = "Static routes with multiple nexthops not installed correctly"
    assert res is True, assertmsg

    # Expected BGP routes with their nexthops
    expect_bgp = {
        "10.201.0.0/24": {
            "nexthops": [
                {"interfaceName": "r1-eth1", "active": True},
                {"interfaceName": "r1-eth2", "active": True},
                {"interfaceName": "r1-eth3", "active": True},
            ],
            "protocol": "bgp",
        },
        "10.202.0.0/24": {
            "nexthops": [
                {"interfaceName": "r1-eth1", "active": True},
                {"interfaceName": "r1-eth2", "active": True},
                {"interfaceName": "r1-eth3", "active": True},
            ],
            "protocol": "bgp",
        },
        "10.203.0.0/24": {
            "nexthops": [
                {"interfaceName": "r1-eth1", "active": True},
                {"interfaceName": "r1-eth2", "active": True},
                {"interfaceName": "r1-eth3", "active": True},
            ],
            "protocol": "bgp",
        },
        "10.204.0.0/24": {
            "nexthops": [
                {"interfaceName": "r1-eth1", "active": True},
                {"interfaceName": "r1-eth2", "active": True},
                {"interfaceName": "r1-eth3", "active": True},
            ],
            "protocol": "bgp",
        },
    }

    def _check_bgp_routes():
        output = router.vtysh_cmd("show ip route")
        logger.info("Checking BGP routes. Output:\n%s", output)

        for prefix, data in expect_bgp.items():
            # Check if route exists and is BGP
            if prefix not in output or "B" not in output:  # B indicates BGP route
                logger.error("BGP route %s not found or not a BGP route", prefix)
                return False

            # Find all nexthops for this prefix
            found_nexthops = []
            for nh in data["nexthops"]:
                if nh["interfaceName"] in output:
                    found_nexthops.append(nh["interfaceName"])

            logger.info("Route %s: Found nexthops: %s", prefix, found_nexthops)

            if len(found_nexthops) != len(data["nexthops"]):
                logger.error(
                    "BGP route %s has wrong number of nexthops. Expected %d (%s), got %d (%s)",
                    prefix,
                    len(data["nexthops"]),
                    [nh["interfaceName"] for nh in data["nexthops"]],
                    len(found_nexthops),
                    found_nexthops,
                )
                return False
        return True

    # Wait for BGP routes to be installed
    test_func = functools.partial(_check_bgp_routes)
    _, res = topotest.run_and_expect(test_func, True, count=20, wait=3)
    assertmsg = "BGP routes with multiple nexthops not installed correctly"
    assert res is True, assertmsg

    ## Validate route re-install post ip nexthop flush
    logger.info("=" * 80)
    logger.info("*** Validate route re-install post ip nexthop flush ***")
    logger.info("=" * 80)
    pre_route = router.cmd("ip route show | wc -l")
    pre_route6 = router.cmd("ip -6 route show | wc -l")

    post_out = router.cmd("ip next flush")

    def _check_current_route_counts():
        post_route = router.cmd("ip route show | wc -l")
        post_route6 = router.cmd("ip -6 route show | wc -l")
        if post_route != pre_route or post_route6 != pre_route6:
            return False
        return True

    result_tuple = topotest.run_and_expect(
        _check_current_route_counts, True, count=30, wait=1
    )
    _, result = result_tuple
    if not result:
        post_route = router.cmd("ip route show | wc -l")
        post_route6 = router.cmd("ip -6 route show | wc -l")
        assert (
            False
        ), "Expected same ipv6 routes(pre-{}: post-{}) and ipv4 route count(pre-{}:post-{}) after nexthop flush".format(
            pre_route6, post_route6, pre_route, post_route
        )

    # Verify routes are still installed correctly after nexthop flush
    test_func = functools.partial(_check_static_routes)
    _, res = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assertmsg = "Static routes not reinstalled correctly after nexthop flush"
    assert res is True, assertmsg

    test_func = functools.partial(_check_bgp_routes)
    _, res = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assertmsg = "BGP routes not reinstalled correctly after nexthop flush"
    assert res is True, assertmsg

    ## Validate route re-install after quick interface flaps
    logger.info("=" * 80)
    logger.info("*** Validate route re-install after quick interface flaps ***")
    logger.info("=" * 80)
    pre_route = router.cmd("ip route show | wc -l")
    pre_route6 = router.cmd("ip -6 route show | wc -l")

    # Use only the interfaces we want to test (eth1-eth3)
    interfaces = [1, 2, 3]  # Explicitly list eth1, eth2, eth3
    cmds = [f"ip link set r1-eth{i} down; ip link set r1-eth{i} up" for i in interfaces]
    router.cmd(" ; ".join(cmds))

    def _check_current_route_counts_after_flap():
        post_route = router.cmd("ip route show | wc -l")
        post_route6 = router.cmd("ip -6 route show | wc -l")
        if post_route != pre_route or post_route6 != pre_route6:
            return False
        return True

    result_tuple = topotest.run_and_expect(
        _check_current_route_counts_after_flap, True, count=30, wait=1
    )
    _, result = result_tuple
    if not result:
        post_route = router.cmd("ip route show | wc -l")
        post_route6 = router.cmd("ip -6 route show | wc -l")
        assert (
            False
        ), "Expected same ipv6 routes(pre-{}: post-{}) and route count(pre-{}:post-{}) after quick interface flaps".format(
            pre_route6, post_route6, pre_route, post_route
        )

    # Verify routes are still installed correctly after interface flaps
    test_func = functools.partial(_check_static_routes)
    _, res = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assertmsg = "Static routes not reinstalled correctly after interface flaps"
    assert res is True, assertmsg

    test_func = functools.partial(_check_bgp_routes)
    _, res = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assertmsg = "BGP routes not reinstalled correctly after interface flaps"
    assert res is True, assertmsg

    # Cleanup: Remove all configured static routes
    logger.info("*** Cleaning up static routes ***")
    router.vtysh_cmd(
        """
        configure terminal
        no ip route 10.1.1.0/24 r1-eth1
        no ip route 10.1.1.0/24 r1-eth2
        no ip route 10.1.2.0/24 r1-eth2
        no ip route 10.1.2.0/24 r1-eth3
        no ip route 10.1.3.0/24 r1-eth1
        no ip route 10.1.3.0/24 r1-eth3
        no ip route 10.1.4.0/24 r1-eth1
        no ip route 10.1.4.0/24 r1-eth2
        no ip route 10.1.4.0/24 r1-eth3
        exit
    """
    )

    # Verify routes are removed
    def _check_routes_removed():
        output = router.vtysh_cmd("show ip route")
        for prefix in ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24", "10.1.4.0/24"]:
            if prefix in output:
                logger.error("Static route %s still present after cleanup", prefix)
                return False
        return True

    test_func = functools.partial(_check_routes_removed)
    _, res = topotest.run_and_expect(test_func, True, count=10, wait=1)
    assertmsg = "Static routes not properly cleaned up"
    assert res is True, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
