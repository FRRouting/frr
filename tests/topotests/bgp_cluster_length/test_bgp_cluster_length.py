#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_cluster_length.py
# Test BGP cluster list length filtering in route reflector topology
#
# Copyright (c) 2025 Nvidia, Inc
#                                   Donald Sharp
#

r"""
Test BGP cluster list length handling in a multi-layer route reflector topology.

Topology:
  r7 r8
  |\ /|
  | X |
  |/ \|
  r5 r6
  |\ /|
  | X |
  |/ \|
  r3 r4
  |\ /|
  | X |
  |/ \|
  r1 r2

All routers are in AS 100 (IBGP).
Each router is configured as a route reflector with its neighbors as clients.

The test verifies that r4 correctly filters BGP paths based on cluster list length.
r4 should receive 4 paths to r8's loopback (10.0.0.8/32):
- Via r5 directly (cluster list length: 1)
- Via r6 directly (cluster list length: 1)
- Via r1->r3->r5 (cluster list length: 3)
- Via r2->r3->r5 (cluster list length: 3)

r4 should only install the 2 shortest paths (via r5 and r6) for multipath.
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
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """Build the multi-layer RR topology"""

    # Create routers
    for routern in range(1, 9):
        tgen.add_router("r{}".format(routern))

    # Layer 1 connections (r1-r2 to r3-r4)
    # r1 to r3
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # r1 to r4
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    # r2 to r3
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # r2 to r4
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    # Layer 2 connections (r3-r4 to r5-r6)
    # r3 to r5
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])

    # r3 to r6
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r6"])

    # r4 to r5
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])

    # r4 to r6
    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r6"])

    # Layer 3 connections (r5-r6 to r7-r8)
    # r5 to r7
    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r7"])

    # r5 to r8
    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r8"])

    # r6 to r7
    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["r6"])
    switch.add_link(tgen.gears["r7"])

    # r6 to r8
    switch = tgen.add_switch("s12")
    switch.add_link(tgen.gears["r6"])
    switch.add_link(tgen.gears["r8"])


def setup_module(mod):
    """Setup the test environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()


def teardown_module(mod):
    """Teardown the test environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """Test that BGP sessions are established"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP convergence")

    # Expected neighbor counts for each router
    expected_neighbors = {
        "r1": 2,  # r3, r4
        "r2": 2,  # r3, r4
        "r3": 4,  # r1, r2, r5, r6
        "r4": 4,  # r1, r2, r5, r6
        "r5": 4,  # r3, r4, r7, r8
        "r6": 4,  # r3, r4, r7, r8
        "r7": 2,  # r5, r6
        "r8": 2,  # r5, r6
    }

    for rname, expected_count in expected_neighbors.items():
        router = tgen.gears[rname]

        def check_bgp_session(router, expected_count):
            output = router.vtysh_cmd("show bgp summary json")
            try:
                parsed = json.loads(output)
                ipv4_summary = parsed.get("ipv4Unicast", {})
                peers = ipv4_summary.get("peers", {})
                established_count = sum(
                    1 for peer in peers.values() if peer.get("state") == "Established"
                )

                if established_count == expected_count:
                    logger.info(
                        "{}: {} BGP sessions established".format(
                            router.name, established_count
                        )
                    )
                    return True
                else:
                    logger.info(
                        "{}: {}/{} BGP sessions established (waiting)".format(
                            router.name, established_count, expected_count
                        )
                    )
                    return False
            except (json.JSONDecodeError, KeyError):
                return False

        test_func = functools.partial(check_bgp_session, router, expected_count)
        success, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
        assert success, "{} BGP sessions did not converge".format(rname)


def check_r8_routes(
    router, expected_total_paths, expected_multipath_count, expected_cluster_length
):
    """Check that router has correct paths to r8's loopback"""
    output = router.vtysh_cmd("show bgp ipv4 unicast 10.0.0.8/32 json")
    try:
        parsed = json.loads(output)
        paths = parsed.get("paths", [])

        if not paths:
            logger.info(
                "{}: No paths found for 10.0.0.8/32 (waiting for BGP convergence)".format(
                    router.name
                )
            )
            return None

        # Count paths and their cluster list lengths
        path_info = []
        multipath_count = 0

        for path in paths:
            cluster_list = path.get("clusterList", [])
            cluster_length = len(cluster_list) if cluster_list else 0
            is_multipath = path.get("multipath", False)
            is_bestpath = path.get("bestpath", {}).get("overall", False)

            if is_multipath or is_bestpath:
                multipath_count += 1

            path_info.append(
                {
                    "nexthop": path.get("nexthops", [{}])[0].get("ip", "unknown"),
                    "cluster_length": cluster_length,
                    "cluster_list": cluster_list,
                    "multipath": is_multipath or is_bestpath,
                    "valid": path.get("valid", False),
                }
            )

        logger.info(
            "{}: has {} total paths to 10.0.0.8/32:".format(router.name, len(paths))
        )
        for idx, info in enumerate(path_info, 1):
            logger.info(
                "  Path {}: nexthop={}, cluster_length={}, multipath={}, valid={}".format(
                    idx,
                    info["nexthop"],
                    info["cluster_length"],
                    info["multipath"],
                    info["valid"],
                )
            )

        # Check that we have the expected number of paths
        if len(paths) < expected_total_paths:
            logger.info(
                "{}: Expected at least {} paths, got {} (waiting)".format(
                    router.name, expected_total_paths, len(paths)
                )
            )
            return None

        # Verify that only the shortest cluster list paths are used for multipath
        multipath_paths = [p for p in path_info if p["multipath"]]

        if len(multipath_paths) != expected_multipath_count:
            logger.info(
                "{}: Expected {} multipath routes, got {} (waiting)".format(
                    router.name, expected_multipath_count, len(multipath_paths)
                )
            )
            return None

        # Verify all multipath routes have the expected cluster length
        for path in multipath_paths:
            if path["cluster_length"] != expected_cluster_length:
                logger.info(
                    "{}: Multipath route has incorrect cluster length: {} (expected {})".format(
                        router.name, path["cluster_length"], expected_cluster_length
                    )
                )
                return None

        logger.info(
            "✓ {} correctly installed {} paths with cluster list length {}".format(
                router.name, expected_multipath_count, expected_cluster_length
            )
        )
        return True

    except (json.JSONDecodeError, KeyError) as e:
        logger.info("{}: Error parsing BGP output: {}".format(router.name, e))
        return None


def test_bgp_cluster_list_filtering():
    """Test that routers only install shortest cluster list paths"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP cluster list length filtering on r3 and r4")

    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    # Test r4: should have 4 total paths but only 2 with cluster length 1 in multipath
    logger.info("Checking r4 routes to 10.0.0.8/32")
    test_func = functools.partial(
        check_r8_routes,
        r4,
        expected_total_paths=4,
        expected_multipath_count=2,
        expected_cluster_length=1,
    )
    success, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
    assert success, "r4 did not correctly filter paths based on cluster list length"

    # Test r3: should have 4 total paths but only 2 with cluster length 2 in multipath
    logger.info("Checking r3 routes to 10.0.0.8/32")
    test_func = functools.partial(
        check_r8_routes,
        r3,
        expected_total_paths=2,
        expected_multipath_count=2,
        expected_cluster_length=1,
    )
    success, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
    assert success, "r3 did not correctly filter paths based on cluster list length"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
