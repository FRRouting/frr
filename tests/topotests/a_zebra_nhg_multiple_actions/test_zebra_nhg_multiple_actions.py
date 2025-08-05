#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_nhg_multiple_actions.py
#
# Copyright (c) 2024 by
# Nvidia, Inc.
# Donald Sharp
#

r"""
test_zebra_nhg_multiple_actions.py: Test multiple actions on zebra nexthop groups

Topology:
                +----------+     +----------+     +----------+     +----------+
                |  Spine1  |     |  Spine2  |     |  Spine3  |     |  Spine4  |
                +----------+     +----------+     +----------+     +----------+
               /|\\|//|\\|/\    /|\\|//|\\|/\    /|\\|//|\\|/\    /|\\|//|\\|/\
              //|\\\//|\\\//\  //|\\\//|\\\//\  //|\\\//|\\\//\  //|\\\//|\\\//\
             ///|\\\/|\\\\///\///|\\\/|\\\\///\///|\\\/|\\\\///\///|\\\/|\\\\///\
            ////|\\\|\\\\////\\//|\\\|\\\\////\\//|\\\|\\\\////\\//|\\\|\\\\////\\
            8 links to each leaf (8 links × 8 leaves = 64 links total per spine)
                |   |   |   |      |   |   |   |      |   |   |   |      |   |   |   |
                |   |   |   |      |   |   |   |      |   |   |   |      |   |   |   |
                v   v   v   v      v   v   v   v      v   v   v   v      v   v   v   v
         +----------+  +----------+  +----------+  +----------+  +----------+  +----------+  +----------+  +----------+
         |  Leaf1   |  |  Leaf2   |  |  Leaf3   |  |  Leaf4   |  |  Leaf5   |  |  Leaf6   |  |  Leaf7   |  |  Leaf8   |
         +----------+  +----------+  +----------+  +----------+  +----------+  +----------+  +----------+  +----------+
              ↑             ↑             ↑             ↑             ↑             ↑             ↑             ↑
         8 links to each spine (8 links × 4 spines = 32 links total per leaf)

Description:
- Each leaf router connects to each spine router with 8 BGP peering links
- 32 total links per leaf router (8 links × 4 spines)
- 64 total links per spine router (8 links × 8 leaves)
- 256 total links in the network (4 spines × 8 leaves × 8 links)
- 32-way ECMP on each leaf, 8-way ECMP on each spine
"""

import os
import sys
import pytest
import json
import functools
from functools import partial
import time

# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen, set_cmd_output_limit
from lib.topolog import logger
from lib.common_config import step

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Global dictionary to store nexthop group IDs for each router
# Format: {"leaf1": nhg_id, "leaf2": nhg_id, ...}
ROUTER_NHG_IDS = {}


def build_topo(tgen):
    "Build function"

    # Limit output from vtysh commands in exec.log
    set_cmd_output_limit()

    # Create 4 spine routers
    for i in range(1, 5):
        tgen.add_router(f"spine{i}")

    # Create 8 leaf routers
    for i in range(1, 9):
        tgen.add_router(f"leaf{i}")

    # Connect each leaf to each spine with 8 links each
    for leaf_num in range(1, 9):
        for spine_num in range(1, 5):
            # Create 8 links between each leaf-spine pair
            for link_num in range(8):
                switch = tgen.add_switch(f"s{leaf_num}-{spine_num}-{link_num}")
                switch.add_link(tgen.gears[f"leaf{leaf_num}"])
                switch.add_link(tgen.gears[f"spine{spine_num}"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Initialize all routers.
    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info(f"Loading router {rname}")
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_SHARP, None),
            ],
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_spine_bgp_neighbors():
    "Test that each spine router has 64 BGP neighbors established"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for spine_num in range(1, 5):
        spine = tgen.gears[f"spine{spine_num}"]

        step(f"Checking BGP neighbors for spine{spine_num}")

        # Define expected BGP state
        expected = {"peerCount": 64, "peers": {}}

        # Each spine should have 8 connections to each of the 8 leaf routers
        for leaf_num in range(1, 9):
            for link_num in range(8):
                # The interface name pattern matches how they're created in build_topo
                intf = f"spine{spine_num}-eth{((leaf_num-1)*8) + link_num}"
                expected["peers"][intf] = {"state": "Established", "peerState": "OK"}

        def _bgp_converge():
            output = json.loads(spine.vtysh_cmd("show bgp ipv4 uni summ json"))
            return topotest.json_cmp(output, expected)

        test_func = functools.partial(_bgp_converge)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assertmsg = f"Spine{spine_num} BGP convergence failure"
        assert result is None, assertmsg


def test_sharp_install_routes():
    "Test installing 200 unique routes on each leaf using SHARP"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # First, install 200 routes on each leaf
    step("Installing 200 routes on each leaf")
    # For each leaf, install 200 routes in its own range
    # Leaf1: 1.0.0.0/32 - 1.0.0.199/32
    # Leaf2: 2.0.0.0/32 - 2.0.0.199/32
    # etc...
    for leaf_num in range(1, 9):
        leaf = tgen.gears[f"leaf{leaf_num}"]
        base_first_octet = leaf_num  # 1-8 for leaves 1-8

        step(f"Installing 200 routes on leaf{leaf_num}")

        # Install 200 /32 routes
        cmd = f"sharp install route {base_first_octet}.0.0.0 nexthop 10.1.{leaf_num}.1 200"
        leaf.vtysh_cmd(cmd)

    # Now verify routes are installed in SHARP on each leaf
    step("Verifying routes are installed on each leaf")
    for leaf_num in range(1, 9):
        leaf = tgen.gears[f"leaf{leaf_num}"]
        base_first_octet = leaf_num  # 1-8 for leaves 1-8

        step(f"Verifying routes are installed in SHARP on leaf{leaf_num}")
        # Verify routes are installed in SHARP
        output = json.loads(leaf.vtysh_cmd("show ip route sharp json"))
        expected = {
            "{}.0.{}.{}/32".format(base_first_octet, i // 256, i % 256): [
                {"protocol": "sharp"}
            ]
            for i in range(200)
        }
        test_func = functools.partial(topotest.json_cmp, output, expected)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assertmsg = f"Leaf{leaf_num} SHARP route installation failed"
        assert result is None, assertmsg

        step(f"Verifying routes are redistributed into BGP on leaf{leaf_num}")
        # Verify routes are redistributed into BGP
        expected = {
            "routes": {
                f"{base_first_octet}.0.{i // 256}.{i % 256}/32": [
                    {
                        "valid": True,
                        "pathFrom": "external",
                        "prefix": f"{base_first_octet}.0.{i // 256}.{i % 256}",
                        "prefixLen": 32,
                        "network": f"{base_first_octet}.0.{i // 256}.{i % 256}/32",
                    }
                ]
                for i in range(200)
            }
        }

        def _check_bgp_routes():
            output = json.loads(leaf.vtysh_cmd("show bgp ipv4 uni json"))
            return topotest.json_cmp(output, expected)

        _, result = topotest.run_and_expect(_check_bgp_routes, None, count=60, wait=1)
        assertmsg = f"Leaf{leaf_num} BGP redistribution verification failed"
        assert result is None, assertmsg

    # Verify routes are visible on all spines
    step("Verifying routes are visible on all spines")
    for spine_num in range(1, 5):
        spine = tgen.gears[f"spine{spine_num}"]

        step(f"Verifying all leaf routes are visible on spine{spine_num}")

        # Build a single expected dictionary for all leaves
        expected = {"routes": {}}

        # Include routes from all 8 leaves
        for leaf_num in range(1, 9):
            base_first_octet = leaf_num  # 1-8 for leaves 1-8
            for i in range(200):
                route = f"{base_first_octet}.0.{i // 256}.{i % 256}/32"
                expected["routes"][route] = [
                    {
                        "valid": True,
                        "prefix": f"{base_first_octet}.0.{i // 256}.{i % 256}",
                        "prefixLen": 32,
                        "network": route,
                    }
                ]

        def _check_spine_routes():
            output = json.loads(spine.vtysh_cmd("show bgp ipv4 uni json"))
            return topotest.json_cmp(output, expected)

        _, result = topotest.run_and_expect(_check_spine_routes, None, count=60, wait=1)
        assert result is None, f"Not all leaf routes visible on Spine{spine_num}"


def verify_leaf_route_reception(tgen):
    """
    Verify that each leaf has received all routes from other leaves.
    This function can be called multiple times during the test.
    """
    # For each leaf, verify it has received routes from all other leaves
    for leaf_num in range(1, 9):
        leaf = tgen.gears[f"leaf{leaf_num}"]

        step(f"Checking routes received on leaf{leaf_num}")

        # Build expected routes dictionary
        expected = {"routes": {}}

        # Add expected routes from each other leaf
        for other_leaf in range(1, 9):
            if other_leaf == leaf_num:
                continue  # Skip own routes

            base_first_octet = other_leaf  # 1-8 for leaves 1-8
            for i in range(200):
                route = f"{base_first_octet}.0.{i // 256}.{i % 256}/32"
                expected["routes"][route] = [
                    {
                        "valid": True,
                        "prefix": f"{base_first_octet}.0.{i // 256}.{i % 256}",
                        "prefixLen": 32,
                    }
                ]

        def _check_received_routes():
            output = json.loads(leaf.vtysh_cmd("show bgp ipv4 uni json"))
            return topotest.json_cmp(output, expected)

        _, result = topotest.run_and_expect(
            _check_received_routes, None, count=30, wait=1
        )
        assertmsg = f"Leaf{leaf_num} missing routes from other leaves"
        assert result is None, assertmsg

        # Additional verification: Count total routes
        def _check_route_count():
            output = json.loads(leaf.vtysh_cmd("show bgp ipv4 uni json"))
            route_count = len(output.get("routes", {}))
            if (
                route_count != 1600
            ):  # 7 other leaves × 200 routes each + 200 routes from own leaf
                return f"Route count mismatch: got {route_count}, expected 1600"
            return None

        _, result = topotest.run_and_expect(_check_route_count, None, count=60, wait=1)
        assert (
            result is None
        ), f"Leaf{leaf_num} route count verification failed: {result}"

        # Verify routes are in RIB
        def _check_rib_routes():
            output = json.loads(leaf.vtysh_cmd("show ip route bgp json"))
            routes_in_rib = sum(
                1 for route in output.values() if route[0]["protocol"] == "bgp"
            )
            if routes_in_rib != 1400:
                return f"RIB route count mismatch: got {routes_in_rib}, expected 1400"
            return None

        _, result = topotest.run_and_expect(_check_rib_routes, None, count=60, wait=1)
        assert (
            result is None
        ), f"Leaf{leaf_num} RIB route count verification failed: {result}"


def test_leaf_route_reception():
    "Test that each leaf has received all routes from other leaves"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    verify_leaf_route_reception(tgen)


def verify_leaf_ecmp_paths(tgen):
    """
    Verify that each leaf has 32-way ECMP for received BGP routes.
    This function can be called multiple times during the test.
    """
    # For each leaf, verify ECMP paths for received routes
    for leaf_num in range(1, 9):
        leaf = tgen.gears[f"leaf{leaf_num}"]

        step(f"Checking ECMP paths on leaf{leaf_num}")

        def _check_ecmp_paths():
            output = json.loads(leaf.vtysh_cmd("show ip route json"))

            # Check each route
            for route, route_data in output.items():
                # Skip non-BGP routes
                if route_data[0]["protocol"] != "bgp":
                    continue

                # Count nexthops
                nexthop_count = len(route_data[0].get("nexthops", []))
                if nexthop_count != 32:
                    return f"Route {route} has {nexthop_count} nexthops, expected 32"

            return None

        _, result = topotest.run_and_expect(_check_ecmp_paths, None, count=30, wait=1)
        assert result is None, f"Leaf{leaf_num} ECMP verification failed: {result}"

        # Additional verification using show bgp
        def _check_bgp_ecmp():
            output = json.loads(leaf.vtysh_cmd("show bgp ipv4 uni json"))
            routes = output.get("routes", {})

            for prefix, paths in routes.items():
                # Skip our own routes
                if prefix.startswith(f"{leaf_num}.0."):
                    continue

                # Count paths marked as multipath or bestpath
                valid_paths = sum(
                    1
                    for path in paths
                    if path.get("valid")
                    and (path.get("multipath") or path.get("bestpath"))
                )

                if valid_paths != 32:
                    return f"Prefix {prefix} has {valid_paths} valid paths, expected 32"

            return None

        _, result = topotest.run_and_expect(_check_bgp_ecmp, None, count=30, wait=1)
        assert result is None, f"Leaf{leaf_num} BGP ECMP verification failed: {result}"


def test_leaf_ecmp_paths():
    "Test that each leaf has 32-way ECMP for received BGP routes"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    verify_leaf_ecmp_paths(tgen)


def verify_spine_ecmp_paths(tgen):
    """
    Verify that each spine has 8-way ECMP for routes learned from leaves.
    This function can be called multiple times during the test.
    """
    # For each spine, verify ECMP paths for received routes
    for spine_num in range(1, 5):
        spine = tgen.gears[f"spine{spine_num}"]

        step(f"Checking ECMP paths on spine{spine_num}")

        def _check_spine_ecmp():
            output = json.loads(spine.vtysh_cmd("show ip route json"))

            # Check each route
            for route, route_data in output.items():
                # Skip non-BGP routes
                if route_data[0]["protocol"] != "bgp":
                    continue

                # Count nexthops
                nexthop_count = len(route_data[0].get("nexthops", []))
                if nexthop_count != 8:
                    return f"Route {route} has {nexthop_count} nexthops, expected 8"

            return None

        _, result = topotest.run_and_expect(_check_spine_ecmp, None, count=30, wait=1)
        assert result is None, f"Spine{spine_num} ECMP verification failed: {result}"

        # Additional verification using show bgp
        def _check_bgp_ecmp():
            output = json.loads(spine.vtysh_cmd("show bgp ipv4 uni json"))
            routes = output.get("routes", {})

            for prefix, paths in routes.items():
                # Count paths marked as multipath or bestpath
                valid_paths = sum(
                    1
                    for path in paths
                    if path.get("valid")
                    and (path.get("multipath") or path.get("bestpath"))
                )

                if valid_paths != 8:
                    return f"Prefix {prefix} has {valid_paths} valid paths, expected 8"

            return None

        _, result = topotest.run_and_expect(_check_bgp_ecmp, None, count=30, wait=1)
        assert (
            result is None
        ), f"Spine{spine_num} BGP ECMP verification failed: {result}"


def test_spine_ecmp_paths():
    "Test that each spine has 8-way ECMP for routes learned from leaves"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    verify_spine_ecmp_paths(tgen)


def test_leaf_nhg_consistency():
    "Test that all received BGP routes on each leaf share the same nexthop group ID"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # For each leaf, verify nexthop group consistency
    for leaf_num in range(1, 9):
        leaf = tgen.gears[f"leaf{leaf_num}"]
        router_name = f"leaf{leaf_num}"

        step(f"Checking nexthop group consistency on {router_name}")

        def _check_nhg_consistency():
            output = json.loads(leaf.vtysh_cmd("show ip route json"))
            nhg_id = None
            routes_checked = 0

            # Check each route
            for route, route_data in output.items():
                # Skip non-BGP routes and our own routes
                if route_data[0]["protocol"] != "bgp":
                    continue
                if route.startswith(f"{leaf_num}.0."):  # Skip self-originated routes
                    continue

                # Get the nexthop group ID for this route
                if "nexthopGroupId" not in route_data[0]:
                    return f"Route {route} missing nexthop group ID"
                if "installedNexthopGroupId" not in route_data[0]:
                    return f"Route {route} missing installed nexthop group ID"

                current_nhg = route_data[0]["nexthopGroupId"]
                installed_nhg = route_data[0]["installedNexthopGroupId"]

                # Verify the installed NHG matches the route NHG
                if current_nhg != installed_nhg:
                    return f"Route {route} has mismatched NHG IDs: route={current_nhg}, installed={installed_nhg}"

                routes_checked += 1

                # If this is the first route, set the reference nhg_id
                if nhg_id is None:
                    nhg_id = current_nhg
                    logger.info(f"{router_name} using nexthop group ID: {nhg_id}")
                    # Store the NHG ID in the global dictionary
                    ROUTER_NHG_IDS[router_name] = nhg_id
                # Otherwise compare with the reference
                elif nhg_id != current_nhg:
                    return f"Route {route} has nhgid {current_nhg}, expected {nhg_id}"

                # Verify the number of nexthops
                if route_data[0].get("internalNextHopNum", 0) != 32:
                    return f"Route {route} has {route_data[0].get('internalNextHopNum', 0)} nexthops, expected 32"
                if route_data[0].get("internalNextHopActiveNum", 0) != 32:
                    return f"Route {route} has {route_data[0].get('internalNextHopActiveNum', 0)} active nexthops, expected 32"

            # Ensure we actually checked some routes
            if routes_checked == 0:
                return "No BGP routes found to check"

            return None

        _, result = topotest.run_and_expect(
            _check_nhg_consistency, None, count=30, wait=1
        )
        assert (
            result is None
        ), f"{router_name} nexthop group consistency check failed: {result}"

        # Log all NHG IDs after collecting them
        if leaf_num == 8:
            logger.info("Collected nexthop group IDs for all routers:")
            for router, nhg_id in sorted(ROUTER_NHG_IDS.items()):
                logger.info(f"  {router}: {nhg_id}")


def test_spine_interface_shutdown():
    "Test shutting down specific interfaces on each spine and verify impact"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Interface shutdown mapping
    spine_leaf_shutdown = {
        "spine1": ["leaf1", "leaf5"],
        "spine2": ["leaf2", "leaf6"],
        "spine3": ["leaf3", "leaf7"],
        "spine4": ["leaf4", "leaf8"],
    }

    # Shutdown interfaces
    for spine_name, leaves in spine_leaf_shutdown.items():
        spine = tgen.gears[spine_name]
        spine_num = int(spine_name[-1])

        for leaf_name in leaves:
            leaf_num = int(leaf_name[-1])
            # Each spine-leaf pair has 8 interfaces
            for i in range(8):
                intf = f"{spine_name}-eth{((leaf_num-1)*8) + i}"
                step(f"Shutting down interface {intf} on {spine_name}")
                spine.run(f"ip link set {intf} down")


def test_spine_bgp_peer_shutdown():
    "Test that BGP peers go down for shutdown interfaces"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Interface shutdown mapping
    spine_leaf_shutdown = {
        "spine1": ["leaf1", "leaf5"],
        "spine2": ["leaf2", "leaf6"],
        "spine3": ["leaf3", "leaf7"],
        "spine4": ["leaf4", "leaf8"],
    }

    # For each spine, verify its BGP sessions to affected leaves are down
    for spine_name, target_leaves in spine_leaf_shutdown.items():
        spine = tgen.gears[spine_name]
        spine_num = int(spine_name[-1])

        step(
            f"Verifying BGP sessions are down on {spine_name} for leaves {target_leaves}"
        )

        def _check_bgp_peers():
            output = json.loads(spine.vtysh_cmd("show bgp summary json"))
            peers = output.get("ipv4Unicast", {}).get("peers", {})

            # For each peer interface
            for intf, peer_data in peers.items():
                # Extract leaf number from interface name (spine1-eth0 -> leaf1, spine1-eth8 -> leaf2, etc)
                intf_num = int(intf.split("-eth")[1])
                leaf_num = (intf_num // 8) + 1
                leaf_name = f"leaf{leaf_num}"

                # If this interface connects to a target leaf, it should be down
                if leaf_name in target_leaves:
                    if peer_data["state"] != "Idle":
                        return f"BGP peer {intf} to {leaf_name} is {peer_data['state']}, expected Idle"
                # Otherwise it should be Established
                else:
                    if peer_data["state"] != "Established":
                        return f"BGP peer {intf} to {leaf_name} is {peer_data['state']}, expected Established"

            return None

        _, result = topotest.run_and_expect(_check_bgp_peers, None, count=30, wait=1)
        assert result is None, f"{spine_name} BGP peer verification failed: {result}"

    # Also verify from the leaf side
    for leaf_name, leaf_num in [(f"leaf{i}", i) for i in range(1, 9)]:
        leaf = tgen.gears[leaf_name]
        affected_spine = None

        # Find which spine this leaf is disconnected from
        for spine_name, leaves in spine_leaf_shutdown.items():
            if leaf_name in leaves:
                affected_spine = spine_name
                break

        step(
            f"Verifying BGP sessions are down on {leaf_name} for spine {affected_spine}"
        )

        def _check_leaf_bgp_peers():
            output = json.loads(leaf.vtysh_cmd("show bgp summary json"))
            peers = output.get("ipv4Unicast", {}).get("peers", {})

            # For each peer interface
            for intf, peer_data in peers.items():
                # If this interface connects to the affected spine, it should be down
                if affected_spine and affected_spine in intf:
                    if peer_data["state"] != "Idle":
                        return f"BGP peer {intf} to {affected_spine} is {peer_data['state']}, expected Idle"
                # Otherwise it should be Established
                else:
                    if peer_data["state"] != "Established":
                        return f"BGP peer {intf} is {peer_data['state']}, expected Established"

            return None

        _, result = topotest.run_and_expect(
            _check_leaf_bgp_peers, None, count=30, wait=1
        )
        assert result is None, f"{leaf_name} BGP peer verification failed: {result}"


def test_spine_bgp_peer_queue_stability():
    "Test that established BGP peers on spines have empty input and output queues"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Interface shutdown mapping (to know which peers should be established)
    spine_leaf_shutdown = {
        "spine1": ["leaf1", "leaf5"],
        "spine2": ["leaf2", "leaf6"],
        "spine3": ["leaf3", "leaf7"],
        "spine4": ["leaf4", "leaf8"],
    }

    # For each spine, verify its established BGP sessions have empty queues
    for spine_name, target_leaves in spine_leaf_shutdown.items():
        spine = tgen.gears[spine_name]
        spine_num = int(spine_name[-1])

        step(f"Checking BGP peer queues on {spine_name}")

        # Check for 10 seconds (10 iterations with 1 second wait)
        for i in range(10):
            step(f"Queue check iteration {i+1}/10 on {spine_name}")

            def _check_bgp_peer_queues():
                output = json.loads(spine.vtysh_cmd("show bgp ipv4 uni summ json"))
                peers = output.get("ipv4Unicast", {}).get("peers", {})

                # Check each peer
                for intf, peer_data in peers.items():
                    # Extract leaf number from interface name
                    intf_num = int(intf.split("-eth")[1])
                    leaf_num = (intf_num // 8) + 1
                    leaf_name = f"leaf{leaf_num}"

                    # Only check established peers (those not in target_leaves)
                    if leaf_name not in target_leaves:
                        # Verify the peer is established
                        if peer_data["state"] != "Established":
                            return f"BGP peer {intf} to {leaf_name} is {peer_data['state']}, expected Established"

                        # Check input queue
                        if peer_data["inq"] != 0:
                            return f"BGP peer {intf} to {leaf_name} has non-zero input queue: {peer_data['inq']}"

                        # Check output queue
                        if peer_data["outq"] != 0:
                            return f"BGP peer {intf} to {leaf_name} has non-zero output queue: {peer_data['outq']}"

                return None

            _, result = topotest.run_and_expect(
                _check_bgp_peer_queues, None, count=30, wait=1
            )
            assert (
                result is None
            ), f"{spine_name} BGP peer queue check failed on iteration {i+1}: {result}"

            # Wait 1 second before the next check
            if i < 9:  # Don't wait after the last iteration
                time.sleep(1)

        logger.info(f"{spine_name} BGP peer queues remained empty for 10 seconds")


def test_leaf_route_source_nhg_consistency():
    "Test that routes from leaf pairs use consistent NHG IDs based on spine disconnection pattern"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Define which spine each leaf is disconnected from
    leaf_spine_disconnections = {
        "leaf1": "spine1",
        "leaf2": "spine2",
        "leaf3": "spine3",
        "leaf4": "spine4",
        "leaf5": "spine1",
        "leaf6": "spine2",
        "leaf7": "spine3",
        "leaf8": "spine4",
    }

    # Store NHG IDs for each leaf and source combination
    leaf_source_nhgs = {}  # {leaf_name: {source_leaf: nhg_id}}

    # For each leaf, verify routes from source leaves use correct NHG IDs
    for leaf_num in range(1, 9):
        leaf = tgen.gears[f"leaf{leaf_num}"]
        router_name = f"leaf{leaf_num}"
        leaf_source_nhgs[router_name] = {}

        step(f"Checking route source NHG consistency on {router_name}")

        def _check_source_nhg_consistency():
            output = json.loads(leaf.vtysh_cmd("show ip route json"))
            # Dictionary to track NHG ID for each source leaf's routes
            source_nhgs = {}  # {source_leaf_num: (nhg_id, route_count)}
            inconsistent_routes = []

            # Check each route
            for route, route_data in output.items():
                # Skip non-BGP routes
                if route_data[0]["protocol"] != "bgp":
                    continue

                # Extract source leaf number from route prefix (X.0.Y.Z -> X)
                prefix_parts = route.split(".")
                if len(prefix_parts) != 4:  # Including the /32 part
                    continue

                # Get the first octet which is the leaf number
                source_num = int(prefix_parts[0])

                # Skip our own routes
                if source_num == leaf_num:
                    continue

                current_nhg = route_data[0]["nexthopGroupId"]
                source_leaf = f"leaf{source_num}"  # Convert to leaf name

                # If this is the first route from this source, record its NHG ID
                if source_leaf not in source_nhgs:
                    source_nhgs[source_leaf] = (current_nhg, 1)
                    logger.info(
                        f"{router_name} using NHG ID {current_nhg} for routes from {source_leaf}"
                    )
                    # Store in our global tracking dictionary
                    leaf_source_nhgs[router_name][source_leaf] = current_nhg
                else:
                    # Check if NHG ID matches previous routes from this source
                    if current_nhg != source_nhgs[source_leaf][0]:
                        logger.info(
                            f"Route {route} from {source_leaf} uses NHG ID {current_nhg}, expected {source_nhgs[source_leaf][0]}"
                        )
                        inconsistent_routes.append(
                            f"Route {route} from {source_leaf} uses NHG ID {current_nhg}, "
                            f"expected {source_nhgs[source_leaf][0]}"
                        )
                    else:
                        source_nhgs[source_leaf] = (
                            current_nhg,
                            source_nhgs[source_leaf][1] + 1,
                        )

            # Verify we found routes from all other leaves
            missing_sources = []
            for source in range(1, 9):
                if source != leaf_num:
                    source_leaf = f"leaf{source}"
                    if source_leaf not in source_nhgs:
                        missing_sources.append(source_leaf)
            if missing_sources:
                return f"No routes found from: {', '.join(missing_sources)}"

            # Verify each source has all 200 routes
            incomplete_sources = []
            for source_leaf, (nhg_id, count) in source_nhgs.items():
                if count != 200:
                    incomplete_sources.append(f"{source_leaf} has {count} routes")
            if incomplete_sources:
                return f"Incomplete route counts: {', '.join(incomplete_sources)}"

            # Group leaves by their NHG IDs
            nhg_to_leaves = {}  # {nhg_id: [leaf_names]}
            for source_leaf, (nhg_id, _) in source_nhgs.items():
                if nhg_id not in nhg_to_leaves:
                    nhg_to_leaves[nhg_id] = [source_leaf]
                else:
                    nhg_to_leaves[nhg_id].append(source_leaf)

            # For each NHG ID, verify the leaves using it are disconnected from the same spine
            for nhg_id, leaves in nhg_to_leaves.items():
                if len(leaves) > 1:
                    # Get the spine that the first leaf is disconnected from
                    reference_spine = leaf_spine_disconnections[leaves[0]]
                    # All other leaves in this group should be disconnected from the same spine
                    for other_leaf in leaves[1:]:
                        if leaf_spine_disconnections[other_leaf] != reference_spine:
                            return (
                                f"Incorrect leaf grouping for NHG ID {nhg_id}: "
                                f"{leaves[0]} and {other_leaf} are disconnected from different spines "
                                f"({reference_spine} vs {leaf_spine_disconnections[other_leaf]})"
                            )

            # Verify leaves disconnected from the same spine share NHG IDs
            spine_to_nhg = {}  # {spine: nhg_id}
            for source_leaf, (nhg_id, _) in source_nhgs.items():
                disconnected_spine = leaf_spine_disconnections[source_leaf]
                if disconnected_spine not in spine_to_nhg:
                    spine_to_nhg[disconnected_spine] = nhg_id
                elif spine_to_nhg[disconnected_spine] != nhg_id:
                    return (
                        f"Routes from leaves disconnected from {disconnected_spine} use different NHG IDs: "
                        f"{nhg_id} vs {spine_to_nhg[disconnected_spine]}"
                    )

            # Report any inconsistencies within source groups
            if inconsistent_routes:
                return "Inconsistent NHG IDs within source groups:\n" + "\n".join(
                    inconsistent_routes
                )

            return None

        _, result = topotest.run_and_expect(
            _check_source_nhg_consistency, None, count=30, wait=1
        )
        assert (
            result is None
        ), f"{router_name} route source NHG consistency check failed: {result}"

    # After checking all leaves, print a summary of NHG IDs
    logger.info("\n=== NHG ID Summary ===")
    logger.info("Format: leaf -> source leaf: NHG ID")

    # First, print a header with all leaf names
    header = "Leaf"
    for source_num in range(1, 9):
        header += f" | leaf{source_num}"
    logger.info(header)
    logger.info("-" * len(header))

    # Print the NHG IDs in a table format
    for leaf_num in range(1, 9):
        leaf_name = f"leaf{leaf_num}"
        row = leaf_name

        for source_num in range(1, 9):
            source_leaf = f"leaf{source_num}"
            if source_leaf == leaf_name:
                # Skip self (own routes)
                row += " |    -   "
            else:
                nhg_id = leaf_source_nhgs[leaf_name].get(source_leaf, "N/A")
                row += f" | {nhg_id:^7}"

        logger.info(row)

    # Print grouped by disconnected spine
    logger.info("\n=== Grouped by Disconnected Spine ===")
    for spine_name in ["spine1", "spine2", "spine3", "spine4"]:
        logger.info(f"\nLeaves disconnected from {spine_name}:")
        # Get all leaves disconnected from this spine
        disconnected_leaves = [
            leaf
            for leaf, spine in leaf_spine_disconnections.items()
            if spine == spine_name
        ]

        # For each leaf in the network
        for leaf_name in sorted([f"leaf{i}" for i in range(1, 9)]):
            # Show NHG IDs for routes from leaves disconnected from this spine
            nhg_ids = {}
            for source_leaf in disconnected_leaves:
                if source_leaf != leaf_name:  # Skip self
                    nhg_id = leaf_source_nhgs[leaf_name].get(source_leaf, "N/A")
                    nhg_ids[source_leaf] = nhg_id

            if nhg_ids:
                logger.info(
                    f"  {leaf_name} routes from {disconnected_leaves}: {nhg_ids}"
                )


def test_spine_interface_restore():
    "Test restoring previously shut down interfaces and verifying BGP sessions come back up"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Interface shutdown mapping (same as used in test_spine_interface_shutdown)
    spine_leaf_shutdown = {
        "spine1": ["leaf1", "leaf5"],
        "spine2": ["leaf2", "leaf6"],
        "spine3": ["leaf3", "leaf7"],
        "spine4": ["leaf4", "leaf8"],
    }

    # Restore interfaces
    for spine_name, leaves in spine_leaf_shutdown.items():
        spine = tgen.gears[spine_name]
        spine_num = int(spine_name[-1])

        for leaf_name in leaves:
            leaf_num = int(leaf_name[-1])
            # Each spine-leaf pair has 8 interfaces
            for i in range(8):
                intf = f"{spine_name}-eth{((leaf_num-1)*8) + i}"
                step(f"Bringing up interface {intf} on {spine_name}")
                spine.run(f"ip link set {intf} up")

    # Verify BGP sessions are restored on all spines
    step("Verifying BGP sessions are restored on all spines")
    for spine_num in range(1, 5):
        spine = tgen.gears[f"spine{spine_num}"]

        step(f"Checking BGP neighbor states on spine{spine_num}")

        def _check_spine_bgp_peers():
            output = json.loads(spine.vtysh_cmd("show bgp summary json"))
            peers = output.get("ipv4Unicast", {}).get("peers", {})

            # All sessions should be established
            down_peers = []
            for intf, peer_data in peers.items():
                if peer_data["state"] != "Established":
                    down_peers.append(f"{intf} is {peer_data['state']}")

            if down_peers:
                return f"Some BGP peers still down on spine{spine_num}: {', '.join(down_peers)}"

            # Check if we have all 64 peers (8 per leaf × 8 leaves)
            if len(peers) != 64:
                return f"Expected 64 BGP peers on spine{spine_num}, got {len(peers)}"

            return None

        _, result = topotest.run_and_expect(
            _check_spine_bgp_peers, None, count=60, wait=1
        )
        assert (
            result is None
        ), f"BGP session restoration check failed on spine{spine_num}: {result}"

    # Verify BGP sessions are restored on all leaves
    step("Verifying BGP sessions are restored on all leaves")
    for leaf_num in range(1, 9):
        leaf = tgen.gears[f"leaf{leaf_num}"]

        step(f"Checking BGP neighbor states on leaf{leaf_num}")

        def _check_leaf_bgp_peers():
            output = json.loads(leaf.vtysh_cmd("show bgp summary json"))
            peers = output.get("ipv4Unicast", {}).get("peers", {})

            # All sessions should be established
            down_peers = []
            for intf, peer_data in peers.items():
                if peer_data["state"] != "Established":
                    down_peers.append(f"{intf} is {peer_data['state']}")

            if down_peers:
                return f"Some BGP peers still down on leaf{leaf_num}: {', '.join(down_peers)}"

            # Check if we have all 32 peers (8 per spine × 4 spines)
            if len(peers) != 32:
                return f"Expected 32 BGP peers on leaf{leaf_num}, got {len(peers)}"

            return None

        _, result = topotest.run_and_expect(
            _check_leaf_bgp_peers, None, count=60, wait=1
        )
        assert (
            result is None
        ), f"BGP session restoration check failed on leaf{leaf_num}: {result}"


def test_route_reception_after_restore():
    "Test that all routes are properly received after interface restoration"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verifying route reception after interface restoration")

    # Call the abstracted route verification function
    verify_leaf_route_reception(tgen)

    logger.info("All routes successfully received after interface restoration")


def test_ecmp_paths_after_restore():
    "Test that ECMP paths are consistent after interface restoration"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verifying ECMP paths after interface restoration")

    # Call the abstracted ECMP path verification function
    verify_leaf_ecmp_paths(tgen)

    logger.info("All ECMP paths successfully verified after interface restoration")


def test_spine_ecmp_after_restore():
    "Test that spine ECMP paths are consistent after interface restoration"
    tgen = get_topogen()

    # Skip if previous tests failed
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verifying spine ECMP paths after interface restoration")

    # Call the abstracted spine ECMP verification function
    verify_spine_ecmp_paths(tgen)

    logger.info(
        "All spine ECMP paths successfully verified after interface restoration"
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
