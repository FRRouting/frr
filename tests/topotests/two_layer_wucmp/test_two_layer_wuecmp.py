#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# test_two_layer_wuecmp.py
#
# Copyright (c) 2025 by
# Nvidia Corporation
# Karthikeya Venkat Muppalla <kmuppalla@nvidia.com>
#

import os
import sys
import json
import re
from functools import partial
import pytest
import re
import tempfile
import time
import logging

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, verify_bgp_convergence_from_running_config
from lib.common_config import step


"""
test_nexthop_group_wecmp.py: Test nexthop group behavior with WECMP (Weighted ECMP) 
in a high-density CLOS topology with many parallel links.
"""

TOPOLOGY = """
High-density 2-layer CLOS topology with:
- Spines (2): spine1 (AS 65100), spine2 (AS 65100)
- Leafs (2): leaf1 (AS 65001), leaf2 (AS 65002)

Each leaf connects to each spine with 32 parallel links:
- leaf1 <-> spine1: 32 links (leaf1-eth0 to leaf1-eth31)
- leaf1 <-> spine2: 32 links (leaf1-eth32 to leaf1-eth63)
- leaf2 <-> spine1: 32 links (leaf2-eth0 to leaf2-eth31)
- leaf2 <-> spine2: 32 links (leaf2-eth32 to leaf2-eth63)

Routes are injected via sharpd on leaf2 and redistributed via BGP.
This topology tests nexthop group (NHG) stability with W-ECMP during link state changes:

Test scenarios:

Single link down:
- Trigger: 1 link down (leaf1-eth0)
- Expectation: Link nexthop in that NHID is marked inactive, NHID is retained and not 
  marked for deletion, routes continue pointing to the same NHID, no new NHID is created,
  no per-route programming occurs since NHID did not change, ECMP adjusts to 63 paths

Single link up:
- Trigger: 1 link up (leaf1-eth0) 
- Expectation: Link nexthop in that NHID is marked active, NHID is retained, routes
  continue pointing to the same NHID, no new NHID is created, no per-route programming
  occurs since NHID did not change, ECMP adjusts back to 64 paths

16 out of 32 links towards spine1 down:
- Trigger: 16 out of 32 links to spine1 down (leaf1-eth0 to leaf1-eth15)
- Expectation: 16 link nexthops in that NHID are marked inactive, NHID is retained and
  not marked for deletion, routes continue pointing to the same NHID, no new NHID is
  created, no per-route programming occurs since NHID did not change, W-ECMP adjusts to 48 paths

16 out of 32 links towards spine1 up:
- Trigger: 16 out of 32 links to spine1 up (leaf1-eth0 to leaf1-eth15)
- Expectation: 16 link nexthops in that NHID are marked active, NHID is retained, routes
  continue pointing to the same NHID, no new NHID is created, no per-route programming
  occurs since NHID did not change, W-ECMP adjusts back to 64 paths

Key expectation: No new NHID should be created during local link state changes. Instead,
only the ECMP nexthop paths within the existing NHG should be updated. Since the
NHID remains unchanged, all routes continue pointing to the same NHID and no route
reprogramming occurs - avoiding unnecessary dataplane churn.

This addresses weight mismatch issues in dependent NHGs where link state changes
previously caused unnecessary NHG deletion/recreation, triggering expensive route
reprogramming and potential forwarding disruptions in high-density CLOS topologies.
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]

# Constants
LINKS_PER_SPINE = 32  # 32 links between each leaf and each spine
TOTAL_LINKS_PER_LEAF = LINKS_PER_SPINE * 2  # 64 total links per leaf

# Global variables to store state between tests
INITIAL_NHG_ID = None
INITIAL_BGP_ROUTES_COUNT = 0

logger = logging.getLogger(__name__)


def verify_nhg_and_routes(
    net, description="", expected_ecmp_paths=None, show_detailed_rib=False
):
    """Focused verification of NHG stability for 39.99.x routes only"""
    logger.info(f"=== NHG STABILITY CHECK {description} ===")

    # 1. Count all 39.99 routes with nhid in kernel (should be 1000)
    total_nhid_routes = (
        net["leaf1"].cmd('ip route show | grep nhid | grep "39\\.99" | wc -l').strip()
    )

    # 2. Get unique NHIDs used by 39.99 routes (should be only 1)
    unique_nhids_output = net["leaf1"].cmd(
        'ip route show | grep nhid | grep "39\\.99" | awk \'{for(i=1;i<=NF;i++) if($i=="nhid") print $(i+1)}\' | sort | uniq'
    )
    unique_nhids = [
        nhid.strip() for nhid in unique_nhids_output.split("\n") if nhid.strip()
    ]

    # 3. Verify only one NHID is used
    if len(unique_nhids) == 1:
        primary_nhid = unique_nhids[0]
        logger.info(f" All 1000 routes use same NHID: {primary_nhid}")
    else:
        logger.info(f" FAILURE: Multiple NHIDs found: {unique_nhids}")
        primary_nhid = unique_nhids[0] if unique_nhids else None

    # 4. Verify route count
    expected_routes = 1000
    route_count = int(total_nhid_routes) if total_nhid_routes.isdigit() else 0
    if route_count == expected_routes:
        logger.info(f" Route count correct: {route_count}")
    else:
        logger.info(f" Route count mismatch: {route_count}/{expected_routes}")

    # 5. Analyze ONLY the NHG used by 39.99.x routes
    if primary_nhid:
        logger.info(f"Analyzing NHID {primary_nhid} (used by 39.99.x routes):")

        # Get NHG details from RIB
        rib_output = net["leaf1"].cmd(
            f'vtysh -c "show nexthop-group rib {primary_nhid}"'
        )

        # Extract key information
        import re

        refcnt_match = re.search(r"RefCnt: (\d+)", rib_output)
        refcnt = int(refcnt_match.group(1)) if refcnt_match else 0

        # Count active ECMP paths
        ecmp_count = (
            net["leaf1"]
            .cmd(
                f'vtysh -c "show nexthop-group rib {primary_nhid}" | grep "via" | grep -v "inactive" | wc -l'
            )
            .strip()
        )
        total_ecmp_paths = int(ecmp_count) if ecmp_count.isdigit() else 0

        # Count paths via each spine
        spine1_paths = (
            net["leaf1"]
            .cmd(
                f'vtysh -c "show nexthop-group rib {primary_nhid}" | grep "via" | grep -v "inactive" | grep "10\\.1\\." | wc -l'
            )
            .strip()
        )
        spine2_paths = (
            net["leaf1"]
            .cmd(
                f'vtysh -c "show nexthop-group rib {primary_nhid}" | grep "via" | grep -v "inactive" | grep "10\\.2\\." | wc -l'
            )
            .strip()
        )

        spine1_count = int(spine1_paths) if spine1_paths.isdigit() else 0
        spine2_count = int(spine2_paths) if spine2_paths.isdigit() else 0

        logger.info(f"  - Active ECMP paths: {total_ecmp_paths}")
        logger.info(f"  - Paths via spine1: {spine1_count}")
        logger.info(f"  - Paths via spine2: {spine2_count}")

        # Use context-aware expected ECMP paths (default to 64 if not specified)
        if expected_ecmp_paths is None:
            expected_ecmp_paths = 64

        if total_ecmp_paths == expected_ecmp_paths:
            logger.info(
                f"✓ ECMP structure correct: {total_ecmp_paths}/{expected_ecmp_paths} paths"
            )
        else:
            logger.info(
                f"✗ ECMP structure incorrect: {total_ecmp_paths}/{expected_ecmp_paths} paths"
            )

        # Show detailed RIB output if requested
        if show_detailed_rib:
            logger.info(f"=== DETAILED NHG ANALYSIS FOR NHID {primary_nhid} ===")

            # 1. FRR RIB view
            logger.info(f"FRR RIB view (show nexthop-group rib {primary_nhid}):")
            logger.info(f"{rib_output}")

            # 2. Kernel NHG view
            logger.info(f"Kernel NHG view (ip nexthop show id {primary_nhid}):")
            kernel_nhg_output = net["leaf1"].cmd(f"ip nexthop show id {primary_nhid}")
            logger.info(f"{kernel_nhg_output}")

            # 3. Route count verification
            logger.info(
                f"Route count verification (ip route show | grep 'nhid {primary_nhid}' | wc -l):"
            )
            route_count_cmd = (
                net["leaf1"]
                .cmd(f'ip route show | grep "nhid {primary_nhid}" | wc -l')
                .strip()
            )
            logger.info(
                f"Routes using NHID {primary_nhid}: {route_count_cmd} (expected: 1000)"
            )

            logger.info(f"=== END DETAILED ANALYSIS ===")
            logger.info("")
    else:
        logger.info("✗ No NHID found for 39.99.x routes")
        total_ecmp_paths = 0

    # 6. Return verification results
    return primary_nhid, route_count, len(unique_nhids), total_ecmp_paths


def build_topo(tgen):
    "Build function for high-density topology"

    # Create the routers
    tgen.add_router("spine1")
    tgen.add_router("spine2")
    tgen.add_router("leaf1")
    tgen.add_router("leaf2")

    switch_id = 1

    # Connect leaf1 to spine1 (32 links: leaf1-eth0 to leaf1-eth31)
    for i in range(LINKS_PER_SPINE):
        switch = tgen.add_switch(f"s{switch_id}")
        switch.add_link(tgen.gears["leaf1"])
        switch.add_link(tgen.gears["spine1"])
        switch_id += 1

    # Connect leaf1 to spine2 (32 links: leaf1-eth32 to leaf1-eth63)
    for i in range(LINKS_PER_SPINE):
        switch = tgen.add_switch(f"s{switch_id}")
        switch.add_link(tgen.gears["leaf1"])
        switch.add_link(tgen.gears["spine2"])
        switch_id += 1

    # Connect leaf2 to spine1 (32 links: leaf2-eth0 to leaf2-eth31)
    for i in range(LINKS_PER_SPINE):
        switch = tgen.add_switch(f"s{switch_id}")
        switch.add_link(tgen.gears["leaf2"])
        switch.add_link(tgen.gears["spine1"])
        switch_id += 1

    # Connect leaf2 to spine2 (32 links: leaf2-eth32 to leaf2-eth63)
    for i in range(LINKS_PER_SPINE):
        switch = tgen.add_switch(f"s{switch_id}")
        switch.add_link(tgen.gears["leaf2"])
        switch.add_link(tgen.gears["spine2"])
        switch_id += 1

    # Add host connections
    switch = tgen.add_switch(f"s{switch_id}")
    switch.add_link(tgen.gears["leaf1"])
    switch_id += 1

    switch = tgen.add_switch(f"s{switch_id}")
    switch.add_link(tgen.gears["leaf2"])


def setup_module(mod):
    logger.info("Create a topology:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_SHARP, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


# Old individual test functions removed - now combined into test_topology_setup()


def test_topology_setup():
    """Complete topology setup: BGP convergence, route installation, and steady state verification"""
    tgen = get_topogen()
    net = tgen.net
    global INITIAL_NHG_ID, INITIAL_BGP_ROUTES_COUNT
    expected_route_count = 1000

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # === PHASE 1: BGP CONVERGENCE ===
    step("STEP 1: Establishing BGP sessions")

    def check_bgp_peer():
        output = net["leaf1"].cmd('vtysh -c "show bgp ipv4 uni summary json"')
        try:
            bgp_summary = json.loads(output)
            non_established_peers = bgp_summary.get("failedPeers", 0)
            total_peers = bgp_summary.get("totalPeers", 0)

            logger.info(
                f"BGP Status: {total_peers} total peers, {non_established_peers} not yet established"
            )

            if non_established_peers != 0:
                logger.info(
                    f"Peers not yet established: {non_established_peers} (waiting for BGP convergence)"
                )
                return False

            # Must have exactly 64 peers
            peers = bgp_summary.get("peers", {})
            if len(peers) != 64:
                logger.info(
                    f"Expected exactly 64 peers, found {len(peers)} (waiting for BGP convergence)"
                )
                return False

            logger.info(f"All 64 BGP peers established successfully")
            return True

        except (json.JSONDecodeError, KeyError) as e:
            logger.info(f"JSON parsing error: {e} (waiting for BGP convergence)")
            return False

    success, result = topotest.run_and_expect(
        check_bgp_peer,
        True,
        count=60,  # Wait up to 60 tries
        wait=1,  # 1 second between tries
    )

    assert success, "BGP session establishment failed"

    # === PHASE 2: ROUTE INSTALLATION ===
    step("STEP 2: Installing sharp routes and waiting for convergence")

    # Extract IPv4 from leaf2 loopback
    lo_output = net["leaf2"].cmd("vtysh -c 'show interface lo'")
    ipv4_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", lo_output)

    if not ipv4_match:
        assert False, "Could not find IPv4 address on loopback interface"

    ipv4_nexthop = ipv4_match.group(1)
    logger.info(f"Using nexthop for sharp routes: IPv4={ipv4_nexthop}")

    # Install IPv4 routes
    ipv4_cmd = f"vtysh -c 'sharp install routes 39.99.0.0 nexthop {ipv4_nexthop} {expected_route_count}'"
    logger.info(f"Installing {expected_route_count} routes with command: {ipv4_cmd}")
    net["leaf2"].cmd(ipv4_cmd)

    # Verify routes appear in BGP
    def check_leaf1_routes():
        route_count = (
            net["leaf1"]
            .cmd(
                'vtysh -c "show bgp ipv4 unicast" | grep "*>" | grep "39\\.99" | wc -l'
            )
            .rstrip()
        )
        try:
            count = int(route_count)
            if count == expected_route_count:
                logger.info(
                    f"Found {count} BGP routes with 39.99.x prefix on leaf1 (target: {expected_route_count})"
                )
            else:
                logger.info(
                    f"Still waiting... Found {count}/{expected_route_count} BGP routes with 39.99.x prefix"
                )
            return count
        except ValueError:
            return 0

    success, result = topotest.run_and_expect(
        check_leaf1_routes,
        expected_route_count,
        count=60,  # Wait up to 60 tries
        wait=1,  # 1 second between tries
    )

    assert (
        success
    ), f"Expected {expected_route_count} routes on leaf1 but found {result}"

    # CRITICAL: Wait for full topology convergence across all links
    logger.info("=== WAITING FOR FULL TOPOLOGY CONVERGENCE ===")

    def check_full_convergence():
        """Verify routes are learned from both spine1 and spine2 with proper ECMP"""

        # 1. Verify routes exist in kernel with NHID
        kernel_routes = (
            net["leaf1"]
            .cmd('ip route show | grep nhid | grep "39\\.99" | wc -l')
            .strip()
        )
        try:
            kernel_count = int(kernel_routes)
            if kernel_count != expected_route_count:
                logger.info(
                    f"Kernel routes: {kernel_count}/{expected_route_count} (waiting for convergence)"
                )
                return False
        except ValueError:
            logger.info("Failed to parse kernel route count (waiting for convergence)")
            return False

        # 2. Verify we have exactly one NHID for all routes
        unique_nhids = (
            net["leaf1"]
            .cmd(
                'ip route show | grep nhid | grep "39\\.99" | awk \'{for(i=1;i<=NF;i++) if($i=="nhid") print $(i+1)}\' | sort | uniq | wc -l'
            )
            .strip()
        )
        try:
            nhid_count = int(unique_nhids)
            if nhid_count != 1:
                logger.info(
                    f"Multiple NHIDs found: {nhid_count} (expected 1, waiting for convergence)"
                )
                return False
        except ValueError:
            logger.info("Failed to parse NHID count (waiting for convergence)")
            return False

        # 3. Get the NHID and verify ECMP structure
        nhid = (
            net["leaf1"]
            .cmd(
                'ip route show | grep nhid | grep "39\\.99" | head -1 | awk \'{for(i=1;i<=NF;i++) if($i=="nhid") print $(i+1)}\''
            )
            .strip()
        )
        if not nhid:
            logger.info("Could not extract NHID (waiting for convergence)")
            return False

        # 4. Count active ECMP paths (excluding inactive)
        ecmp_count = (
            net["leaf1"]
            .cmd(
                f'vtysh -c "show nexthop-group rib {nhid}" | grep "via" | grep -v "inactive" | wc -l'
            )
            .strip()
        )
        try:
            ecmp_paths = int(ecmp_count)
            if ecmp_paths != 64:  # Expect all 64 paths active
                logger.info(
                    f"ECMP paths: {ecmp_paths}/64 active (waiting for convergence)"
                )
                return False
        except ValueError:
            logger.info("Failed to parse ECMP count (waiting for convergence)")
            return False

        # 5. Verify that the weight of each nexthop in the nexthop group is 255
        nhg_output = net["leaf1"].cmd(
            f'vtysh -c "show nexthop-group rib {nhid}" | grep "via" | grep -v "inactive"'
        )
        if not nhg_output:
            logger.info("No nexthop output found (waiting for convergence)")
            return False

        # Check that all nexthops have weight 255
        lines = nhg_output.strip().split("\n")
        for line in lines:
            if "weight" not in line or "weight 255" not in line:
                logger.info(
                    f"Nexthop without weight 255 found: {line} (waiting for convergence)"
                )
                return False

        # 6. Verify routes are learned from both spine1 and spine2
        spine1_paths = (
            net["leaf1"]
            .cmd(
                f'vtysh -c "show nexthop-group rib {nhid}" | grep "via" | grep -v "inactive" | grep "10\\.1\\." | wc -l'
            )
            .strip()
        )
        spine2_paths = (
            net["leaf1"]
            .cmd(
                f'vtysh -c "show nexthop-group rib {nhid}" | grep "via" | grep -v "inactive" | grep "10\\.2\\." | wc -l'
            )
            .strip()
        )

        try:
            spine1_count = int(spine1_paths)
            spine2_count = int(spine2_paths)

            if spine1_count != 32:
                logger.info(
                    f"Spine1 paths: {spine1_count}/32 (waiting for convergence)"
                )
                return False
            if spine2_count != 32:
                logger.info(
                    f"Spine2 paths: {spine2_count}/32 (waiting for convergence)"
                )
                return False

        except ValueError:
            logger.info("Failed to parse spine path counts (waiting for convergence)")
            return False

        logger.info(
            f"Full convergence: {kernel_count} routes, NHID {nhid}, {ecmp_paths} ECMP paths ({spine1_count} via spine1, {spine2_count} via spine2), all nexthops have weight 255"
        )
        return True

    # Wait for full convergence with longer timeout
    convergence_success, convergence_result = topotest.run_and_expect(
        check_full_convergence,
        True,
        count=120,  # Wait up to 120 tries (2 minutes)
        wait=1,  # 1 second between tries
    )

    if not convergence_success:
        logger.info("CONVERGENCE TIMEOUT - Final diagnostic information:")

        # Show final state for debugging
        final_kernel_routes = (
            net["leaf1"]
            .cmd('ip route show | grep nhid | grep "39\\.99" | wc -l')
            .strip()
        )
        logger.info(
            f"Final kernel routes: {final_kernel_routes}/{expected_route_count}"
        )

        final_nhids = (
            net["leaf1"]
            .cmd(
                'ip route show | grep nhid | grep "39\\.99" | awk \'{for(i=1;i<=NF;i++) if($i=="nhid") print $(i+1)}\' | sort | uniq | wc -l'
            )
            .strip()
        )
        logger.info(f"Final NHID count: {final_nhids} (expected 1)")

        # Get NHID for ECMP analysis
        nhid = (
            net["leaf1"]
            .cmd(
                'ip route show | grep nhid | grep "39\\.99" | head -1 | awk \'{for(i=1;i<=NF;i++) if($i=="nhid") print $(i+1)}\''
            )
            .strip()
        )
        if nhid:
            final_ecmp = (
                net["leaf1"]
                .cmd(
                    f'vtysh -c "show nexthop-group rib {nhid}" | grep "via" | grep -v "inactive" | wc -l'
                )
                .strip()
            )
            logger.info(f"Final ECMP paths: {final_ecmp}/64")

        assert (
            False
        ), "Full topology convergence failed - routes not properly learned from both spines after 2 minutes"

    # Comprehensive verification of NHG and routes
    primary_nhid, route_count, nhid_count, ecmp_paths = verify_nhg_and_routes(
        net, "INITIAL STATE", expected_ecmp_paths=64
    )

    # Store initial state for other tests
    INITIAL_NHG_ID = int(primary_nhid) if primary_nhid else None
    INITIAL_BGP_ROUTES_COUNT = route_count

    logger.info(f"Initial State Summary:")
    logger.info(f"  - Primary NHG ID: {INITIAL_NHG_ID}")
    logger.info(f"  - BGP routes using this NHG: {INITIAL_BGP_ROUTES_COUNT}")
    logger.info(f"  - Number of different NHIDs: {nhid_count}")
    logger.info(f"  - ECMP paths in NHG: {ecmp_paths}")

    # Verify we have proper state before proceeding
    if nhid_count != 1:
        pytest.fail(f"Expected exactly 1 NHID, found {nhid_count}")
    if route_count != 1000:
        pytest.fail(f"Expected 1000 routes, found {route_count}")
    if ecmp_paths != 64:
        pytest.fail(f"Expected 64 ECMP paths, found {ecmp_paths}")

    logger.info("=== TOPOLOGY SETUP COMPLETE ===")
    logger.info("Ready for link state change tests")


def test_single_link_down():
    """Bring down a single link and verify NHG behavior"""
    tgen = get_topogen()
    net = tgen.net
    global INITIAL_NHG_ID, INITIAL_BGP_ROUTES_COUNT

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not INITIAL_NHG_ID:
        pytest.skip("Initial NHG ID not available")

    step("Test case 1: Single link down")

    # Verify before link down
    (
        primary_nhid_before,
        route_count_before,
        nhid_count_before,
        ecmp_paths_before,
    ) = verify_nhg_and_routes(net, "BEFORE LINK DOWN", expected_ecmp_paths=64)

    # Bring down interface
    logger.info("Bringing down interface: leaf1-eth0")
    down_output = net["leaf1"].cmd("ip link set leaf1-eth0 down")

    def verify_after_link_down():
        # Get current NHG state
        (
            primary_nhid_after,
            route_count_after,
            nhid_count_after,
            ecmp_paths_after,
        ) = verify_nhg_and_routes(net, "AFTER LINK DOWN CHECK", expected_ecmp_paths=63)

        # Check if NHG ID is stable
        if primary_nhid_after != str(INITIAL_NHG_ID):
            logger.info(f"NHG ID changed: {INITIAL_NHG_ID} -> {primary_nhid_after}")
            return False

        # Check if route count is stable
        if route_count_after != INITIAL_BGP_ROUTES_COUNT:
            logger.info(
                f"Route count changed: {INITIAL_BGP_ROUTES_COUNT} -> {route_count_after}"
            )
            return False

        # Check if ECMP paths reduced by 1 (one link down)
        expected_ecmp_after = 63  # 64 - 1 link down
        if ecmp_paths_after != expected_ecmp_after:
            logger.info(
                f"ECMP paths unexpected: expected {expected_ecmp_after}, got {ecmp_paths_after}"
            )
            return False

        logger.info(
            f"NHG {INITIAL_NHG_ID} stable with {route_count_after} routes and {ecmp_paths_after} ECMP paths after link down"
        )
        return True

    success, result = topotest.run_and_expect(
        verify_after_link_down,
        True,
        count=60,
        wait=1,
    )

    # Final verification after link down
    verify_nhg_and_routes(
        net,
        "FINAL STATE AFTER LINK DOWN",
        expected_ecmp_paths=63,
        show_detailed_rib=True,
    )

    assert success, "Single link down verification failed"


def test_single_link_up():
    """Bring up the previously downed link"""
    tgen = get_topogen()
    net = tgen.net
    global INITIAL_NHG_ID, INITIAL_BGP_ROUTES_COUNT

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not INITIAL_NHG_ID:
        pytest.skip("Initial NHG ID not available")

    step("Test case 2: Single link up")

    # Verify before link up
    verify_nhg_and_routes(net, "BEFORE LINK UP", expected_ecmp_paths=63)

    # Bring up interface
    logger.info("Bringing up interface: leaf1-eth0")
    net["leaf1"].cmd("ip link set leaf1-eth0 up")

    def verify_after_link_up():
        (
            primary_nhid_after,
            route_count_after,
            nhid_count_after,
            ecmp_paths_after,
        ) = verify_nhg_and_routes(net, "AFTER LINK UP CHECK", expected_ecmp_paths=64)

        if primary_nhid_after != str(INITIAL_NHG_ID):
            logger.info(f"NHG ID changed: {INITIAL_NHG_ID} -> {primary_nhid_after}")
            return False

        if route_count_after != INITIAL_BGP_ROUTES_COUNT:
            logger.info(
                f"Route count changed: {INITIAL_BGP_ROUTES_COUNT} -> {route_count_after}"
            )
            return False

        # Check if ECMP paths are back to full (64 paths after link up)
        expected_ecmp_after = 64  # All links should be up
        if ecmp_paths_after != expected_ecmp_after:
            logger.info(
                f"ECMP paths unexpected: expected {expected_ecmp_after}, got {ecmp_paths_after}"
            )
            return False

        logger.info(
            f"NHG {INITIAL_NHG_ID} stable with {route_count_after} routes and {ecmp_paths_after} ECMP paths after link up"
        )
        return True

    success, result = topotest.run_and_expect(
        verify_after_link_up,
        True,
        count=60,
        wait=1,
    )

    # Final verification
    verify_nhg_and_routes(
        net, "FINAL STATE AFTER LINK UP", expected_ecmp_paths=64, show_detailed_rib=True
    )

    assert success, "Single link up verification failed"


def test_partial_links_towards_spine1_down():
    """Bring down 16 out of 32 links towards spine1 and verify NHG behavior"""
    tgen = get_topogen()
    net = tgen.net
    global INITIAL_NHG_ID, INITIAL_BGP_ROUTES_COUNT

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not INITIAL_NHG_ID:
        pytest.skip("Initial NHG ID not available")

    step("Test case 3: Partial links down (16/32 to spine1)")

    # Verify before partial links down
    verify_nhg_and_routes(
        net, "BEFORE PARTIAL LINKS TOWARDS SPINE1 DOWN", expected_ecmp_paths=64
    )

    # Bring down 16 interfaces towards spine1
    logger.info("Bringing down 16 interfaces towards spine1: leaf1-eth0 to leaf1-eth15")
    for i in range(16):
        net["leaf1"].cmd(f"ip link set leaf1-eth{i} down")

    def verify_after_partial_links_down():
        (
            primary_nhid_after,
            route_count_after,
            nhid_count_after,
            ecmp_paths_after,
        ) = verify_nhg_and_routes(
            net, "AFTER PARTIAL LINKS TOWARDS SPINE1 DOWN CHECK", expected_ecmp_paths=48
        )

        if primary_nhid_after != str(INITIAL_NHG_ID):
            logger.info(f"NHG ID changed: {INITIAL_NHG_ID} -> {primary_nhid_after}")
            return False

        if route_count_after != INITIAL_BGP_ROUTES_COUNT:
            logger.info(
                f"Route count changed: {INITIAL_BGP_ROUTES_COUNT} -> {route_count_after}"
            )
            return False

        # Check if ECMP paths reduced by 16 (16 links down)
        expected_ecmp_after = 48  # 64 - 16 links down
        if ecmp_paths_after != expected_ecmp_after:
            logger.info(
                f"ECMP paths unexpected: expected {expected_ecmp_after}, got {ecmp_paths_after}"
            )
            return False

        logger.info(
            f"NHG {INITIAL_NHG_ID} stable with {route_count_after} routes and {ecmp_paths_after} ECMP paths after partial links towards spine1 down"
        )
        return True

    success, result = topotest.run_and_expect(
        verify_after_partial_links_down,
        True,
        count=60,
        wait=1,
    )

    # Final verification
    verify_nhg_and_routes(
        net,
        "FINAL STATE AFTER PARTIAL LINKS TOWARDS SPINE1 DOWN",
        expected_ecmp_paths=48,
        show_detailed_rib=True,
    )

    assert success, "Partial links towards spine1 down verification failed"


def test_partial_links_towards_spine1_up():
    """Bring up the 16 out of 32 previously downed links towards spine1"""
    tgen = get_topogen()
    net = tgen.net
    global INITIAL_NHG_ID, INITIAL_BGP_ROUTES_COUNT

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not INITIAL_NHG_ID:
        pytest.skip("Initial NHG ID not available")

    step("Test case 4: Partial links up (16/32 to spine1)")

    # Verify before partial links up
    verify_nhg_and_routes(net, "BEFORE PARTIAL LINKS UP", expected_ecmp_paths=48)

    # Bring up 16 interfaces towards spine1
    logger.info("Bringing up 16 interfaces towards spine1: leaf1-eth0 to leaf1-eth15")
    for i in range(16):
        net["leaf1"].cmd(f"ip link set leaf1-eth{i} up")

    def verify_after_partial_links_up():
        (
            primary_nhid_after,
            route_count_after,
            nhid_count_after,
            ecmp_paths_after,
        ) = verify_nhg_and_routes(
            net, "AFTER PARTIAL LINKS UP CHECK", expected_ecmp_paths=64
        )

        if primary_nhid_after != str(INITIAL_NHG_ID):
            logger.info(f"NHG ID changed: {INITIAL_NHG_ID} -> {primary_nhid_after}")
            return False

        if route_count_after != INITIAL_BGP_ROUTES_COUNT:
            logger.info(
                f"Route count changed: {INITIAL_BGP_ROUTES_COUNT} -> {route_count_after}"
            )
            return False

        # Check if ECMP paths are back to full (64 paths after partial links up)
        expected_ecmp_after = 64  # All links should be up
        if ecmp_paths_after != expected_ecmp_after:
            logger.info(
                f"ECMP paths unexpected: expected {expected_ecmp_after}, got {ecmp_paths_after}"
            )
            return False

        logger.info(
            f"NHG {INITIAL_NHG_ID} stable with {route_count_after} routes and {ecmp_paths_after} ECMP paths after partial links up"
        )
        return True

    success, result = topotest.run_and_expect(
        verify_after_partial_links_up,
        True,
        count=60,
        wait=1,
    )

    # Final verification
    verify_nhg_and_routes(
        net,
        "FINAL STATE AFTER PARTIAL LINKS UP",
        expected_ecmp_paths=64,
        show_detailed_rib=True,
    )

    assert success, "Partial links up verification failed"


@pytest.fixture(scope="module", autouse=True)
def cleanup_sharp_routes():
    """Fixture to clean up sharp routes after all tests"""
    yield  # This runs before tests

    # This runs after all tests
    tgen = get_topogen()
    if tgen and not tgen.routers_have_failure():
        net = tgen.net
        logger.info("Cleaning up sharp routes to prevent memory leaks")

        try:
            # Remove the 1000 sharp routes we installed
            net["leaf2"].cmd('vtysh -c "sharp remove routes 39.99.0.0 1000"')

            # Wait for routes to be removed from BGP (shorter timeout since it's cleanup)
            def check_routes_removed():
                route_count = (
                    net["leaf1"]
                    .cmd(
                        'vtysh -c "show bgp ipv4 unicast" | grep "*>" | grep "39\\.99" | wc -l'
                    )
                    .rstrip()
                )
                try:
                    count = int(route_count)
                    logger.info(f"Routes remaining: {count} (waiting for removal)")
                    return count == 0
                except ValueError:
                    return False

            success, result = topotest.run_and_expect(
                check_routes_removed,
                True,
                count=15,  # Shorter timeout for cleanup
                wait=1,
            )

            if success:
                logger.info("All sharp routes successfully removed")
            else:
                logger.info(
                    "Some routes may still remain, but continuing with teardown"
                )

        except Exception as e:
            logger.info(f"Cleanup encountered error (continuing): {e}")


# Cleanup moved to pytest fixture above


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
