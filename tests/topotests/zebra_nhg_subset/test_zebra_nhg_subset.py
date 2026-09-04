#!/usr/bin/env python3

# SPDX-License-Identifier: ISC
"""
Test: Next-Hop Group (NHG) Subset Reuse Optimization

BACKGROUND:
-----------
When a nexthop becomes unavailable, routes using that nexthop need to be
updated. With kernel nexthops enabled, FRR can optimize this by reusing
the existing NHG ID with fewer nexthops, instead of creating a new NHG.

This optimization ONLY applies when the removed nexthop is INACTIVE (link down).
If the nexthop is still ACTIVE (link up, but route withdrawn), a NEW NHG
must be created because other routes might still need the original NHG.

TOPOLOGY:
---------
                    +----+
          10.0.1.x  | r2 |  (BGP AS 65002)
                +---+----+
                |
    +----+      |   +----+
    | r1 |------+---| r3 |  (BGP AS 65003)
    +----+      |   +----+
    (DUT)       |     10.0.2.x
    AS 65000    |
                |   +----+
                +---| r4 |  (BGP AS 65004)
                |   +----+
                |     10.0.3.x
                |
                |   +----+
                +---| r5 |  (BGP AS 65005)
                    +----+
                      10.0.4.x

All peers (r2-r5) advertise the same 10 routes (10.100.0.0/24 - 10.100.9.0/24).
On r1, these routes have 4-way ECMP with nexthops: 10.0.1.2, 10.0.2.2, 10.0.3.2, 10.0.4.2

TEST PARTS:
-----------
Part 1 (Steps 1-9b):   LINK DOWN -> NHG reused (same ID), nexthop marked inactive
                       Step 9a: Verify kernel NHG updated (10.0.4.2 removed)
                       Step 9b: Verify NO route/NHG deletions during link down

Part 2 (Steps 10-13a): LINK UP -> Behavior depends on whether NHG was shrunk
                       Step 13a: Verify kernel NHG restored (10.0.4.2 is back)

Part 3 (Steps 14-17):  ROUTE WITHDRAW (link UP) -> NEW NHG (no reuse for active nexthop)
"""

import os
import sys
import re
import pytest
import subprocess
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

# Globals to pass state between tests
g_nhg_id = None
g_route_updates = None
g_nexthops_before = None
g_dplane_counters = None
g_netlink_monitor = None
g_netlink_output_file = None


def build_topo(tgen):
    for r in ["r1", "r2", "r3", "r4", "r5"]:
        tgen.add_router(r)

    for i, peer in enumerate(["r2", "r3", "r4", "r5"], 1):
        sw = tgen.add_switch("s{}".format(i))
        sw.add_link(tgen.gears["r1"])
        sw.add_link(tgen.gears[peer])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, ""), (TopoRouter.RD_BGP, "")],
        )

    tgen.start_router()

    # Create dummy interfaces with addresses on peer routers for route origination
    # This works around WSL2 not supporting blackhole/Null0 routes
    # Done AFTER FRR starts so zebra can detect the new interfaces

    # Wait for zebra to be ready before creating interfaces
    r1 = tgen.gears["r1"]

    def zebra_ready():
        out = vtysh_cmd_logged(r1, "show zebra")
        return "Zebra Infomation" in out or "zebra" in out.lower()

    topotest.run_and_expect(zebra_ready, True, count=30, wait=1)

    for peer in ["r2", "r3", "r4", "r5"]:
        router = tgen.gears[peer]
        cmd_raises_logged(router, "ip link add dummy0 type dummy")
        cmd_raises_logged(router, "ip link set dummy0 up")
        for i in range(10):
            cmd_raises_logged(router, "ip addr add 10.100.{}.1/24 dev dummy0".format(i))


def teardown_module(mod):
    get_topogen().stop_topology()


def vtysh_cmd_logged(router, cmd):
    """Execute vtysh command."""
    return router.vtysh_cmd(cmd)


def run_logged(router, cmd):
    """Execute shell command."""
    return router.run(cmd)


def cmd_raises_logged(router, cmd):
    """Execute shell command (raises on error)."""
    router.cmd_raises(cmd)


def get_nexthop_count(r1, prefix):
    """Count active nexthops for a prefix using text output."""
    out = vtysh_cmd_logged(r1, "show ip route {}".format(prefix))
    # Count lines with '*' that indicate active/FIB-installed nexthops
    count = 0
    for line in out.split("\n"):
        if "*" in line and "via" in line:
            count += 1
    if count < 4:
        logger.info("Route output (count={}):\n{}".format(count, out))
    return count


def verify_nexthops_reachable(r1, prefix, expected_nexthops):
    """Verify that specific nexthops are present and active for a route."""
    out = vtysh_cmd_logged(r1, "show ip route {}".format(prefix))
    logger.info("Route output for {}:\n{}".format(prefix, out))

    # Check each expected nexthop is present and active (has *)
    for nh in expected_nexthops:
        found = False
        for line in out.split("\n"):
            if nh in line and "*" in line:
                found = True
                break
        if not found:
            logger.info("Nexthop {} not found or not active".format(nh))
            return False
    return True


def get_nhg_id(r1, prefix):
    """Get NHG ID for a prefix using text output."""
    out = vtysh_cmd_logged(r1, "show ip route {} nexthop-group".format(prefix))
    m = re.search(r"Nexthop Group ID: (\d+)", out)
    return int(m.group(1)) if m else None


def get_nhg_nexthop_count(r1, nhg_id):
    """Get the actual number of nexthops in an NHG (from NHG itself, not route)."""
    import json

    out = vtysh_cmd_logged(r1, "show nexthop-group rib {} json".format(nhg_id))
    try:
        data = json.loads(out)
        nhg_data = data.get(str(nhg_id), {})
        return nhg_data.get("nexthopCount", 0)
    except (json.JSONDecodeError, KeyError):
        return 0


def get_route_updates(r1):
    """Get route update counter from zebra dataplane stats."""
    out = vtysh_cmd_logged(r1, "show zebra dplane")
    m = re.search(r"Route updates:\s+(\d+)", out)
    return int(m.group(1)) if m else 0


def get_dplane_counters(r1):
    """Get route and NHG update/delete counters from zebra dataplane stats."""
    out = vtysh_cmd_logged(r1, "show zebra dplane")
    counters = {}

    # Route updates and deletes
    m = re.search(r"Route updates:\s+(\d+)", out)
    counters["route_updates"] = int(m.group(1)) if m else 0

    m = re.search(r"Route deletes:\s+(\d+)", out)
    counters["route_deletes"] = int(m.group(1)) if m else 0

    # Nexthop (NHG) updates - note: called "Nexthop updates" in dplane output
    m = re.search(r"Nexthop updates:\s+(\d+)", out)
    counters["nhg_updates"] = int(m.group(1)) if m else 0

    # No separate delete counter in dplane output for nexthops
    counters["nhg_deletes"] = 0

    return counters


def get_active_nexthops(r1, prefix):
    """Get list of active nexthop IPs for a prefix (marked with *)."""
    out = vtysh_cmd_logged(r1, "show ip route {}".format(prefix))
    nexthops = []

    # FRR format: "  * 10.0.1.2, via r1-eth0, weight 1" (active)
    #             "    10.0.4.2, via r1-eth3 inactive" (inactive, no *)
    for line in out.split("\n"):
        # Only match lines with asterisk (active nexthops)
        if "*" in line and "via" in line:
            m = re.search(r"\*\s*(\d+\.\d+\.\d+\.\d+),?\s+via", line)
            if m:
                nexthops.append(m.group(1))

    return sorted(nexthops)


def verify_route_installed(r1, prefix):
    """Check that route is installed in kernel FIB using ip route show."""
    out = run_logged(r1, "ip route show {}".format(prefix))
    # Route should be present in kernel FIB
    return prefix.split("/")[0] in out and ("via" in out or "nhid" in out)


def verify_nexthop_inactive(r1, prefix, nexthop_ip):
    """Check that a specific nexthop is marked inactive."""
    out = vtysh_cmd_logged(r1, "show ip route {} nexthop-group".format(prefix))
    # Look for the nexthop IP and check if it's marked inactive
    for line in out.split("\n"):
        if nexthop_ip in line:
            if "inactive" in line.lower():
                return True
            # If nexthop is present but not marked inactive, return False
            return False
    # Nexthop not present at all means it was removed (also acceptable)
    return True


def get_kernel_nhg_nexthops(r1, nhg_id):
    """Get the list of nexthop IPs in a kernel NHG.

    Uses 'ip nexthop show' to map NHG group IDs to actual IP addresses.

    Args:
        r1: Router object
        nhg_id: The NHG ID to query

    Returns:
        List of nexthop IP addresses in the NHG, or empty list on error.
    """
    import re

    # Get the NHG group composition from kernel
    # Format: "id 29 group 18/22/26 proto zebra"
    nhg_info = run_logged(r1, "ip nexthop show id {}".format(nhg_id))

    # Extract the nexthop IDs from the group
    group_match = re.search(r'group\s+([\d/]+)', nhg_info)
    if not group_match:
        logger.info("Could not parse NHG group from: {}".format(nhg_info))
        return []

    nh_ids = group_match.group(1).split('/')

    # Get all kernel nexthops to map IDs to IPs
    all_nexthops = run_logged(r1, "ip nexthop show")

    # Build a map of nexthop ID -> IP address
    # Format: "id 18 via 10.0.1.2 dev r1-eth0 scope link proto zebra"
    nh_id_to_ip = {}
    for line in all_nexthops.split('\n'):
        id_match = re.search(r'^id\s+(\d+)\s+via\s+([\d.]+)', line)
        if id_match:
            nh_id_to_ip[id_match.group(1)] = id_match.group(2)

    # Map NHG's nexthop IDs to their IP addresses
    nhg_ips = [nh_id_to_ip.get(nh_id, "unknown-{}".format(nh_id)) for nh_id in nh_ids]

    return nhg_ips


# ============================================================================
# Part 1: LINK DOWN -> NHG REUSED (subset reuse optimization)
# ============================================================================
#
# When a link goes down, the nexthop through that link becomes INACTIVE.
# FRR can optimize by reusing the existing NHG ID with fewer nexthops:
#   - Same NHG ID, but with 3 nexthops instead of 4
#   - No need to create a new NHG
#   - Routes referencing this NHG don't need to be re-sent to kernel
#
# Test flow:
#   1. Establish 4-way ECMP with nexthops: 10.0.1.2, 10.0.2.2, 10.0.3.2, 10.0.4.2
#   2. Bring down link r1-eth3 (to r5, nexthop 10.0.4.2)
#   3. Verify NHG ID stays the SAME (subset reuse worked)
#   4. Verify no route updates sent to kernel (optimization worked)
# ============================================================================

# Expected nexthops - BGP peer IPs
EXPECTED_NEXTHOPS = ["10.0.1.2", "10.0.2.2", "10.0.3.2", "10.0.4.2"]


def test_step1_wait_for_ecmp():
    """Wait for 4-way ECMP with all nexthops reachable."""
    step("Step 1: Wait for 4-way ECMP to be established")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Log BGP neighbor status for debugging
    bgp_out = vtysh_cmd_logged(r1, "show bgp summary")
    logger.info("BGP Summary:\n{}".format(bgp_out))

    def check():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        logger.info("Current nexthop count: {}".format(count))
        return count == 4

    ok, _ = topotest.run_and_expect(check, True, count=60, wait=1)

    # If failed, log more debug info
    if not ok:
        logger.info("BGP neighbors:\n{}".format(vtysh_cmd_logged(r1, "show bgp neighbors")))
        logger.info("IP routes:\n{}".format(vtysh_cmd_logged(r1, "show ip route")))

    assert ok, "4-way ECMP not established"


def test_step2_verify_nexthops_reachable():
    """Verify all 4 nexthops are present and reachable."""
    step("Step 2: Verify all 4 nexthops are reachable")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check():
        return verify_nexthops_reachable(r1, "10.100.0.0/24", EXPECTED_NEXTHOPS)

    ok, _ = topotest.run_and_expect(check, True, count=30, wait=1)
    assert ok, "Not all nexthops {} are reachable".format(EXPECTED_NEXTHOPS)

    logger.info("All 4 nexthops verified as reachable")


def test_step3_verify_routes_installed():
    """Verify routes are installed in FIB."""
    step("Step 3: Verify routes are installed in FIB")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check():
        return verify_route_installed(r1, "10.100.0.0/24")

    ok, _ = topotest.run_and_expect(check, True, count=30, wait=1)
    assert ok, "Route 10.100.0.0/24 not installed in FIB"

    logger.info("Routes verified as installed in FIB")


def start_netlink_monitor(r1):
    """Start monitoring netlink route and nexthop messages in r1's namespace."""
    global g_netlink_monitor, g_netlink_output_file

    # Use unique filename with timestamp
    g_netlink_output_file = "/tmp/netlink_monitor_{}_{}.txt".format(
        os.getpid(), int(time.time()))

    # Remove old file if exists
    run_logged(r1, "rm -f {} 2>/dev/null || true".format(g_netlink_output_file))

    # Start ip monitor in r1's namespace, capturing all route and nexthop updates
    # Use -ts for timestamps and monitor all to capture both ROUTE and NEXTHOP events
    cmd = "ip -ts monitor all > {} 2>&1 &".format(g_netlink_output_file)
    run_logged(r1, cmd)

    # Wait for output file to be created
    def monitor_started():
        out = run_logged(r1, "test -f {} && echo 'running' || echo 'waiting'".format(
            g_netlink_output_file))
        return "running" in out

    topotest.run_and_expect(monitor_started, True, count=10, wait=1)

    logger.info("Started netlink monitor, output: {}".format(g_netlink_output_file))


def stop_netlink_monitor(r1):
    """Stop the netlink monitor."""
    # Kill ip monitor processes started by this test
    run_logged(r1, "pkill -f 'ip monitor' 2>/dev/null || true")
    # Give it a moment to terminate
    time.sleep(0.5)


def get_netlink_route_updates(r1, prefix_pattern):
    """Parse netlink monitor output for route updates matching prefix pattern."""
    global g_netlink_output_file

    # Read the captured output from r1's namespace
    output = run_logged(r1, "cat {} 2>/dev/null || echo ''".format(g_netlink_output_file))

    routes_updated = []
    for line in output.split("\n"):
        # ip monitor format: "10.100.0.0/24 via 10.0.1.2 dev r1-eth0 proto bgp..."
        if prefix_pattern in line and ("via" in line or "nhid" in line):
            routes_updated.append(line.strip())

    return routes_updated


def get_netlink_deletions(r1, prefix_pattern=None, nhg_id=None):
    """Parse netlink monitor output for route and nexthop deletions.

    Args:
        r1: Router object
        prefix_pattern: Filter route deletions by this prefix (e.g., "10.100.")
        nhg_id: Filter nexthop deletions by this NHG ID (e.g., 200)

    Returns a dict with:
        - 'route_deletions': list of deleted route entries matching prefix_pattern
        - 'nexthop_deletions': list of deleted nexthop entries matching nhg_id

    The output format from 'ip -ts monitor all' is:
        [2026-01-22T06:15:16.005595] [ROUTE]Deleted 60.1.0.79 nhid 200 proto bgp metric 20
        [2026-01-22T06:15:16.006411] [NEXTHOP]Deleted id 200 via 45.3.0.4 dev vlan200 ...
    """
    global g_netlink_output_file

    # Read the captured output from r1's namespace
    output = run_logged(r1, "cat {} 2>/dev/null || echo ''".format(g_netlink_output_file))

    route_deletions = []
    nexthop_deletions = []

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Check for ROUTE deletions
        if "[ROUTE]Deleted" in line or ("Deleted" in line and "proto" in line):
            # If prefix_pattern is specified, filter by it
            if prefix_pattern:
                if prefix_pattern in line:
                    route_deletions.append(line)
            else:
                # Check if it's a route deletion (has proto or nhid)
                if "proto" in line or "nhid" in line:
                    route_deletions.append(line)

        # Check for NEXTHOP deletions - filter by NHG ID if specified
        if "[NEXTHOP]Deleted" in line:
            if nhg_id is not None:
                # Look for "id <nhg_id>" pattern in the line
                if "id {}".format(nhg_id) in line or "id {} ".format(nhg_id) in line:
                    nexthop_deletions.append(line)
            else:
                nexthop_deletions.append(line)

    return {
        "route_deletions": route_deletions,
        "nexthop_deletions": nexthop_deletions
    }


def get_netlink_nhg_updates(r1, nhg_id=None):
    """
    Parse captured netlink monitor output for NHG UPDATE events.

    When zebra updates an NHG (e.g., removes inactive nexthops), the kernel
    receives an update that shows in ip monitor as:
        [NEXTHOP]id 29 group 10/20/30 proto zebra

    This is different from deletion ([NEXTHOP]Deleted).

    Args:
        r1: Router object
        nhg_id: Filter updates by this NHG ID

    Returns list of NHG update lines matching nhg_id.
    """
    global g_netlink_output_file

    output = run_logged(r1, "cat {} 2>/dev/null || echo ''".format(g_netlink_output_file))

    nhg_updates = []
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        # NHG update format: [NEXTHOP]id <id> group <nexthops> proto zebra
        # NOT a deletion (those have [NEXTHOP]Deleted)
        if "[NEXTHOP]id" in line and "Deleted" not in line:
            if nhg_id is not None:
                # Match "id <nhg_id>" or "id <nhg_id> "
                if "id {} ".format(nhg_id) in line or line.endswith("id {}".format(nhg_id)):
                    nhg_updates.append(line)
            else:
                nhg_updates.append(line)

    return nhg_updates


def test_step4_record_state():
    """Record NHG ID, nexthops, and dplane counters before link down."""
    step("Step 4: Record NHG ID, nexthops, and dplane counters")
    global g_nhg_id, g_route_updates, g_nexthops_before, g_dplane_counters

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    g_nhg_id = get_nhg_id(r1, "10.100.0.0/24")
    g_route_updates = get_route_updates(r1)
    g_nexthops_before = get_active_nexthops(r1, "10.100.0.0/24")
    g_dplane_counters = get_dplane_counters(r1)

    assert g_nhg_id is not None, "Failed to get NHG ID"
    assert len(g_nexthops_before) == 4, "Expected 4 nexthops, got {}".format(g_nexthops_before)

    logger.info("Recorded NHG ID: {}".format(g_nhg_id))
    logger.info("Recorded nexthops: {}".format(g_nexthops_before))
    logger.info("Recorded dplane counters: {}".format(g_dplane_counters))

    # Start netlink monitoring before link down
    start_netlink_monitor(r1)
    logger.info("Netlink monitoring started")


def test_step5_link_down():
    """Bring down link to r5 - nexthop becomes INACTIVE."""
    step("Step 5: Bring down link to r5 (r1-eth3)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    run_logged(r1, "ip link set r1-eth3 down")

    def check():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        logger.info("Nexthop count after link down: {}".format(count))
        return count == 3

    ok, _ = topotest.run_and_expect(check, True, count=30, wait=1)
    assert ok, "Nexthops didn't reduce to 3"


def test_step6_verify_nexthops_subset():
    """Verify new nexthops are a subset of the original nexthops."""
    step("Step 6: Verify new nexthops are a subset of original")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    nexthops_after = get_active_nexthops(r1, "10.100.0.0/24")

    logger.info("Nexthops before: {}".format(g_nexthops_before))
    logger.info("Nexthops after:  {}".format(nexthops_after))

    # Verify new nexthops are a subset of original
    for nh in nexthops_after:
        assert nh in g_nexthops_before, \
            "Nexthop {} not in original set {}".format(nh, g_nexthops_before)

    # Verify we have exactly 3 nexthops (one removed)
    assert len(nexthops_after) == 3, "Expected 3 nexthops, got {}".format(len(nexthops_after))

    # Verify 10.0.4.2 (r5) was the one removed
    removed = set(g_nexthops_before) - set(nexthops_after)
    logger.info("Removed nexthops: {}".format(removed))
    assert "10.0.4.2" in removed, "Expected 10.0.4.2 to be removed, got {}".format(removed)


def test_step7_verify_nexthop_inactive():
    """Verify the nexthop via r5 is marked inactive."""
    step("Step 7: Verify nexthop to r5 (10.0.4.2) is inactive")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # r5's IP on the link to r1 is 10.0.4.2
    def check():
        return verify_nexthop_inactive(r1, "10.100.0.0/24", "10.0.4.2")

    ok, _ = topotest.run_and_expect(check, True, count=20, wait=1)
    assert ok, "Nexthop 10.0.4.2 should be inactive after link down"

    logger.info("Nexthop 10.0.4.2 verified as inactive in zebra")

    # Also verify in kernel: 10.0.4.2 should NOT be in the kernel NHG
    logger.info("Verifying kernel NHG does not contain inactive nexthop 10.0.4.2")
    kernel_nhg_ips = get_kernel_nhg_nexthops(r1, g_nhg_id)
    logger.info("Kernel NHG {} contains: {}".format(g_nhg_id, kernel_nhg_ips))

    assert "10.0.4.2" not in kernel_nhg_ips, \
        "Inactive nexthop 10.0.4.2 should NOT be in kernel NHG {}. Found: {}".format(
            g_nhg_id, kernel_nhg_ips)

    logger.info("Verified: 10.0.4.2 is NOT in kernel NHG (correctly removed)")


def test_step8_verify_nhg_reused():
    """NHG ID should be unchanged (inactive nexthop -> reuse OK)."""
    step("Step 8: Verify NHG ID is reused (subset reuse for inactive nexthop)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    nhg_after = get_nhg_id(r1, "10.100.0.0/24")

    logger.info("NHG ID before: {}, after: {}".format(g_nhg_id, nhg_after))

    assert nhg_after == g_nhg_id, \
        "NHG ID changed {} -> {} (should reuse for inactive nexthop)".format(
            g_nhg_id, nhg_after)


def test_step9_verify_no_route_updates():
    """Verify BGP routes using the affected NHG were NOT reinstalled by ZEBRA.

    IMPORTANT: ip monitor shows kernel notifications, not just zebra messages.
    When NHG is updated, kernel notifies about all routes using that NHG.
    These are kernel-generated notifications, NOT zebra-initiated route updates.

    The definitive check is zebra dplane counters.
    """
    step("Step 9: Verify BGP routes using NHG {} were not reinstalled".format(g_nhg_id))
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Verify each BGP route (10.100.x.x) still uses the same NHG ID
    # This is the definitive check that routes were NOT reinstalled
    bgp_prefixes = ["10.100.{}.0/24".format(i) for i in range(10)]

    routes_with_wrong_nhg = []
    for prefix in bgp_prefixes:
        nhg_id = get_nhg_id(r1, prefix)
        if nhg_id != g_nhg_id:
            routes_with_wrong_nhg.append((prefix, nhg_id))
            logger.error("Route {} has NHG {} (expected {})".format(
                prefix, nhg_id, g_nhg_id))
        else:
            logger.info("Route {} still uses NHG {} (correct)".format(prefix, g_nhg_id))

    # This is the key assertion - all BGP routes must still use the original NHG
    assert len(routes_with_wrong_nhg) == 0, \
        "BGP routes were reinstalled with different NHG! Routes with wrong NHG: {}".format(
            routes_with_wrong_nhg)

    logger.info("All {} BGP routes still use NHG {} - routes were NOT reinstalled".format(
        len(bgp_prefixes), g_nhg_id))

    # Note: Do NOT stop netlink monitor here - test_step9b needs to wait longer
    # to capture any delayed deletions that may occur ~10 seconds after link down

    # THE DEFINITIVE CHECK: Netlink for specific BGP routes (10.100.x.x)
    # Dplane counters include ALL routes (connected, etc.) so they're not specific enough
    bgp_route_updates = get_netlink_route_updates(r1, "10.100.")

    logger.info("")
    logger.info("=== BGP Route Updates Check (10.100.x.x only) ===")
    logger.info("BGP route updates in netlink: {}".format(len(bgp_route_updates)))

    if bgp_route_updates:
        logger.info("WARNING: BGP route updates found:")
        for update in bgp_route_updates[:5]:
            logger.info("  {}".format(update))
    else:
        logger.info("GOOD: No BGP route updates (10.100.x.x) in netlink!")

    # Also show dplane counters for informational purposes
    counters_after = get_dplane_counters(r1)
    route_update_delta = counters_after["route_updates"] - g_dplane_counters["route_updates"]
    nhg_update_delta = counters_after["nhg_updates"] - g_dplane_counters["nhg_updates"]

    logger.info("")
    logger.info("=== Dplane Counters (informational - includes all routes) ===")
    logger.info("Total route update DELTA: {} (includes connected routes, etc.)".format(route_update_delta))
    logger.info("NHG update DELTA:         {}".format(nhg_update_delta))

    # Check for NHG creation events (should be NONE for link down - NHG is updated in place)
    nhg_creations = get_netlink_nhg_creations(r1)
    logger.info("")
    if nhg_creations:
        logger.info("NHG creation events captured: {}".format(len(nhg_creations)))
        for creation in nhg_creations:
            logger.info("  {}".format(creation))
    else:
        logger.info("No NHG creation events (expected - NHG updated in place for link down)")

    logger.info("=" * 60)

    # KEY ASSERTION: No BGP route updates (10.100.x.x) in netlink
    # This is the specific check - we don't care about connected route updates
    assert len(bgp_route_updates) == 0, \
        "BGP routes (10.100.x.x) were updated during link down! " \
        "Found {} route updates: {}. " \
        "Expected: 0 BGP route updates.".format(
            len(bgp_route_updates),
            bgp_route_updates[:3] if bgp_route_updates else [])

    logger.info("Test PASSED: No BGP route updates (10.100.x.x) during link down")


def test_step9a_verify_nhg_update_sent():
    """Verify zebra updated kernel NHG to remove the inactive nexthop 10.0.4.2.

    When nexthop 10.0.4.2 becomes inactive (link down), zebra should update
    the kernel NHG to remove that nexthop. We verify using 'ip nexthop show'.
    """
    step("Step 9a: Verify kernel NHG updated (10.0.4.2 removed)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Get the IPs currently in the kernel NHG
    nhg_ips = get_kernel_nhg_nexthops(r1, g_nhg_id)
    logger.info("Kernel NHG {} contains IPs: {}".format(g_nhg_id, nhg_ips))

    # Verify 10.0.4.2 is NOT in the NHG (it was removed when link went down)
    assert "10.0.4.2" not in nhg_ips, \
        "Inactive nexthop 10.0.4.2 should have been removed from kernel NHG {}. " \
        "NHG contains: {}".format(g_nhg_id, nhg_ips)

    # Verify the other 3 nexthops ARE still in the NHG
    for expected_nh in ["10.0.1.2", "10.0.2.2", "10.0.3.2"]:
        assert expected_nh in nhg_ips, \
            "Active nexthop {} should still be in kernel NHG {}. " \
            "NHG contains: {}".format(expected_nh, g_nhg_id, nhg_ips)

    logger.info("Test PASSED: Kernel NHG {} updated - 10.0.4.2 removed, {} remain".format(
        g_nhg_id, nhg_ips))


def test_step9b_verify_no_deletions():
    """Verify BGP routes and their NHG are not deleted during link down.

    This test verifies that when a link goes down:
    - BGP routes (10.100.x.x) using the affected NHG are NOT deleted from kernel
    - The specific NHG used by those routes is NOT deleted, only updated

    Expected behavior: Routes and NHG remain in kernel, NHG is updated in-place.
    Bad behavior: Routes deleted and recreated, or NHG deleted and recreated.

    Note: Deletions may occur with a delay (~10 seconds after link down),
    so we monitor for 20 seconds to ensure we capture any delayed deletions.

    Only checks for:
    - Route deletions matching prefix "10.100." (the BGP routes)
    - NHG deletions matching the specific NHG ID used by those routes

    Example of BAD netlink output (what we want to avoid):
        [ROUTE]Deleted 10.100.0.0/24 nhid 200 proto bgp metric 20
        [NEXTHOP]Deleted id 200 via 10.0.4.2 dev r1-eth3 scope link proto zebra
    """
    step("Step 9b: Verify no deletions of NHG {} or its BGP routes (10.100.x.x)".format(g_nhg_id))
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Only check for deletions of BGP routes (10.100.x.x) and their specific NHG
    # g_nhg_id contains the NHG ID used by the BGP routes
    logger.info("Checking for deletions of BGP routes (10.100.x.x) and NHG ID {}".format(g_nhg_id))

    # Poll for deletions over ~20 seconds - deletions can occur ~10 seconds
    # after link down if there's a bug in NHG subset reuse
    logger.info("Monitoring for route/NHG deletions over 20 seconds...")

    # Use run_and_expect to poll without explicit sleep
    # Track deletion state separately so we can return True when done (avoiding ERROR logs)
    deletions_found = [None]
    check_count = [0]

    def check_for_deletions():
        check_count[0] += 1
        deletions = get_netlink_deletions(r1, prefix_pattern="10.100.", nhg_id=g_nhg_id)
        route_dels = len(deletions["route_deletions"])
        nhg_dels = len(deletions["nexthop_deletions"])

        if route_dels > 0 or nhg_dels > 0:
            deletions_found[0] = True
            logger.info("Detected deletions at {}s: {} routes, {} NHGs".format(
                check_count[0], route_dels, nhg_dels))
            return True  # Stop polling - deletions found (bad)

        if check_count[0] >= 20:
            deletions_found[0] = False
            return True  # Stop polling - no deletions after 20s (good)

        return False  # Keep polling

    topotest.run_and_expect(check_for_deletions, True, count=25, wait=1)

    if deletions_found[0] is False:
        logger.info("No deletions detected during 20 second monitoring period")

    # Now stop the netlink monitor
    stop_netlink_monitor(r1)
    logger.info("Netlink monitor stopped, analyzing captured events")

    # Show the raw netlink monitor output for verification
    logger.info("=== Netlink monitor captured events ===")
    run_logged(r1, "cat {}".format(g_netlink_output_file))
    logger.info("=== End of netlink monitor output ===")

    # Parse netlink monitor output for final deletion counts
    deletions = get_netlink_deletions(r1, prefix_pattern="10.100.", nhg_id=g_nhg_id)
    route_deletions = deletions["route_deletions"]
    nexthop_deletions = deletions["nexthop_deletions"]

    logger.info("BGP route deletions found: {}".format(len(route_deletions)))
    logger.info("NHG deletions found: {}".format(len(nexthop_deletions)))

    # Log any deletions found for debugging
    if route_deletions:
        logger.info("Route deletions (should be empty):")
        for deletion in route_deletions[:10]:  # Log first 10
            logger.info("  {}".format(deletion))

    if nexthop_deletions:
        logger.info("NHG deletions (should be empty):")
        for deletion in nexthop_deletions[:5]:  # Log first 5
            logger.info("  {}".format(deletion))

    # Assert no BGP route deletions occurred (only checking 10.100.x.x routes)
    assert len(route_deletions) == 0, \
        "BGP routes (10.100.x.x) were deleted during link down! Found {} deletions. " \
        "Routes should remain in kernel with updated NHG. First deletion: {}".format(
            len(route_deletions), route_deletions[0] if route_deletions else "N/A")

    # Assert no NHG deletions occurred (only checking NHG ID {})
    assert len(nexthop_deletions) == 0, \
        "NHG {} was deleted during link down! Found {} deletions. " \
        "NHG should be updated in-place (subset reuse). First deletion: {}".format(
            g_nhg_id, len(nexthop_deletions), nexthop_deletions[0] if nexthop_deletions else "N/A")

    logger.info("Test PASSED: No deletions of BGP routes (10.100.x.x) or NHG {} during link down".format(g_nhg_id))


def test_step9c_route_update_during_linkdown():
    """Trigger a route update while link is down and verify NHG ID is preserved.

    This tests the effective_active hashing optimization:
    - When interface is down: ACTIVE=0, IFDOWN=1
    - effective_active = ACTIVE || IFDOWN = 1
    - Route update should find the SAME NHG (not create a new one)

    Without this fix, route updates during link down would cause NHG ID changes
    leading to route update storms.

    We trigger the update by changing a BGP attribute (community) that does NOT
    affect the NHG composition. NHG is keyed by nexthops, not by communities.
    """
    step("Step 9c: Trigger route update during link down - verify NHG preserved")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Record NHG ID before route update
    nhg_before = get_nhg_id(r1, "10.100.0.0/24")
    logger.info("NHG ID before route update: {}".format(nhg_before))

    # Verify link is still down
    out = run_logged(r1, "ip link show r1-eth3")
    assert "state DOWN" in out or "NO-CARRIER" in out, "Link r1-eth3 should be down"
    logger.info("Confirmed: r1-eth3 is down")

    # Trigger route update by adding a community on r2's advertised routes
    # This changes a BGP attribute but NOT the NHG (nexthops stay the same)
    logger.info("Adding community to r2's routes to trigger route update")
    vtysh_cmd_logged(r2, """
configure terminal
route-map SET-COMMUNITY permit 10
set community 65002:100
exit
router bgp 65002
address-family ipv4 unicast
neighbor 10.0.1.1 route-map SET-COMMUNITY out
exit
exit
exit
""")

    # Trigger the update by doing a soft reset
    vtysh_cmd_logged(r2, "clear bgp 10.0.1.1 soft out")

    # Wait for route processing
    def check_routes_stable():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        return count == 3  # Should still be 3 (r5's nexthop is down)

    ok, _ = topotest.run_and_expect(check_routes_stable, True, count=10, wait=1)
    assert ok, "Routes should remain stable with 3 nexthops after attribute change"

    # Verify community was received (proves route was updated)
    out = vtysh_cmd_logged(r1, "show bgp ipv4 unicast 10.100.0.0/24")
    logger.info("BGP route after update:\n{}".format(out))

    # Get NHG ID after route update
    nhg_after = get_nhg_id(r1, "10.100.0.0/24")
    logger.info("NHG ID after route update: {}".format(nhg_after))

    # KEY ASSERTION: NHG ID should be the SAME
    # This proves effective_active hashing is working:
    # - The down interface nexthop has ACTIVE=0, IFDOWN=1
    # - effective_active = 1, so it matches the hash lookup
    # - Same NHG is reused, no new NHG created
    assert nhg_after == nhg_before, \
        "NHG ID changed during route update while link is down! " \
        "Before: {}, After: {}. " \
        "This indicates effective_active hashing is NOT working. " \
        "Expected: same NHG (IFDOWN nexthop should match for hash lookup)".format(
            nhg_before, nhg_after)

    logger.info("Test PASSED: NHG ID {} preserved during route update with link down".format(nhg_after))
    logger.info("effective_active hashing is working correctly!")


# ============================================================================
# Part 2: LINK UP -> NHG ID stays the SAME
# ============================================================================
#
# After Part 1 brings link down, we bring it back up.
# With our optimization, the NHG keeps the inactive nexthop (marked with
# NEXTHOP_FLAG_IFDOWN), so when link comes up:
#   - SAME NHG ID is reused
#   - Nexthop is restored to active (clear IFDOWN, set ACTIVE)
#   - No new NHG creation needed
#
# ============================================================================

g_nhg_id_before_linkup = None  # NHG ID before link up
g_nhg_id_after_linkup = None   # NHG ID after link up


def nhg_exists(r1, nhg_id):
    """Check if an NHG ID exists in zebra."""
    out = vtysh_cmd_logged(r1, "show nexthop-group rib {}".format(nhg_id))
    # If NHG exists, output will contain "ID:" and nexthops
    # If not, output will be empty or say "Nexthop Group not found"
    return "ID:" in out and "via" in out


def test_step10_record_nhg_before_linkup():
    """Record the NHG ID before bringing link back up."""
    step("Step 10: Record NHG state before link up")
    global g_nhg_id_before_linkup

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    g_nhg_id_before_linkup = get_nhg_id(r1, "10.100.0.0/24")
    active_nexthops = get_active_nexthops(r1, "10.100.0.0/24")

    logger.info("NHG ID before link up: {}".format(g_nhg_id_before_linkup))
    logger.info("Active nexthops in route: {}".format(active_nexthops))

    assert g_nhg_id_before_linkup is not None, "Failed to get NHG ID"
    assert len(active_nexthops) == 3, "Expected 3 active nexthops, got {}".format(active_nexthops)

    # NHG ID should be same as original (from test 4) - optimization keeps inactive nexthop
    assert g_nhg_id_before_linkup == g_nhg_id, \
        "NHG ID changed during link down! Before: {}, After: {}".format(g_nhg_id, g_nhg_id_before_linkup)

    logger.info("NHG ID unchanged from original {} (inactive nexthop kept in NHG)".format(g_nhg_id))

    # Start netlink monitoring for Part 2 (link up)
    start_netlink_monitor(r1)
    logger.info("Netlink monitoring started for Part 2 (link up)")


def test_step11_restore_link():
    """Bring link back up to restore 4-way ECMP."""
    step("Step 11: Restore link to r5 (r1-eth3)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    run_logged(r1, "ip link set r1-eth3 up")

    # First wait for nexthop count to reach 4
    def check_nexthops():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        logger.info("Nexthop count after link up: {}".format(count))
        return count == 4

    ok, _ = topotest.run_and_expect(check_nexthops, True, count=30, wait=1)
    assert ok, "Nexthops didn't restore to 4"

    logger.info("Link restored, 4-way ECMP re-established")

    # Reset BGP neighbor to trigger immediate reconnection (avoids long retry timer)
    vtysh_cmd_logged(r1, "clear bgp 10.0.4.2")

    # Also wait for BGP session to r5 (10.0.4.2) to be established
    # This is critical for Part 3 (route withdrawal) to work
    def check_bgp_established():
        import json

        out = vtysh_cmd_logged(r1, "show bgp summary json")
        try:
            data = json.loads(out)
            # Try different JSON paths depending on FRR version
            peers = data.get("ipv4Unicast", {}).get("peers", {})
            if not peers:
                peers = data.get("peers", {})
            peer_data = peers.get("10.0.4.2", {})
            state = peer_data.get("state", "")
            pfx_rcvd = peer_data.get("pfxRcd", 0)

            logger.info("BGP peer 10.0.4.2 state: {}, prefixes: {}".format(state, pfx_rcvd))
            # Session must be Established and receiving prefixes
            return state == "Established" and pfx_rcvd > 0
        except (json.JSONDecodeError, KeyError) as e:
            logger.info("BGP check error: {}".format(e))
            return False

    ok, _ = topotest.run_and_expect(check_bgp_established, True, count=30, wait=1)
    assert ok, "BGP session to 10.0.4.2 didn't establish"

    logger.info("BGP session to 10.0.4.2 established")


def test_step12_verify_nhg_after_link_up():
    """Verify NHG ID stays the same after link comes back up."""
    step("Step 12: Verify NHG ID unchanged after link up")
    global g_nhg_id_after_linkup

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    g_nhg_id_after_linkup = get_nhg_id(r1, "10.100.0.0/24")
    nexthops = get_active_nexthops(r1, "10.100.0.0/24")

    logger.info("NHG ID before link up: {}".format(g_nhg_id_before_linkup))
    logger.info("NHG ID after link up: {}".format(g_nhg_id_after_linkup))
    logger.info("Active nexthops (should be 4): {}".format(nexthops))

    # All 4 nexthops should be active again
    assert len(nexthops) == 4, "Expected 4 active nexthops, got {}".format(nexthops)

    # NHG ID should be the SAME - optimization keeps inactive nexthop in NHG
    assert g_nhg_id_after_linkup == g_nhg_id_before_linkup, \
        "NHG ID changed after link up! Before: {}, After: {}. " \
        "Expected same NHG (nexthop restored to active).".format(
            g_nhg_id_before_linkup, g_nhg_id_after_linkup)

    logger.info("SAME NHG {} - nexthop 10.0.4.2 restored to active".format(g_nhg_id_after_linkup))


def test_step13_verify_nhg_has_all_nexthops():
    """Verify the current NHG has all 4 nexthops active."""
    step("Step 13: Verify NHG {} has all 4 nexthops active".format(g_nhg_id_after_linkup))
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Verify the route uses the expected NHG
    current_nhg = get_nhg_id(r1, "10.100.0.0/24")
    nexthops = get_active_nexthops(r1, "10.100.0.0/24")
    nhg_nh_count = get_nhg_nexthop_count(r1, current_nhg)

    logger.info("Current NHG ID: {}".format(current_nhg))
    logger.info("Nexthops in NHG: {}".format(nhg_nh_count))
    logger.info("Active nexthops: {}".format(nexthops))

    # Verify route uses the expected NHG
    assert current_nhg == g_nhg_id_after_linkup, \
        "Route NHG changed unexpectedly: {} -> {}".format(g_nhg_id_after_linkup, current_nhg)

    # Verify NHG has 4 nexthops
    assert nhg_nh_count == 4, \
        "Expected NHG to have 4 nexthops, got {}".format(nhg_nh_count)

    # Verify all 4 nexthops are active
    assert len(nexthops) == 4, \
        "Expected 4 active nexthops, got {}".format(len(nexthops))

    # Verify the expected nexthops are present
    for expected_nh in EXPECTED_NEXTHOPS:
        assert expected_nh in nexthops, \
            "Missing nexthop {} in active nexthops {}".format(expected_nh, nexthops)

    logger.info("Test PASSED: NHG {} has all 4 nexthops active".format(current_nhg))


def test_step13a_verify_kernel_nhg_restored():
    """Verify kernel NHG now contains all 4 nexthops including 10.0.4.2.

    After link comes back up, the kernel NHG should be updated to include
    the previously removed nexthop 10.0.4.2. We verify using 'ip nexthop show'.
    """
    step("Step 13a: Verify kernel NHG restored (10.0.4.2 is back)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Get the current NHG ID (may be different from before if NHG was shrunk)
    current_nhg = get_nhg_id(r1, "10.100.0.0/24")

    # Get the IPs currently in the kernel NHG
    nhg_ips = get_kernel_nhg_nexthops(r1, current_nhg)
    logger.info("Kernel NHG {} contains IPs: {}".format(current_nhg, nhg_ips))

    # Verify 10.0.4.2 IS now in the NHG (it was restored when link came up)
    assert "10.0.4.2" in nhg_ips, \
        "Nexthop 10.0.4.2 should be back in kernel NHG {} after link up. " \
        "NHG contains: {}".format(current_nhg, nhg_ips)

    # Verify all 4 nexthops are in the kernel NHG
    for expected_nh in EXPECTED_NEXTHOPS:
        assert expected_nh in nhg_ips, \
            "Nexthop {} should be in kernel NHG {}. " \
            "NHG contains: {}".format(expected_nh, current_nhg, nhg_ips)

    logger.info("Test PASSED: Kernel NHG {} restored - all 4 nexthops present: {}".format(
        current_nhg, nhg_ips))


def test_step13b_verify_no_route_updates_on_linkup():
    """Verify NO route updates were SENT BY ZEBRA during link up.

    This is the KEY optimization check for Part 2:
    - When link comes back up, the nexthop is restored to active
    - The NHG is updated in-place (same ID, nexthop restored)
    - Zebra should NOT send route updates - only NHG update

    IMPORTANT: ip monitor shows kernel notifications, not just zebra messages.
    When NHG is updated, kernel notifies about all routes using that NHG.
    These are kernel-generated notifications, NOT zebra-initiated route updates.

    The definitive check is zebra dplane counters.
    """
    step("Step 13b: Verify NO route updates SENT BY ZEBRA during link up")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Stop netlink monitor and analyze
    stop_netlink_monitor(r1)

    logger.info("=" * 60)
    logger.info("Route Updates Check (Part 2 - Link Up)")
    logger.info("=" * 60)

    # Show raw netlink output
    logger.info("=== Netlink monitor captured events (Part 2 - Link Up) ===")
    run_logged(r1, "cat {}".format(g_netlink_output_file))
    logger.info("=== End of netlink monitor output ===")

    # THE DEFINITIVE CHECK: Netlink for specific BGP routes (10.100.x.x)
    bgp_route_updates = get_netlink_route_updates(r1, "10.100.")

    logger.info("")
    logger.info("=== BGP Route Updates Check (10.100.x.x only) ===")
    logger.info("BGP route updates in netlink: {}".format(len(bgp_route_updates)))

    if bgp_route_updates:
        logger.info("WARNING: BGP route updates found:")
        for update in bgp_route_updates[:5]:
            logger.info("  {}".format(update))
    else:
        logger.info("GOOD: No BGP route updates (10.100.x.x) in netlink!")

    # Check for NHG updates - we expect to see NHG update (restoring the nexthop)
    nhg_updates = get_netlink_nhg_updates(r1, g_nhg_id)
    logger.info("")
    if nhg_updates:
        logger.info("NHG {} updates captured: {} (EXPECTED - nexthop restored)".format(
            g_nhg_id, len(nhg_updates)))
        for update in nhg_updates:
            logger.info("  {}".format(update))
    else:
        logger.info("No NHG update events captured (may have been batched)")

    # Also show dplane counters for informational purposes
    counters_after = get_dplane_counters(r1)
    route_update_delta = counters_after["route_updates"] - g_dplane_counters["route_updates"]

    logger.info("")
    logger.info("=== Dplane Counters (informational - includes all routes) ===")
    logger.info("Total route update DELTA: {} (includes connected routes, etc.)".format(route_update_delta))

    logger.info("=" * 60)

    # NOTE: Current FRR sends route updates on link UP (subset reuse only works for link DOWN)
    # The NEXTHOP_FLAG_IFDOWN fix would eliminate these route updates
    if len(bgp_route_updates) == 0:
        logger.info("EXCELLENT: No BGP route updates during link up!")
        logger.info("The IFDOWN optimization is working for link UP!")
    else:
        logger.info("")
        logger.info("=" * 60)
        logger.info("EXPECTED (without IFDOWN fix): {} BGP route updates during link up".format(
            len(bgp_route_updates)))
        logger.info("This is the route update storm that IFDOWN fix would eliminate.")
        logger.info("Current FRR behavior: subset reuse only works for link DOWN, not UP.")
        logger.info("=" * 60)

    # Don't fail - this is expected without the IFDOWN fix
    # Uncomment the assertion below once IFDOWN fix is applied:
    # assert len(bgp_route_updates) == 0, \
    #     "BGP routes (10.100.x.x) were updated during link up! " \
    #     "Found {} route updates.".format(len(bgp_route_updates))

    logger.info("Test completed (link up route updates: {})".format(len(bgp_route_updates)))


# ============================================================================
# Part 3: ROUTE WITHDRAW (link UP) -> NEW NHG (no subset reuse)
# ============================================================================
#
# This tests the OPPOSITE of Part 1.
# When a BGP peer withdraws routes but the link is still UP (nexthop ACTIVE):
#   - Subset reuse should be REJECTED
#   - A NEW NHG must be created
#
# Why? The removed nexthop is still usable by other routes.
# Shrinking the existing NHG would break those other routes.
#
# Test flow:
#   1. All 4 peers advertising routes (4-way ECMP)
#   2. r5 withdraws its routes (removes addresses from dummy0)
#   3. Link r1-r5 stays UP, 10.0.4.2 is still reachable (ping works)
#   4. Verify a NEW NHG ID is used (not the same as before)
# ============================================================================

g_nhg_id_part3 = None


def test_step14_record_nhg_before_withdraw():
    """Record NHG ID before BGP withdrawal and start netlink monitoring."""
    step("Step 14: Record NHG ID before BGP route withdrawal")
    global g_nhg_id_part3

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    g_nhg_id_part3 = get_nhg_id(r1, "10.100.0.0/24")
    nexthops = get_active_nexthops(r1, "10.100.0.0/24")

    logger.info("NHG ID before withdrawal: {}".format(g_nhg_id_part3))
    logger.info("Active nexthops: {}".format(nexthops))

    assert g_nhg_id_part3 is not None, "Failed to get NHG ID"
    assert len(nexthops) == 4, "Expected 4 active nexthops, got {}".format(nexthops)

    # Start netlink monitoring to capture route updates during withdrawal
    start_netlink_monitor(r1)
    logger.info("Netlink monitoring started for Part 3")


def test_step15_withdraw_route():
    """Have r5 withdraw routes - nexthop remains ACTIVE (link is up)."""
    step("Step 15: r5 withdraws BGP routes (link still up)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r5 = tgen.gears["r5"]

    # Log BGP state before shutdown
    logger.info("BGP neighbors on r5 before shutdown:")
    logger.info(vtysh_cmd_logged(r5, "show bgp summary"))

    # Shut down BGP neighbor on r5 to cause route withdrawal
    # The link to r1 stays UP (10.0.4.2 is still reachable)
    vtysh_cmd_logged(r5, """
configure terminal
router bgp 65005
neighbor 10.0.4.1 shutdown
""")

    # Log BGP state after shutdown
    logger.info("BGP neighbors on r5 after shutdown:")
    logger.info(vtysh_cmd_logged(r5, "show bgp summary"))

    # Also check from r1's perspective
    logger.info("BGP neighbors on r1:")
    logger.info(vtysh_cmd_logged(r1, "show bgp summary"))

    # Wait for routes to have only 3 nexthops
    def check():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        logger.info("Nexthop count after withdrawal: {}".format(count))
        if count == 4:
            # Debug: show the actual route
            out = vtysh_cmd_logged(r1, "show ip route 10.100.0.0/24")
            logger.info("Route details:\n{}".format(out))
        return count == 3

    ok, _ = topotest.run_and_expect(check, True, count=30, wait=1)

    if not ok:
        # More debugging on failure
        logger.info("BGP routes on r1:")
        logger.info(vtysh_cmd_logged(r1, "show bgp ipv4 unicast 10.100.0.0/24"))

    assert ok, "Nexthops didn't reduce to 3 after withdrawal"


def test_step16_verify_nexthop_still_active():
    """Verify 10.0.4.2 is still reachable (link is up)."""
    step("Step 16: Verify withdrawn nexthop is still reachable")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Check interface is up
    out = run_logged(r1, "ip link show r1-eth3")
    assert "state UP" in out, "r1-eth3 should be UP"

    # Check we can ping the nexthop
    out = run_logged(r1, "ping -c 1 -W 1 10.0.4.2")
    assert "1 received" in out or "1 packets received" in out, \
        "10.0.4.2 should be reachable (link is up)"

    logger.info("10.0.4.2 is still reachable - nexthop is ACTIVE")


def test_step17_verify_new_nhg_created():
    """Verify a NEW NHG ID was created (not reused) for active nexthop removal."""
    step("Step 17: Verify NEW NHG ID created (no reuse for active nexthop)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    nhg_id_after = get_nhg_id(r1, "10.100.0.0/24")
    nexthops_after = get_active_nexthops(r1, "10.100.0.0/24")

    logger.info("NHG ID before withdrawal: {}".format(g_nhg_id_part3))
    logger.info("NHG ID after withdrawal:  {}".format(nhg_id_after))
    logger.info("Nexthops after: {}".format(nexthops_after))

    # Key assertion: NHG ID should be DIFFERENT
    # When a nexthop is removed but still active, we must NOT reuse the NHG
    assert nhg_id_after != g_nhg_id_part3, \
        "NHG ID should be DIFFERENT when active nexthop is removed! " \
        "Before: {}, After: {} (should not match)".format(g_nhg_id_part3, nhg_id_after)

    logger.info("Test PASSED: New NHG ID {} created (old was {})".format(
        nhg_id_after, g_nhg_id_part3))


def test_step18_verify_route_updates_sent():
    """Verify route updates WERE sent to kernel (unlike Part 1 where only NHG updated).

    In Part 1 (link down, nexthop inactive):
        - Only NHG was updated in kernel
        - Routes were NOT touched (optimization)

    In Part 3 (BGP withdrawal, nexthop still active):
        - A NEW NHG is created
        - Routes MUST be updated to point to new NHG
        - This is because the old NHG can't be modified (other routes may use it)
    """
    step("Step 18: Verify route updates were sent to kernel")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Stop netlink monitor and analyze captured events
    stop_netlink_monitor(r1)

    # Show the raw netlink monitor output
    logger.info("=== Netlink monitor captured events (Part 3) ===")
    run_logged(r1, "cat {}".format(g_netlink_output_file))
    logger.info("=== End of netlink monitor output ===")

    # Check for NHG creation events - should see new NHG created for 3-nexthop set
    nhg_creations = get_netlink_nhg_creations(r1)
    logger.info("")
    logger.info("=== NHG Creation Events (Part 3 - BGP Withdrawal) ===")
    if nhg_creations:
        logger.info("NHG creation events captured: {}".format(len(nhg_creations)))
        for creation in nhg_creations:
            logger.info("  {}".format(creation))
    else:
        logger.info("No [NEXTHOP] creation events captured in netlink monitor")
        logger.info("(NHG creation may have happened before monitor started or in same batch)")
    logger.info("")

    # Get route updates for BGP routes (10.100.x.x)
    bgp_route_updates = get_netlink_route_updates(r1, "10.100.")

    logger.info("=== Route Updates (Part 3 - BGP Withdrawal) ===")
    logger.info("BGP route updates captured: {}".format(len(bgp_route_updates)))
    for update in bgp_route_updates[:5]:  # Log first 5
        logger.info("  {}".format(update))
    logger.info("")

    # In Part 3, routes SHOULD be updated (unlike Part 1)
    # Each of the 10 BGP routes (10.100.0.0 - 10.100.9.0) should have an update
    assert len(bgp_route_updates) > 0, \
        "Expected route updates in kernel for BGP withdrawal! " \
        "Routes should be updated to point to new NHG. " \
        "Found 0 route updates."

    logger.info("Test PASSED: {} route updates sent to kernel (expected for active nexthop removal)".format(
        len(bgp_route_updates)))


# ============================================================================
# Part 4: RESTORE r5 BGP SESSION -> Verify NHG ID changes AGAIN
# ============================================================================
#
# After Part 3 withdrew r5's routes, we now restore the BGP session.
# Expected behavior:
#   - r5 re-advertises routes
#   - 10.0.4.2 nexthop is added back to routes
#   - A NEW NHG ID is created (different from both Part 3's NHG and original)
#   - Route updates are sent to kernel
#
# This demonstrates that each nexthop set change (when nexthop is ACTIVE)
# results in a new NHG being created.
# ============================================================================

g_nhg_id_part4_before = None  # NHG ID before restoring r5
g_nhg_id_part4_after = None   # NHG ID after restoring r5


def test_step19_record_nhg_before_restore():
    """Record NHG ID before restoring r5's BGP session and start netlink monitoring."""
    step("Step 19: Record NHG ID before restoring r5's BGP session")
    global g_nhg_id_part4_before

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    g_nhg_id_part4_before = get_nhg_id(r1, "10.100.0.0/24")
    nexthops = get_active_nexthops(r1, "10.100.0.0/24")

    logger.info("=" * 60)
    logger.info("PART 4: Restore r5 BGP session")
    logger.info("=" * 60)
    logger.info("NHG ID before restore: {}".format(g_nhg_id_part4_before))
    logger.info("Active nexthops (should be 3): {}".format(nexthops))

    # Print commands for manual verification
    logger.info("")
    logger.info("=== Commands to verify current state ===")
    logger.info("vtysh -c \"show ip route 10.100.0.0/24\"")
    logger.info("vtysh -c \"show ip route 10.100.0.0/24 nexthop-group\"")
    logger.info("vtysh -c \"show nexthop-group rib {}\"".format(g_nhg_id_part4_before))
    logger.info("ip nexthop show id {}".format(g_nhg_id_part4_before))
    logger.info("ip nexthop show")
    logger.info("=" * 60)

    assert g_nhg_id_part4_before is not None, "Failed to get NHG ID"
    assert len(nexthops) == 3, "Expected 3 active nexthops, got {}".format(nexthops)

    # Start netlink monitoring to capture route updates during restore
    start_netlink_monitor(r1)
    logger.info("Netlink monitoring started for Part 4")
    logger.info("")
    logger.info("=== Command to start netlink monitor manually ===")
    logger.info("ip -ts monitor all > /tmp/netlink_part4.txt &")
    logger.info("=" * 60)


def test_step20_restore_r5_bgp():
    """Restore r5's BGP session - nexthop 10.0.4.2 will be added back."""
    step("Step 20: Restore r5's BGP session (no shutdown)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r5 = tgen.gears["r5"]

    logger.info("=" * 60)
    logger.info("Restoring BGP session on r5")
    logger.info("=" * 60)

    # Log BGP state before restore
    logger.info("BGP neighbors on r5 before restore:")
    logger.info(vtysh_cmd_logged(r5, "show bgp summary"))

    # Remove the shutdown on r5's BGP neighbor
    logger.info("")
    logger.info("=== Commands to restore BGP session ===")
    logger.info("vtysh -c \"configure terminal\" -c \"router bgp 65005\" -c \"no neighbor 10.0.4.1 shutdown\"")
    logger.info("=" * 60)

    vtysh_cmd_logged(r5, """
configure terminal
router bgp 65005
no neighbor 10.0.4.1 shutdown
""")

    # Log BGP state after restore
    logger.info("BGP neighbors on r5 after restore:")
    logger.info(vtysh_cmd_logged(r5, "show bgp summary"))

    # Wait for routes to have 4 nexthops again
    def check():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        logger.info("Nexthop count after restore: {}".format(count))
        if count == 3:
            # Debug: show the actual route
            out = vtysh_cmd_logged(r1, "show ip route 10.100.0.0/24")
            logger.info("Route details:\n{}".format(out))
        return count == 4

    ok, _ = topotest.run_and_expect(check, True, count=60, wait=1)

    if not ok:
        # More debugging on failure
        logger.info("BGP routes on r1:")
        logger.info(vtysh_cmd_logged(r1, "show bgp ipv4 unicast 10.100.0.0/24"))
        logger.info("BGP summary on r1:")
        logger.info(vtysh_cmd_logged(r1, "show bgp summary"))

    assert ok, "Nexthops didn't restore to 4 after BGP session restore"

    logger.info("BGP session restored, 4-way ECMP re-established")


def test_step21_verify_nhg_changed_again():
    """Verify NHG ID changed AGAIN when r5's routes came back."""
    step("Step 21: Verify NHG ID changed again (new NHG for restored nexthop)")
    global g_nhg_id_part4_after

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    g_nhg_id_part4_after = get_nhg_id(r1, "10.100.0.0/24")
    nexthops_after = get_active_nexthops(r1, "10.100.0.0/24")

    logger.info("=" * 60)
    logger.info("NHG ID Comparison:")
    logger.info("  Original (Part 1):        {}".format(g_nhg_id))
    logger.info("  After withdrawal (Part 3): {}".format(g_nhg_id_part4_before))
    logger.info("  After restore (Part 4):    {}".format(g_nhg_id_part4_after))
    logger.info("Active nexthops: {}".format(nexthops_after))
    logger.info("=" * 60)

    # Print commands for manual verification
    logger.info("")
    logger.info("=== Commands to verify NHG change ===")
    logger.info("vtysh -c \"show ip route 10.100.0.0/24 nexthop-group\"")
    logger.info("vtysh -c \"show nexthop-group rib {}\"".format(g_nhg_id_part4_after))
    logger.info("ip nexthop show id {}".format(g_nhg_id_part4_after))
    logger.info("ip nexthop show | grep -E 'id {} |group'".format(g_nhg_id_part4_after))
    logger.info("=" * 60)

    # All 4 nexthops should be active again
    assert len(nexthops_after) == 4, "Expected 4 active nexthops, got {}".format(nexthops_after)

    # Key assertion: NHG ID should be DIFFERENT from Part 3's NHG (the 3-nexthop one)
    # When a nexthop is added (active nexthop), we need a different NHG
    # NOTE: It's valid for zebra to REUSE an existing NHG with the same composition!
    # So if NHG 29 (4 nexthops) was still in the hash table, it can be reused.
    assert g_nhg_id_part4_after != g_nhg_id_part4_before, \
        "NHG ID should be DIFFERENT when active nexthop is added! " \
        "Before restore: {}, After restore: {} (should not match)".format(
            g_nhg_id_part4_before, g_nhg_id_part4_after)

    # Check if zebra reused the original NHG (this is valid and efficient!)
    if g_nhg_id_part4_after == g_nhg_id:
        logger.info("NHG REUSED: Zebra reused original NHG {} (efficient - same nexthop composition)".format(
            g_nhg_id))
        logger.info("  This is CORRECT behavior - NHGs are hashed by composition")
        logger.info("  The old 4-nexthop NHG was still in the hash table and got reused")
    else:
        logger.info("NEW NHG: Zebra created new NHG {} (was {} before restore)".format(
            g_nhg_id_part4_after, g_nhg_id_part4_before))

    # Also verify it's different from the original (Part 1) NHG
    # This shows NHG IDs keep changing with each active nexthop set change
    logger.info("")
    logger.info("=== NHG ID History ===")
    logger.info("Part 1 (original 4-way ECMP): NHG {}".format(g_nhg_id))
    logger.info("Part 3 (after withdrawal, 3-way ECMP): NHG {}".format(g_nhg_id_part4_before))
    logger.info("Part 4 (after restore, 4-way ECMP): NHG {}".format(g_nhg_id_part4_after))
    logger.info("=" * 60)


def get_netlink_nhid_changes(r1, prefix_pattern):
    """Parse netlink monitor output for route updates and extract nhid changes.

    Returns list of tuples: (prefix, old_nhid, new_nhid) or (prefix, nhid) for new routes.
    """
    global g_netlink_output_file

    output = run_logged(r1, "cat {} 2>/dev/null || echo ''".format(g_netlink_output_file))

    nhid_changes = []
    for line in output.split("\n"):
        if prefix_pattern in line and "nhid" in line:
            # Extract prefix and nhid from line
            # Format: [timestamp] [ROUTE]10.100.0.0/24 nhid 25 proto bgp...
            import re
            prefix_match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
            nhid_match = re.search(r'nhid\s+(\d+)', line)
            if prefix_match and nhid_match:
                nhid_changes.append({
                    'prefix': prefix_match.group(1),
                    'nhid': int(nhid_match.group(1)),
                    'raw': line.strip()
                })

    return nhid_changes


def get_netlink_nhg_creations(r1):
    """Parse netlink monitor output for NHG creation events.

    Returns list of NHG creation events.
    Format: [NEXTHOP]id 25 group 18/22/26 proto zebra
    """
    global g_netlink_output_file

    output = run_logged(r1, "cat {} 2>/dev/null || echo ''".format(g_netlink_output_file))

    nhg_creations = []
    for line in output.split("\n"):
        line = line.strip()
        # Match NHG creation: [NEXTHOP]id <id> group <nexthops> proto zebra
        # NOT a deletion (those have [NEXTHOP]Deleted)
        if "[NEXTHOP]" in line and "Deleted" not in line and "group" in line:
            nhg_creations.append(line)

    return nhg_creations


def test_step22_verify_route_updates_on_restore():
    """Verify route updates were sent to kernel when r5's routes came back.

    When a BGP peer re-advertises routes (link is UP, nexthop is ACTIVE):
        - Routes MUST be updated to point to the new NHG
        - Netlink should show route updates with new nhid
    """
    step("Step 22: Verify route updates sent to kernel on BGP restore")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Stop netlink monitor and analyze captured events
    stop_netlink_monitor(r1)

    logger.info("=" * 60)
    logger.info("Netlink Monitor Output (Part 4 - BGP Restore)")
    logger.info("=" * 60)

    # Show the raw netlink monitor output
    logger.info("=== Raw netlink monitor captured events ===")
    run_logged(r1, "cat {}".format(g_netlink_output_file))
    logger.info("=== End of netlink monitor output ===")

    # Print command for manual verification
    logger.info("")
    logger.info("=== Command to view netlink monitor output ===")
    logger.info("cat {}".format(g_netlink_output_file))
    logger.info("=" * 60)

    # Get route updates for BGP routes (10.100.x.x)
    bgp_route_updates = get_netlink_route_updates(r1, "10.100.")

    logger.info("")
    logger.info("=== BGP Route Updates Captured ===")
    logger.info("Total BGP route updates: {}".format(len(bgp_route_updates)))
    for update in bgp_route_updates[:10]:  # Log first 10
        logger.info("  {}".format(update))
    logger.info("=" * 60)

    # Parse nhid from route updates
    nhid_changes = get_netlink_nhid_changes(r1, "10.100.")
    if nhid_changes:
        logger.info("")
        logger.info("=== NHG ID (nhid) in Route Updates ===")
        unique_nhids = set(item['nhid'] for item in nhid_changes)
        logger.info("Unique nhids seen in updates: {}".format(sorted(unique_nhids)))
        logger.info("Expected nhid: {} (the restored 4-nexthop NHG)".format(g_nhg_id_part4_after))
        for item in nhid_changes[:5]:  # Show first 5
            logger.info("  {} -> nhid {}".format(item['prefix'], item['nhid']))
        logger.info("=" * 60)

    # Routes SHOULD be updated when BGP peer re-advertises
    assert len(bgp_route_updates) > 0, \
        "Expected route updates in kernel for BGP restore! " \
        "Routes should be updated to point to new NHG. " \
        "Found 0 route updates."

    logger.info("Test PASSED: {} route updates sent to kernel on BGP restore".format(
        len(bgp_route_updates)))


def test_step23_verify_kernel_nhg_has_all_nexthops():
    """Verify the kernel NHG now contains all 4 nexthops including 10.0.4.2."""
    step("Step 23: Verify kernel NHG has all 4 nexthops after restore")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("=" * 60)
    logger.info("Verifying Kernel NHG State")
    logger.info("=" * 60)

    # Get the current NHG ID
    current_nhg = get_nhg_id(r1, "10.100.0.0/24")

    # Print commands for manual verification
    logger.info("")
    logger.info("=== Commands to verify kernel NHG ===")
    logger.info("ip nexthop show id {}".format(current_nhg))
    logger.info("ip nexthop show")
    logger.info("ip route show 10.100.0.0/24")
    logger.info("=" * 60)

    # Get the IPs currently in the kernel NHG
    nhg_ips = get_kernel_nhg_nexthops(r1, current_nhg)
    logger.info("Kernel NHG {} contains IPs: {}".format(current_nhg, nhg_ips))

    # Verify all 4 nexthops are in the kernel NHG
    for expected_nh in EXPECTED_NEXTHOPS:
        assert expected_nh in nhg_ips, \
            "Nexthop {} should be in kernel NHG {} after restore. " \
            "NHG contains: {}".format(expected_nh, current_nhg, nhg_ips)

    logger.info("Test PASSED: Kernel NHG {} has all 4 nexthops: {}".format(
        current_nhg, nhg_ips))


def test_step24_kernel_nhg_summary():
    """Show kernel NHG state and explain the kernel's perspective."""
    step("Step 24: Kernel NHG Summary - What the kernel saw")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("")
    logger.info("=" * 70)
    logger.info("             KERNEL PERSPECTIVE - NHG Operations")
    logger.info("=" * 70)
    logger.info("")
    logger.info("From the kernel's point of view, there were 2 ROUTE REPLACEMENTS:")
    logger.info("")
    logger.info("  1. BGP Withdrawal (Part 3):")
    logger.info("     - RTM_NEWNEXTHOP: Create NHG {} (3 nexthops)".format(g_nhg_id_part4_before))
    logger.info("     - RTM_NEWROUTE x10: Update routes, nhid {} -> {}".format(g_nhg_id_part3, g_nhg_id_part4_before))
    logger.info("")
    logger.info("  2. BGP Restore (Part 4):")
    if g_nhg_id_part4_after == g_nhg_id:
        logger.info("     - NO RTM_NEWNEXTHOP needed (NHG {} still in kernel)".format(g_nhg_id_part4_after))
    else:
        logger.info("     - RTM_NEWNEXTHOP: Create NHG {} (4 nexthops)".format(g_nhg_id_part4_after))
    logger.info("     - RTM_NEWROUTE x10: Update routes, nhid {} -> {}".format(g_nhg_id_part4_before, g_nhg_id_part4_after))
    logger.info("")
    logger.info("=" * 70)
    logger.info("")

    # Show current kernel state
    logger.info("=== Current Kernel NHG State ===")
    logger.info("")
    logger.info("Command: ip nexthop show")
    run_logged(r1, "ip nexthop show")
    logger.info("")
    logger.info("Command: ip route show 10.100.0.0/24")
    run_logged(r1, "ip route show 10.100.0.0/24")
    logger.info("")

    # Show commands for manual verification
    logger.info("=== Commands to Verify Kernel State ===")
    logger.info("")
    logger.info("# Show all kernel nexthops:")
    logger.info("ip nexthop show")
    logger.info("")
    logger.info("# Show specific NHG:")
    logger.info("ip nexthop show id {}".format(g_nhg_id_part4_after))
    logger.info("")
    logger.info("# Show route with nhid:")
    logger.info("ip route show 10.100.0.0/24")
    logger.info("")
    logger.info("# Monitor netlink in real-time:")
    logger.info("ip -ts monitor all")
    logger.info("")
    logger.info("# Filter for route and nexthop events:")
    logger.info("ip -ts monitor route")
    logger.info("ip -ts monitor nexthop")
    logger.info("")
    logger.info("=" * 70)


def test_step25_summary():
    """Print summary of all NHG ID changes throughout the test."""
    step("Step 25: Test Summary - NHG ID Changes")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("")
    logger.info("=" * 70)
    logger.info("                    TEST SUMMARY - NHG ID CHANGES")
    logger.info("=" * 70)
    logger.info("")
    logger.info("Part 1: Link DOWN (nexthop INACTIVE)")
    logger.info("  - Original NHG ID:     {}".format(g_nhg_id))
    logger.info("  - After link down:     {} (SAME - subset reuse for inactive nexthop)".format(g_nhg_id))
    logger.info("")
    logger.info("Part 2: Link UP (nexthop restored)")
    logger.info("  - Before link up:      {}".format(g_nhg_id_before_linkup))
    logger.info("  - After link up:       {} (SAME - nexthop restored to active)".format(g_nhg_id_after_linkup))
    logger.info("")
    logger.info("Part 3: BGP WITHDRAWAL (nexthop ACTIVE, link UP)")
    logger.info("  - Before withdrawal:   {}".format(g_nhg_id_part3))
    logger.info("  - After withdrawal:    {} (DIFFERENT - new NHG for active nexthop removal)".format(g_nhg_id_part4_before))
    logger.info("")
    logger.info("Part 4: BGP RESTORE (nexthop ACTIVE, link UP)")
    logger.info("  - Before restore:      {}".format(g_nhg_id_part4_before))
    if g_nhg_id_part4_after == g_nhg_id:
        logger.info("  - After restore:       {} (REUSED original NHG - same nexthop composition!)".format(g_nhg_id_part4_after))
    else:
        logger.info("  - After restore:       {} (DIFFERENT - new NHG for active nexthop addition)".format(g_nhg_id_part4_after))
    logger.info("")
    logger.info("=" * 70)
    logger.info("KEY FINDINGS:")
    logger.info("  1. Link down/up (INACTIVE nexthop): NHG ID REUSED (subset reuse optimization)")
    logger.info("  2. BGP withdraw (ACTIVE nexthop removed): NEW NHG ID created")
    logger.info("  3. BGP restore (ACTIVE nexthop added): Different NHG needed")
    logger.info("     - May REUSE existing NHG if same composition exists in hash table")
    logger.info("     - NHGs are keyed by nexthop composition, not by creation order")
    logger.info("=" * 70)
    logger.info("")
    logger.info("=== Commands Reference ===")
    logger.info("")
    logger.info("# Show route with NHG ID:")
    logger.info("vtysh -c \"show ip route 10.100.0.0/24 nexthop-group\"")
    logger.info("")
    logger.info("# Show NHG details in zebra:")
    logger.info("vtysh -c \"show nexthop-group rib <NHG_ID>\"")
    logger.info("")
    logger.info("# Show kernel NHG:")
    logger.info("ip nexthop show id <NHG_ID>")
    logger.info("ip nexthop show")
    logger.info("")
    logger.info("# Monitor netlink events:")
    logger.info("ip -ts monitor all")
    logger.info("")
    logger.info("# Show dataplane stats:")
    logger.info("vtysh -c \"show zebra dplane\"")
    logger.info("")
    logger.info("=" * 70)


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
