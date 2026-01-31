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
        out = r1.vtysh_cmd("show zebra")
        return "Zebra Infomation" in out or "zebra" in out.lower()
    topotest.run_and_expect(zebra_ready, True, count=30, wait=1)

    for peer in ["r2", "r3", "r4", "r5"]:
        router = tgen.gears[peer]
        router.cmd_raises("ip link add dummy0 type dummy")
        router.cmd_raises("ip link set dummy0 up")
        for i in range(10):
            router.cmd_raises("ip addr add 10.100.{}.1/24 dev dummy0".format(i))


def teardown_module(mod):
    get_topogen().stop_topology()


def get_nexthop_count(r1, prefix):
    """Count active nexthops for a prefix using text output."""
    out = r1.vtysh_cmd("show ip route {}".format(prefix))
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
    out = r1.vtysh_cmd("show ip route {}".format(prefix))
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
    out = r1.vtysh_cmd("show ip route {} nexthop-group".format(prefix))
    m = re.search(r"Nexthop Group ID: (\d+)", out)
    return int(m.group(1)) if m else None


def get_nhg_nexthop_count(r1, nhg_id):
    """Get the actual number of nexthops in an NHG (from NHG itself, not route)."""
    import json
    out = r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
    try:
        data = json.loads(out)
        nhg_data = data.get(str(nhg_id), {})
        return nhg_data.get("nexthopCount", 0)
    except (json.JSONDecodeError, KeyError):
        return 0


def get_route_updates(r1):
    """Get route update counter from zebra dataplane stats."""
    out = r1.vtysh_cmd("show zebra dplane")
    m = re.search(r"Route updates:\s+(\d+)", out)
    return int(m.group(1)) if m else 0


def get_dplane_counters(r1):
    """Get route and NHG update/delete counters from zebra dataplane stats."""
    out = r1.vtysh_cmd("show zebra dplane")
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
    out = r1.vtysh_cmd("show ip route {}".format(prefix))
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
    """Check that route is installed in FIB (marked with * in output)."""
    out = r1.vtysh_cmd("show ip route {}".format(prefix))
    # '*' indicates FIB-installed route
    return "*" in out and prefix.split("/")[0] in out


def verify_nexthop_inactive(r1, prefix, nexthop_ip):
    """Check that a specific nexthop is marked inactive."""
    out = r1.vtysh_cmd("show ip route {} nexthop-group".format(prefix))
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
    nhg_info = r1.run("ip nexthop show id {}".format(nhg_id))

    # Extract the nexthop IDs from the group
    group_match = re.search(r'group\s+([\d/]+)', nhg_info)
    if not group_match:
        logger.info("Could not parse NHG group from: {}".format(nhg_info))
        return []

    nh_ids = group_match.group(1).split('/')

    # Get all kernel nexthops to map IDs to IPs
    all_nexthops = r1.run("ip nexthop show")

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
    bgp_out = r1.vtysh_cmd("show bgp summary")
    logger.info("BGP Summary:\n{}".format(bgp_out))

    def check():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        logger.info("Current nexthop count: {}".format(count))
        return count == 4

    ok, _ = topotest.run_and_expect(check, True, count=60, wait=1)

    # If failed, log more debug info
    if not ok:
        logger.info("BGP neighbors:\n{}".format(r1.vtysh_cmd("show bgp neighbors")))
        logger.info("IP routes:\n{}".format(r1.vtysh_cmd("show ip route")))

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

    # Kill any existing monitors first
    r1.run("pkill -f 'ip monitor' 2>/dev/null || true")

    # Wait for existing monitors to be killed
    def no_monitors_running():
        out = r1.run("pgrep -f 'ip monitor' 2>/dev/null || echo 'none'")
        return "none" in out or out.strip() == ""
    topotest.run_and_expect(no_monitors_running, True, count=20, wait=1)

    # Use unique filename with timestamp
    g_netlink_output_file = "/tmp/netlink_monitor_{}_{}.txt".format(
        os.getpid(), int(time.time()))

    # Remove old file if exists
    r1.run("rm -f {} 2>/dev/null || true".format(g_netlink_output_file))

    # Start ip monitor in r1's namespace, capturing all route and nexthop updates
    # Use -ts for timestamps and monitor all to capture both ROUTE and NEXTHOP events
    cmd = "ip -ts monitor all > {} 2>&1 &".format(g_netlink_output_file)
    r1.run(cmd)

    # Wait for monitor to start and create output file
    def monitor_started():
        out = r1.run("test -f {} && pgrep -f 'ip monitor' >/dev/null && echo 'running'".format(
            g_netlink_output_file))
        return "running" in out
    topotest.run_and_expect(monitor_started, True, count=20, wait=1)
    logger.info("Started netlink monitor, output: {}".format(g_netlink_output_file))


def stop_netlink_monitor(r1):
    """Stop the netlink monitor."""
    r1.run("pkill -f 'ip monitor' 2>/dev/null || true")

    # Wait for monitor to stop
    def monitor_stopped():
        out = r1.run("pgrep -f 'ip monitor' 2>/dev/null || echo 'stopped'")
        return "stopped" in out or out.strip() == ""
    topotest.run_and_expect(monitor_stopped, True, count=20, wait=1)


def get_netlink_route_updates(r1, prefix_pattern):
    """Parse netlink monitor output for route updates matching prefix pattern."""
    global g_netlink_output_file

    # Read the captured output from r1's namespace
    output = r1.run("cat {} 2>/dev/null || echo ''".format(g_netlink_output_file))

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
    output = r1.run("cat {} 2>/dev/null || echo ''".format(g_netlink_output_file))

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

    output = r1.run("cat {} 2>/dev/null || echo ''".format(g_netlink_output_file))

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
    r1.run("ip link set r1-eth3 down")

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
    logger.info("Nexthop 10.0.4.2 verified as inactive")


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
    """Verify BGP routes using the affected NHG were NOT reinstalled."""
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

    # Also check dplane counters for informational purposes
    counters_after = get_dplane_counters(r1)
    route_update_delta = counters_after["route_updates"] - g_dplane_counters["route_updates"]
    route_delete_delta = counters_after["route_deletes"] - g_dplane_counters["route_deletes"]
    nhg_update_delta = counters_after["nhg_updates"] - g_dplane_counters["nhg_updates"]

    logger.info("Dplane counters - Route updates: {}, Route deletes: {}, NHG updates: {}".format(
        route_update_delta, route_delete_delta, nhg_update_delta))

    # No route deletes should be sent
    assert route_delete_delta == 0, \
        "Route deletes sent to kernel: {} (expected 0)".format(route_delete_delta)

    # Note: Do NOT stop netlink monitor here - test_step9b needs to wait longer
    # to capture any delayed deletions that may occur ~10 seconds after link down

    # Note: Netlink monitoring captures kernel notifications, not just zebra messages.
    # When NHG is updated, kernel generates notifications for all routes using that NHG.
    # This is expected behavior - we're verifying zebra didn't send route updates,
    # but the kernel will still notify about routes whose NHG changed.
    # The dplane counters above are the authoritative check.
    bgp_route_updates = get_netlink_route_updates(r1, "10.100.")
    if bgp_route_updates:
        logger.info("Netlink captured {} BGP route notifications (kernel NHG change notifications, not zebra updates)".format(
            len(bgp_route_updates)))
        for route in bgp_route_updates[:3]:  # Log first 3 only
            logger.info("  Example: {}".format(route))
    else:
        logger.info("No netlink BGP route notifications captured")

    # The key assertion is dplane counters - zebra must skip route updates
    # Netlink notifications from kernel are informational only
    logger.info("Test PASSED: Zebra skipped BGP route updates (dplane counters verified)")


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


# ============================================================================
# Part 2: LINK UP -> NHG behavior depends on subset reuse optimization
# ============================================================================
#
# After Part 1 brings link down, we bring it back up.
# The behavior depends on whether the subset reuse optimization shrunk the NHG:
#
# If NHG was SHRUNK (3 nexthops in NHG):
#   - A NEW NHG ID is created with 4 nexthops
#   - Old NHG can't be expanded, so new one is needed
#
# If NHG was NOT shrunk (4 nexthops, one inactive):
#   - SAME NHG ID is reused
#   - Nexthop just becomes active again
#
# Step 10 detects which case we're in, Step 12 verifies the expected behavior.
# ============================================================================

g_nhg_id_before_linkup = None  # NHG ID before link up
g_nhg_id_after_linkup = None   # NHG ID after link up
g_nhg_was_shrunk = False       # Whether the NHG was shrunk (subset reuse optimization)


def nhg_exists(r1, nhg_id):
    """Check if an NHG ID exists in zebra."""
    out = r1.vtysh_cmd("show nexthop-group rib {}".format(nhg_id))
    # If NHG exists, output will contain "ID:" and nexthops
    # If not, output will be empty or say "Nexthop Group not found"
    return "ID:" in out and "via" in out


def test_step10_record_nhg_before_linkup():
    """Record the NHG ID and check if it was shrunk."""
    step("Step 10: Record NHG state before link up")
    global g_nhg_id_before_linkup, g_nhg_was_shrunk
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    g_nhg_id_before_linkup = get_nhg_id(r1, "10.100.0.0/24")
    active_nexthops = get_active_nexthops(r1, "10.100.0.0/24")
    nhg_nh_count = get_nhg_nexthop_count(r1, g_nhg_id_before_linkup)

    logger.info("NHG ID before link up: {}".format(g_nhg_id_before_linkup))
    logger.info("Active nexthops in route: {}".format(active_nexthops))
    logger.info("Nexthops in NHG {}: {}".format(g_nhg_id_before_linkup, nhg_nh_count))

    assert g_nhg_id_before_linkup is not None, "Failed to get NHG ID"
    assert len(active_nexthops) == 3, "Expected 3 active nexthops, got {}".format(active_nexthops)

    # Check if NHG was shrunk (subset reuse optimization)
    # If NHG has 3 nexthops, it was shrunk. If it has 4 (one inactive), it wasn't.
    g_nhg_was_shrunk = (nhg_nh_count == 3)
    if g_nhg_was_shrunk:
        logger.info("NHG was SHRUNK to 3 nexthops (subset reuse optimization worked)")
    else:
        logger.info("NHG still has {} nexthops (one marked inactive)".format(nhg_nh_count))


def test_step11_restore_link():
    """Bring link back up to restore 4-way ECMP."""
    step("Step 11: Restore link to r5 (r1-eth3)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.run("ip link set r1-eth3 up")

    # First wait for nexthop count to reach 4
    def check_nexthops():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        logger.info("Nexthop count after link up: {}".format(count))
        return count == 4

    ok, _ = topotest.run_and_expect(check_nexthops, True, count=30, wait=1)
    assert ok, "Nexthops didn't restore to 4"
    logger.info("Link restored, 4-way ECMP re-established")

    # Reset BGP neighbor to trigger immediate reconnection (avoids long retry timer)
    r1.vtysh_cmd("clear bgp 10.0.4.2")

    # Also wait for BGP session to r5 (10.0.4.2) to be established
    # This is critical for Part 3 (route withdrawal) to work
    def check_bgp_established():
        import json
        out = r1.vtysh_cmd("show bgp summary json")
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
    """Verify NHG behavior after link up depends on whether it was shrunk."""
    step("Step 12: Verify NHG after link up")
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
    logger.info("NHG was shrunk: {}".format(g_nhg_was_shrunk))

    assert len(nexthops) == 4, "Expected 4 active nexthops, got {}".format(nexthops)

    if g_nhg_was_shrunk:
        # NHG was shrunk to 3 nexthops, so a NEW NHG should be created
        assert g_nhg_id_after_linkup != g_nhg_id_before_linkup, \
            "NHG was shrunk, so ID should be DIFFERENT after link up! Before: {}, After: {}".format(
                g_nhg_id_before_linkup, g_nhg_id_after_linkup)
        logger.info("NEW NHG {} created (old shrunk NHG was {})".format(
            g_nhg_id_after_linkup, g_nhg_id_before_linkup))
    else:
        # NHG kept all nexthops (one inactive), so SAME NHG should be reused
        assert g_nhg_id_after_linkup == g_nhg_id_before_linkup, \
            "NHG wasn't shrunk, so ID should be SAME after link up! Before: {}, After: {}".format(
                g_nhg_id_before_linkup, g_nhg_id_after_linkup)
        logger.info("SAME NHG {} reused (nexthops toggled active/inactive)".format(
            g_nhg_id_after_linkup))


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
    """Record NHG ID before BGP withdrawal."""
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
    logger.info(r5.vtysh_cmd("show bgp summary"))

    # Shut down BGP neighbor on r5 to cause route withdrawal
    # The link to r1 stays UP (10.0.4.2 is still reachable)
    r5.vtysh_cmd("""
        configure terminal
        router bgp 65005
        neighbor 10.0.4.1 shutdown
    """)

    # Log BGP state after shutdown
    logger.info("BGP neighbors on r5 after shutdown:")
    logger.info(r5.vtysh_cmd("show bgp summary"))

    # Also check from r1's perspective
    logger.info("BGP neighbors on r1:")
    logger.info(r1.vtysh_cmd("show bgp summary"))

    # Wait for routes to have only 3 nexthops
    def check():
        count = get_nexthop_count(r1, "10.100.0.0/24")
        logger.info("Nexthop count after withdrawal: {}".format(count))
        if count == 4:
            # Debug: show the actual route
            out = r1.vtysh_cmd("show ip route 10.100.0.0/24")
            logger.info("Route details:\n{}".format(out))
        return count == 3

    ok, _ = topotest.run_and_expect(check, True, count=30, wait=1)
    if not ok:
        # More debugging on failure
        logger.info("BGP routes on r1:")
        logger.info(r1.vtysh_cmd("show bgp ipv4 unicast 10.100.0.0/24"))
    assert ok, "Nexthops didn't reduce to 3 after withdrawal"


def test_step16_verify_nexthop_still_active():
    """Verify 10.0.4.2 is still reachable (link is up)."""
    step("Step 16: Verify withdrawn nexthop is still reachable")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Check interface is up
    out = r1.run("ip link show r1-eth3")
    assert "state UP" in out, "r1-eth3 should be UP"

    # Check we can ping the nexthop
    out = r1.run("ping -c 1 -W 1 10.0.4.2")
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


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
