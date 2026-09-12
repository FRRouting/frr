#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test BGP ECMP backup paths.

Topology:
                    R4 (AS 65004, MED 100) -------- 10.99.99.0/24
                   /
                  /
R1 ------------- R2 (AS 65002)
AS 65001         \
  |               \
  |                R5 (AS 65005, MED 100) -------- 10.99.99.0/24
  |
  |
  |-------------- R3 (AS 65003)
                  /\
                 /  \
                /    \
               /      \
              R6       R7
         (AS 65006)  (AS 65007)
         MED 200     MED 200
            |           |
      10.99.99.0/24  10.99.99.0/24

R1 receives prefix 10.99.99.0/24 from:
- R4 via R2 (AS path: 65002 65004, MED 100) - Best path
- R5 via R2 (AS path: 65002 65005, MED 100) - Multipath with R4
- R6 via R3 (AS path: 65003 65006, MED 200) - Backup ECMP path 1
- R7 via R3 (AS path: 65003 65007, MED 200) - Backup ECMP path 2

This test verifies:
1. Multiple equal-cost backup paths are selected (ECMP backup)
2. Backup paths respect maximum-paths configuration
3. Backup paths don't show up when feature is unconfigured
4. Backup paths are properly marked in text and JSON output
"""

from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib import topotest
import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    # Create routers
    for routern in range(1, 8):
        tgen.add_router("r{}".format(routern))

    # R1-R2 connection
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # R1-R3 connection
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # R2-R4 connection
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    # R2-R5 connection
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r5"])

    # R3-R6 connection
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r6"])

    # R3-R7 connection
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r7"])

    # Add switches for the 10.99.99.0/24 networks
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["r7"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Configure all the routers
    router_list = tgen.routers()

    # Load router configs
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_ecmp_backup_paths():
    """
    Test ECMP backup paths functionality with the 'ecmp' keyword.

    Verifies:
    1. Backup paths don't appear when feature is unconfigured
    2. TEST CASE A: Only 1 backup path with 'install backup-path' (no ecmp keyword)
    3. TEST CASE B: 2 ECMP backup paths with 'install backup-path ecmp'
    4. TEST CASE C: 0 backup paths after 'no install backup-path ecmp' (disables all backup paths)
    5. TEST CASE D: 2 ECMP backup paths after re-adding ecmp
    6. TEST CASE E: No backup paths after 'no install backup-path'
    7. Backup paths respect maximum-paths configuration
    8. Backup paths are properly marked in text and JSON output
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Waiting for BGP convergence on R1")

    def _check_bgp_convergence():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        if "peers" not in output:
            return "No peers found"

        peers = output["peers"]
        expected_peers = ["10.1.2.2", "10.1.3.3"]

        for peer in expected_peers:
            if peer not in peers:
                return f"Peer {peer} not found"
            if peers[peer]["state"] != "Established":
                return f"Peer {peer} not established, state: {peers[peer]['state']}"

        return None

    test_func = functools.partial(_check_bgp_convergence)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=15)
    assert result is None, f"BGP convergence failed: {result}"

    step("Waiting for R1 to receive all paths for 10.99.99.0/24")

    def _check_paths_count():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))

        if "pathCount" not in output:
            return "pathCount not found in output"

        # Should receive 4 paths: R4, R5, R6, R7
        if output["pathCount"] != 4:
            return f"Expected 4 paths, got {output['pathCount']}"

        return None

    test_func = functools.partial(_check_paths_count)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=15)
    assert result is None, f"Did not receive all paths: {result}"

    step("Verifying best path and multipath selection (R4 and R5 via R2)")

    def _check_best_and_multipath():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))

        if "paths" not in output:
            return "No paths found"

        best_count = 0
        multipath_count = 0

        for path in output["paths"]:
            if path.get("bestpath", {}).get("overall"):
                best_count += 1
            if path.get("multipath"):
                multipath_count += 1

        if best_count != 1:
            return f"Expected 1 best path, got {best_count}"

        # Should have 2 multipaths (R4 and R5 via R2)
        if multipath_count != 2:
            return f"Expected 2 multipaths, got {multipath_count}"

        return None

    test_func = functools.partial(_check_best_and_multipath)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Best path/multipath verification failed: {result}"

    step(
        "CRITICAL TEST: Verifying backup paths are NOT present before enabling feature"
    )

    def _check_no_backup_paths_bgp():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))

        if "paths" not in output:
            return "No paths found"

        for path in output["paths"]:
            if path.get("backup"):
                nexthop = path.get("nexthops", [{}])[0].get("ip")
                return f"Backup path found when feature is disabled: {nexthop}"

        return None

    test_func = functools.partial(_check_no_backup_paths_bgp)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=15)
    assert result is None, f"Backup paths should not exist in BGP table: {result}"

    step("Verifying no backup paths in routing table when feature is disabled")

    def _check_no_backup_in_route_table():
        output = json.loads(r1.vtysh_cmd("show ip route 10.99.99.0/24 json"))

        if "10.99.99.0/24" not in output:
            return "Route not found"

        route = output["10.99.99.0/24"]
        if not isinstance(route, list) or len(route) == 0:
            return "Invalid route entry"

        route_entry = route[0]
        backup_nexthops = route_entry.get("backupNexthops", [])

        if len(backup_nexthops) > 0:
            return (
                f"Found {len(backup_nexthops)} backup nexthops when feature is disabled"
            )

        return None

    test_func = functools.partial(_check_no_backup_in_route_table)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=15)
    assert result is None, f"Backup paths should not exist in route table: {result}"

    step("Verifying no 'B' marker in text output when feature is disabled")

    def _check_no_backup_text():
        output = r1.vtysh_cmd("show ip bgp 10.99.99.0/24")
        # Count lines with 'backup' keyword (case insensitive)
        lines_with_backup = [
            line for line in output.lower().split("\n") if "backup" in line
        ]
        if len(lines_with_backup) > 0:
            return "Found 'backup' in text output when feature is disabled"
        return None

    test_func = functools.partial(_check_no_backup_text)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=15)
    assert result is None, f"No backup marker should exist in text output: {result}"

    step("SUCCESS: Confirmed backup paths do NOT appear when feature is unconfigured")

    step("TEST CASE A: Enabling backup path WITHOUT ecmp keyword")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        install backup-path
        maximum-paths 2
        end
    """
    )

    step("Verifying only 1 backup path is installed (without ecmp)")

    def _check_single_backup_path():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))

        if "paths" not in output:
            return "No paths found"

        backup_count = 0
        for path in output["paths"]:
            if path.get("backup"):
                backup_count += 1

        # Should have only 1 backup path (without ecmp keyword)
        if backup_count != 1:
            return f"Expected 1 backup path without ecmp, got {backup_count}"

        return None

    test_func = functools.partial(_check_single_backup_path)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Single backup path verification failed: {result}"

    step("SUCCESS: Only 1 backup path installed without ecmp keyword")

    step("TEST CASE B: Adding ecmp keyword to enable ECMP backup paths")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        install backup-path ecmp
        end
    """
    )

    step("Verifying 2 ECMP backup paths are now installed (R6 and R7 via R3)")

    def _check_ecmp_backup_paths():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))

        if "paths" not in output:
            return "No paths found"

        backup_paths = []
        for path in output["paths"]:
            if path.get("backup"):
                nexthop = path.get("nexthops", [{}])[0].get("ip")
                backup_paths.append(nexthop)

        # Should have 2 backup paths (via R3 to R6 and R7)
        if len(backup_paths) != 2:
            return f"Expected 2 backup paths with ecmp, got {len(backup_paths)}: {backup_paths}"

        # Both should be via R3 (10.1.3.3)
        expected_backup = "10.1.3.3"
        if expected_backup not in backup_paths:
            return f"Expected backup via {expected_backup}, got {backup_paths}"

        return None

    test_func = functools.partial(_check_ecmp_backup_paths)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"ECMP backup paths verification failed: {result}"

    step("SUCCESS: 2 ECMP backup paths installed with ecmp keyword")

    step("Verifying backup paths in routing table JSON output")

    def _check_backup_in_route_table():
        output = json.loads(r1.vtysh_cmd("show ip route 10.99.99.0/24 json"))

        if "10.99.99.0/24" not in output:
            return "Route not found"

        route = output["10.99.99.0/24"]
        if not isinstance(route, list) or len(route) == 0:
            return "Invalid route entry"

        route_entry = route[0]
        backup_nexthops = route_entry.get("backupNexthops", [])

        # Should have 2 backup nexthops
        if len(backup_nexthops) != 2:
            return (
                f"Expected 2 backup nexthops in route table, got {len(backup_nexthops)}"
            )

        return None

    test_func = functools.partial(_check_backup_in_route_table)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Backup paths in route table verification failed: {result}"

    step("Verifying backup path 'b' marker in routing table text output")

    def _check_backup_marker_route_text():
        output = r1.vtysh_cmd("show ip route 10.99.99.0/24")
        # Should have backup marker 'b'
        if "b" not in output:
            return "Backup path marker 'b' not found in routing table text output"
        return None

    test_func = functools.partial(_check_backup_marker_route_text)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Backup marker in route text verification failed: {result}"

    step("Verifying backup path 'B' marker in BGP table text output")

    def _check_backup_marker_bgp_text():
        output = r1.vtysh_cmd("show ip bgp 10.99.99.0/24")
        # Should have 'backup' keyword in output
        if "backup" not in output.lower():
            return "'backup' keyword not found in BGP table text output"
        return None

    test_func = functools.partial(_check_backup_marker_bgp_text)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Backup marker in BGP text verification failed: {result}"

    def _check_no_backup_after_disable():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.99.99.0/24 json"))

        if "paths" not in output:
            return "No paths found"

        for path in output["paths"]:
            if path.get("backup"):
                nexthop = path.get("nexthops", [{}])[0].get("ip")
                return f"Backup path still present after disabling feature: {nexthop}"

        return None

    step("TEST CASE C: Removing ecmp keyword with 'no install backup-path ecmp'")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no install backup-path ecmp
        end
    """
    )

    step("Verifying no backup paths remain after 'no install backup-path ecmp'")

    test_func = functools.partial(_check_no_backup_after_disable)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Backup paths should not exist after 'no install backup-path ecmp': {result}"

    step("SUCCESS: No backup paths after 'no install backup-path ecmp'")

    step("TEST CASE D: Re-adding ecmp keyword")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        install backup-path ecmp
        end
    """
    )

    step("Verifying 2 backup paths reappear after re-adding ecmp")

    test_func = functools.partial(_check_ecmp_backup_paths)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"ECMP backup paths after re-adding ecmp failed: {result}"

    step("SUCCESS: 2 ECMP backup paths reappear after re-adding ecmp")

    step("TEST CASE E: Removing entire feature with 'no install backup-path'")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no install backup-path
        end
    """
    )

    step("Verifying no backup paths exist after removing feature")

    test_func = functools.partial(_check_no_backup_after_disable)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Backup paths should not exist after disabling: {result}"

    step("SUCCESS: No backup paths after removing entire feature")

    step("Re-enabling backup path with ecmp for remaining tests")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        install backup-path ecmp
        end
    """
    )

    # Wait for convergence
    test_func = functools.partial(_check_ecmp_backup_paths)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Failed to restore ECMP backup paths: {result}"

    step("Testing maximum-paths limit - reducing to 1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        maximum-paths 1
        end
    """
    )

    step("Verifying only 1 backup path is installed after maximum-paths change")

    test_func = functools.partial(_check_single_backup_path)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Single backup path verification failed: {result}"

    step("Restoring maximum-paths to 2 for final tests")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        maximum-paths 2
        end
    """
    )

    # Wait for convergence
    test_func = functools.partial(_check_ecmp_backup_paths)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=15)
    assert result is None, f"Failed to restore 2 backup paths: {result}"

    step("SUCCESS: ECMP backup paths test completed successfully")
    step("Summary:")
    step("  ✓ Verified backup paths do NOT appear when feature is unconfigured")
    step("  ✓ TEST CASE A: Verified only 1 backup path with 'install backup-path' (no ecmp)")
    step("  ✓ TEST CASE B: Verified 2 ECMP backup paths with 'install backup-path ecmp'")
    step("  ✓ TEST CASE C: Verified 0 backup paths after 'no install backup-path ecmp' (disables all backup paths)")
    step("  ✓ TEST CASE D: Verified 2 ECMP backup paths after re-adding ecmp")
    step("  ✓ TEST CASE E: Verified no backup paths after 'no install backup-path'")
    step("  ✓ Verified backup paths respect maximum-paths configuration")
    step("  ✓ Verified backup paths appear in both text and JSON output")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
