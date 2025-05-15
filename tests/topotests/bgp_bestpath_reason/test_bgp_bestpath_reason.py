#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donald Sharp, Nvidia INC.
#

"""
Test BGP bestpath selection reasoning.

|----------------------     R3          -------- 192.168.199.0/24
|    192.16.3.0/24       RID 1.1.1.3
|                        AS 65003
|                        MED 150
|
|
|    192.16.2.0/24
R1 --------------------    R2          -------- 192.168.199.0/24
AS 65001                 RID 1.1.1.2
|                        AS 65024
|                        MED 200
|
|
|----------------------     R4          -------- 192.168.199.0/24
    192.16.4.0/24        RID 1.1.1.4
                         AS 65024
                         MED 100
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    # Create routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    # R1 connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    # Add switches for the 192.168.199.0/24 networks
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r4"])


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


def _converge_bgp(router, peer_addrs, count=60, wait=1):
    """
    Verify that BGP sessions are established for a given router with specified peers.

    Parameters:
    -----------
    router : TopoRouter
        The router object to check BGP convergence for
    peer_addrs : list
        List of peer IP addresses that should be in Established state
    count : int, optional
        Maximum number of attempts to check
    wait : int, optional
        Time to wait between attempts in seconds

    Returns:
    --------
    bool
        True if all peer sessions are established, False otherwise
    """
    step(f"Checking BGP convergence for {router.name} with peers: {peer_addrs}")

    def _check_bgp_peers():
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast summary json"))

        if "peers" not in output:
            return "No peers section found in BGP summary output"

        peers = output["peers"]

        # Check if all expected peers are established
        for peer_addr in peer_addrs:
            if peer_addr not in peers:
                return f"Peer {peer_addr} not found"

            if peers[peer_addr]["state"] != "Established":
                return f"Peer {peer_addr} not established, state: {peers[peer_addr]['state']}"

        return None

    test_func = functools.partial(_check_bgp_peers)
    success, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)

    if success:
        logger.info(f"BGP convergence successful for {router.name}")
        return True
    else:
        logger.error(f"BGP convergence failed for {router.name}: {result}")
        return False


def test_bgp_convergence_of_r2():
    """
    Test overall BGP convergence across all routers.

    This test verifies that all BGP sessions are established correctly in the topology:
    - R1 connects to R2, R3, and R4
    - Each router has properly configured BGP sessions with its neighbors
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    assert _converge_bgp(router, ["192.16.2.2"]), f"BGP did not converge on r1"

    step("r1 to r2 is established")


def test_bgp_convergence_of_r3():
    """
    Test BGP convergence with R3.

    This test first activates the BGP peer on R3 by configuring
    'neighbor 192.16.3.1 activate' and then verifies the BGP session establishes.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Get router objects
    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    # First, activate the BGP peer on R3
    step("Activating BGP peer on R3")
    r3.vtysh_cmd(
        """
        configure terminal
        router bgp 65003
        address-family ipv4 unicast
        neighbor 192.16.3.1 activate
        end
    """
    )

    # Now verify the BGP session comes up
    step("Checking if BGP session between R1 and R3 comes up")
    assert _converge_bgp(r1, ["192.16.3.3"]), "BGP session with R3 did not establish"

    step("r1 to r3 is established")


def test_bgp_convergence_of_r4():
    """
    Test BGP convergence with R4.

    This test first activates the BGP peer on R4 by configuring
    'neighbor 192.16.4.1 activate' and then verifies the BGP session establishes.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Get router objects
    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    # First, activate the BGP peer on R4
    step("Activating BGP peer on R4")
    r4.vtysh_cmd(
        """
        configure terminal
        router bgp 65024
        address-family ipv4 unicast
        neighbor 192.16.4.1 activate
        end
    """
    )

    # Now verify the BGP session comes up
    step("Checking if BGP session between R1 and R4 comes up")
    assert _converge_bgp(r1, ["192.16.4.4"]), "BGP session with R4 did not establish"

    step("r1 to r4 is established")


def test_bgp_paths():
    """
    Verify that R1 receives all three paths for the 192.168.199.0/24 prefix.

    This test uses run_and_expect to wait until all three paths for the prefix
    are received by R1 from R2, R3, and R4.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Waiting for R1 to receive all three paths for 192.168.199.0/24")

    def _check_paths_count():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 192.168.199.0/24 json"))

        if "pathCount" not in output:
            return "pathCount not found in output"

        if output["pathCount"] != 3:
            return f"Expected 3 paths, got {output['pathCount']}"

        return None

    test_func = functools.partial(_check_paths_count)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assert result is None, "Did not receive all three paths for 192.168.199.0/24"

    step("Successfully received all three paths for 192.168.199.0/24")

    # Additional verification of path details
    output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 192.168.199.0/24 json"))

    # Verify all three nexthops are present
    nexthops = set()
    for path in output["paths"]:
        nexthop = path.get("nexthops")[0].get("ip")
        nexthops.add(nexthop)

    expected_nexthops = {"192.16.2.2", "192.16.3.3", "192.16.4.4"}
    assert (
        nexthops == expected_nexthops
    ), f"Expected nexthops {expected_nexthops}, got {nexthops}"

    step("Verified paths from all three peers (R2, R3, and R4)")


def test_bgp_bestpath_reason():
    """
    Verify BGP bestpath selection reasons in the JSON output.

    After all BGP sessions are established, this test checks that:
    1. R1 receives paths to 192.168.199.0/24 from all three peers
    2. The path with the lowest MED (via R4) is selected as the best path
    3. The JSON output includes the bestpath reason indicating MED was the deciding factor
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Checking bestpath selection for 192.168.199.0/24")

    # Get route information for the prefix
    output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 192.168.199.0/24 json"))

    assert "prefix" in output, "No prefix information in JSON output"
    assert output["prefix"] == "192.168.199.0/24", "Incorrect prefix in output"
    assert "pathCount" in output, "pathCount missing in JSON output"
    assert output["pathCount"] == 3, f"Expected 3 paths, got {output['pathCount']}"
    assert "paths" in output, "No paths received for prefix 192.168.199.0/24"
    assert len(output["paths"]) == 3, f"Expected 3 paths, got {len(output['paths'])}"

    # Check MED values from each peer
    expected_meds = {
        "192.16.2.2": 200,  # R2
        "192.16.3.3": 150,  # R3
        "192.16.4.4": 100,  # R4
    }

    step("Verifying MED values from each peer")
    for path in output["paths"]:
        nexthop = path.get("nexthops")[0].get("ip")
        med = path.get("metric", None)

        assert nexthop in expected_meds, f"Unexpected nexthop: {nexthop}"
        assert (
            med == expected_meds[nexthop]
        ), f"Incorrect MED for {nexthop}: expected {expected_meds[nexthop]}, got {med}"

    # Extract bestpath information
    paths = {}
    best_path = None

    for path in output["paths"]:
        nexthop = path.get("nexthops")[0].get("ip")
        paths[nexthop] = path
        if path.get("bestpath") and path.get("bestpath").get("overall", False):
            best_path = nexthop

    # Verify R4 is selected as best path (lowest MED)
    assert (
        best_path == "192.16.4.4"
    ), "Best path should be via R4 (192.16.4.4) with lowest MED"

    step("Verified best path is via R4 (192.16.4.4)")

    # Check for bestpath selection reason
    best_path_obj = paths[best_path].get("bestpath", {})
    selection_reason = best_path_obj.get("selectionReason")

    assert (
        selection_reason is not None
    ), "Selection reason is missing in bestpath object"

    # Verify the selection reason includes "MED"
    assert (
        "MED" in selection_reason
    ), f"Expected 'MED' in selection reason, got: '{selection_reason}'"

    step(f"Verified bestpath selection reason contains 'MED': '{selection_reason}'")


def test_bgp_med_based_selection():
    """
    Verify that MED is properly considered in bestpath selection.

    This test ensures that the path with the lowest MED (from R4) is selected
    as the best path, and that MED is mentioned in the selection reason.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verifying MED influences bestpath selection")

    def _check_best_path_is_r4():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 192.168.199.0/24 json"))

        # First check we have all paths
        if "paths" not in output or len(output["paths"]) != 3:
            return "Don't have all three paths yet"

        # Look for best path
        best_path_nexthop = None
        best_path_reason = None

        for path in output["paths"]:
            if path.get("bestpath") and path.get("bestpath").get("overall", False):
                best_path_nexthop = path.get("nexthops")[0].get("ip")
                best_path_reason = path.get("bestpath", {}).get("selectionReason")
                break

        if best_path_nexthop is None:
            return "No best path found"

        if best_path_nexthop != "192.16.4.4":
            return f"Best path is via {best_path_nexthop}, expected 192.16.4.4"

        # Check for MED in selection reason
        if best_path_reason is None:
            return "No selection reason found"

        if "MED" not in best_path_reason:
            return f"Expected 'MED' in selection reason, got: '{best_path_reason}'"

        return None

    test_func = functools.partial(_check_best_path_is_r4)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assert (
        result is None
    ), "Path via R4 (lowest MED of 100) was not selected as best path with proper reason"

    step("Verified path via R4 (lowest MED of 100) is selected as best path")

    # Additional check for MED values to confirm they're correctly set
    output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 192.168.199.0/24 json"))

    med_values = {}
    for path in output["paths"]:
        nexthop = path.get("nexthops")[0].get("ip")
        med = path.get("metric", None)
        med_values[nexthop] = med

    step(
        f"MED values: R2={med_values.get('192.16.2.2')}, R3={med_values.get('192.16.3.3')}, R4={med_values.get('192.16.4.4')}"
    )

    # Final validation that R4 has the lowest MED
    assert med_values.get("192.16.4.4") < med_values.get(
        "192.16.2.2"
    ), "R4's MED should be lower than R2's"
    assert med_values.get("192.16.4.4") < med_values.get(
        "192.16.3.3"
    ), "R4's MED should be lower than R3's"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
