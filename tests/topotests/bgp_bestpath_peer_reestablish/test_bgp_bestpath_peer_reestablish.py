#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_bestpath_peer_reestablish.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Nvidia
# Ashwini Reddy
#

"""
Test BGP bestpath selection after peer re-establishes.

When a BGP peer goes down and comes back up, paths from that peer should
be properly re-evaluated in bestpath selection. This test verifies that
a path with higher Local Preference is correctly selected as best after
the peer re-establishes, even if a lower LP path was temporarily best.

Topology:
    +------+      +------+      +------+
    |  r1  |------|  r2  |------|  r3  |
    | LP850|      | core |      | LP650|
    +------+      +------+      +------+

r1 advertises 10.0.0.0/24 with LP 850 (set by r2 on import)
r3 advertises 10.0.0.0/24 with LP 650 (set by r2 on import)
r2 has static blackhole route (AD 254) as last-resort backup
r2 route priority: BGP LP 850 > BGP LP 650 > Static blackhole

Test Scenarios:
A. Basic BGP bestpath re-evaluation:
   1. Verify r2 selects r1's path (LP 850) as best initially
   2. Shutdown r1's BGP session on r2
   3. Verify r2 falls back to r3's path (LP 650)
   4. Re-enable r1's BGP session on r2
   5. Verify r2 correctly re-selects r1's path (LP 850) - PRIMARY BUG TEST

B. BGP + Static blackhole interaction:
   6. Shutdown both r1 and r3 BGP sessions
   7. Verify r2 falls back to static blackhole (last resort)
   8. Re-enable r1's BGP session
   9. Verify BGP route replaces static blackhole - SECONDARY BUG TEST
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

TEST_PREFIX = "10.0.0.0/24"


def build_topo(tgen):
    """Build function for topology:
    
    r1 (AS 65001) ------ r2 (AS 65000) ------ r3 (AS 65002)
    """
    # Create routers
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # r1-r2 link
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r2-r3 link
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    """Set up the pytest environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    logger.info("Setting up BGP routers")
    
    router_list = tgen.routers()

    # Configure r1 (advertises prefix with LP that will be set to 850 by r2)
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
         ip address 192.168.1.1/24
        !
        router bgp 65001
         bgp router-id 1.1.1.1
         no bgp ebgp-requires-policy
         neighbor 192.168.1.2 remote-as 65000
         address-family ipv4 unicast
          network 10.0.0.0/24
         exit-address-family
        !
        """
    )

    # Configure r2 (core router with route-maps setting different LPs)
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd(
        """
        configure terminal
        interface r2-eth0
         ip address 192.168.1.2/24
        !
        interface r2-eth1
         ip address 192.168.2.1/24
        !
        route-map SET_LP_850 permit 10
         set local-preference 850
        !
        route-map SET_LP_650 permit 10
         set local-preference 650
        !
        router bgp 65000
         bgp router-id 2.2.2.2
         no bgp ebgp-requires-policy
         neighbor 192.168.1.1 remote-as 65001
         neighbor 192.168.2.2 remote-as 65002
         address-family ipv4 unicast
          neighbor 192.168.1.1 route-map SET_LP_850 in
          neighbor 192.168.2.2 route-map SET_LP_650 in
         exit-address-family
        !
        ip route 10.0.0.0/24 blackhole 254
        !
        """
    )

    # Configure r3 (advertises prefix with LP that will be set to 650 by r2)
    r3 = tgen.gears["r3"]
    r3.vtysh_cmd(
        """
        configure terminal
        interface r3-eth0
         ip address 192.168.2.2/24
        !
        router bgp 65002
         bgp router-id 3.3.3.3
         no bgp ebgp-requires-policy
         neighbor 192.168.2.1 remote-as 65000
         address-family ipv4 unicast
          network 10.0.0.0/24
         exit-address-family
        !
        """
    )

    # Start routers
    for rname, router in router_list.items():
        router.start()


def teardown_module(mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """Test that BGP sessions come up and routes are exchanged"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test BGP convergence")
    
    r2 = tgen.gears["r2"]

    def _bgp_peers_established(router):
        """Check both peers are established"""
        output = router.vtysh_cmd("show bgp neighbor json")
        try:
            neighbors = json.loads(output)
        except:
            return "Failed to parse BGP neighbor output"
        
        for peer in ["192.168.1.1", "192.168.2.2"]:
            if peer not in neighbors:
                return "Peer {} not found".format(peer)
            if neighbors[peer].get("bgpState") != "Established":
                return "Peer {} not established: {}".format(
                    peer, neighbors[peer].get("bgpState", "unknown")
                )
        return None

    test_func = functools.partial(_bgp_peers_established, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BGP sessions failed to establish: {}".format(result)


def test_bgp_initial_bestpath():
    """Test initial bestpath selection - r1 (LP 850) should be best"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test initial bestpath selection")
    
    r2 = tgen.gears["r2"]

    def _bgp_check_bestpath(router, expected_lp, expected_nh):
        """Check that the best path has expected local-pref and next-hop"""
        output = router.vtysh_cmd("show bgp ipv4 unicast {} json".format(TEST_PREFIX))
        try:
            routes = json.loads(output)
        except:
            return "Failed to parse BGP route output"
        
        if "paths" not in routes:
            return "No paths found for {}".format(TEST_PREFIX)

        best_path_found = False
        for path in routes["paths"]:
            if path.get("bestpath", {}).get("overall", False):
                best_path_found = True
                actual_lp = path.get("locPrf", 0)
                nexthops = path.get("nexthops", [])
                if not nexthops:
                    return "No nexthops in bestpath"
                actual_nh = nexthops[0].get("ip", "")
                
                if actual_lp != expected_lp:
                    return "Expected LP {} but got {}".format(expected_lp, actual_lp)
                if actual_nh != expected_nh:
                    return "Expected NH {} but got {}".format(expected_nh, actual_nh)
                return None
        
        if not best_path_found:
            return "No bestpath found for {}".format(TEST_PREFIX)
        
        return "Unknown error checking bestpath"

    # r1's path with LP 850 should be best
    test_func = functools.partial(_bgp_check_bestpath, r2, 850, "192.168.1.1")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Initial bestpath check failed: {}".format(result)
    
    logger.info("✓ Initial bestpath correctly selected r1 (LP 850)")


def test_bgp_peer_shutdown():
    """Test that when r1 goes down, r2 falls back to r3's path"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test BGP peer shutdown and fallback")
    
    r2 = tgen.gears["r2"]

    # Shutdown r1's session on r2
    logger.info("Shutting down r1's BGP session")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65000
         neighbor 192.168.1.1 shutdown
        """
    )

    def _bgp_check_bestpath(router, expected_lp, expected_nh):
        """Check bestpath"""
        output = router.vtysh_cmd("show bgp ipv4 unicast {} json".format(TEST_PREFIX))
        try:
            routes = json.loads(output)
        except:
            return "Failed to parse output"
        
        if "paths" not in routes:
            return "No paths found"

        for path in routes["paths"]:
            if path.get("bestpath", {}).get("overall", False):
                actual_lp = path.get("locPrf", 0)
                nexthops = path.get("nexthops", [])
                if not nexthops:
                    return "No nexthops"
                actual_nh = nexthops[0].get("ip", "")
                
                if actual_lp != expected_lp:
                    return "Expected LP {} got {}".format(expected_lp, actual_lp)
                if actual_nh != expected_nh:
                    return "Expected NH {} got {}".format(expected_nh, actual_nh)
                return None
        
        return "No bestpath found"

    # r3's path with LP 650 should now be best
    test_func = functools.partial(_bgp_check_bestpath, r2, 650, "192.168.2.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Fallback bestpath check failed: {}".format(result)
    
    logger.info("✓ Correctly fell back to r3 (LP 650)")


def test_bgp_peer_reestablish():
    """
    CRITICAL TEST: When r1 comes back up, r2 should re-select r1's path (LP 850).
    This is where the bug would manifest - without the fix, r3's path (LP 650)
    would incorrectly remain as best.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test BGP peer re-establishment and bestpath re-evaluation")
    
    r2 = tgen.gears["r2"]

    # Re-enable r1's session
    logger.info("Re-enabling r1's BGP session")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65000
         no neighbor 192.168.1.1 shutdown
        """
    )

    def _bgp_check_bestpath(router, expected_lp, expected_nh):
        """Check bestpath"""
        output = router.vtysh_cmd("show bgp ipv4 unicast {} json".format(TEST_PREFIX))
        try:
            routes = json.loads(output)
        except:
            return "Failed to parse output"
        
        if "paths" not in routes:
            return "No paths found"

        for path in routes["paths"]:
            if path.get("bestpath", {}).get("overall", False):
                actual_lp = path.get("locPrf", 0)
                nexthops = path.get("nexthops", [])
                if not nexthops:
                    return "No nexthops"
                actual_nh = nexthops[0].get("ip", "")
                
                if actual_lp != expected_lp:
                    return "Expected LP {} got {}".format(expected_lp, actual_lp)
                if actual_nh != expected_nh:
                    return "Expected NH {} got {}".format(expected_nh, actual_nh)
                return None
        
        return "No bestpath found"

    # CRITICAL: r1's path with LP 850 should be best again
    # Without the fix, r3's path (LP 650) would incorrectly remain best
    test_func = functools.partial(_bgp_check_bestpath, r2, 850, "192.168.1.1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "BESTPATH NOT RE-EVALUATED AFTER PEER RE-ESTABLISH! "
        "This is the bug - r1's path (LP 850) should be selected but got: {}".format(result)
    )
    
    logger.info("✓ PASS: Bestpath correctly re-evaluated after peer re-established")
    logger.info("✓ r1's path (LP 850) properly selected over r3's path (LP 650)")


def test_bgp_all_peers_down_blackhole():
    """
    Test that when both BGP peers are down, static blackhole becomes active.
    This verifies the backup scenario where BGP paths are unavailable.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test: All BGP peers down, fallback to static blackhole")
    
    r2 = tgen.gears["r2"]

    # Both peers should still be down from previous test, but let's ensure it
    logger.info("Ensuring both r1 and r3 BGP sessions are shutdown")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65000
         neighbor 192.168.1.1 shutdown
         neighbor 192.168.2.2 shutdown
        """
    )

    def _check_route_is_blackhole(router):
        """Verify static blackhole is active"""
        output = router.vtysh_cmd("show ip route {} json".format(TEST_PREFIX))
        try:
            routes = json.loads(output)
        except:
            return "Failed to parse route output"
        
        if TEST_PREFIX not in routes:
            return "Route disappeared completely"
        
        route_info = routes[TEST_PREFIX]
        if not isinstance(route_info, list) or len(route_info) == 0:
            return "No route entries"
        
        best_route = route_info[0]
        protocol = best_route.get("protocol", "")
        
        if protocol != "static":
            return "Expected static route, got {}".format(protocol)
        
        # Verify it's a blackhole
        nexthops = best_route.get("nexthops", [])
        if not nexthops:
            return "No nexthops"
        
        nh = nexthops[0]
        if not nh.get("directlyConnected") or nh.get("interfaceName") != "blackhole":
            return "Not a blackhole nexthop"
        
        return None

    test_func = functools.partial(_check_route_is_blackhole, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Fallback to blackhole failed: {}".format(result)
    
    logger.info("✓ Correctly fell back to static blackhole (last resort)")


def test_bgp_replaces_blackhole():
    """
    CRITICAL TEST: When r1 comes back up, BGP route (LP 850) must replace
    the static blackhole route in the RIB.
    
    This tests the BGP→Zebra→RIB interaction to ensure that when bestpath
    is re-evaluated and a valid BGP path is selected, it properly gets
    installed in zebra's RIB, replacing the lower-priority static route.
    
    Without the fix, the static blackhole might incorrectly remain active
    because the BGP path was not properly re-evaluated and pushed to zebra.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("CRITICAL TEST: Re-enable r1, BGP must replace static blackhole")
    
    r2 = tgen.gears["r2"]

    # Re-enable r1
    logger.info("Re-enabling r1 BGP session")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65000
         no neighbor 192.168.1.1 shutdown
        """
    )

    def _check_route_back_to_bgp(router):
        """Verify BGP route replaced static blackhole in RIB"""
        output = router.vtysh_cmd("show ip route {} json".format(TEST_PREFIX))
        try:
            routes = json.loads(output)
        except:
            return "Failed to parse"
        
        if TEST_PREFIX not in routes:
            return "Route disappeared"
        
        route_info = routes[TEST_PREFIX]
        if not isinstance(route_info, list) or len(route_info) == 0:
            return "No route entries"
        
        best_route = route_info[0]
        protocol = best_route.get("protocol", "")
        
        if protocol != "bgp":
            return "BUG: Expected BGP, still using {} (blackhole not replaced!)".format(protocol)
        
        # Make sure it's not a blackhole nexthop
        nexthops = best_route.get("nexthops", [])
        if nexthops and nexthops[0].get("interfaceName") == "blackhole":
            return "BUG: Protocol shows BGP but nexthop is blackhole"
        
        return None

    test_func = functools.partial(_check_route_back_to_bgp, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "BUG: BGP route did not replace static blackhole after peer re-establish! "
        "This indicates BGP path not re-evaluated or not pushed to zebra. "
        "Result: {}".format(result)
    )
    
    logger.info("✓ PASS: BGP route (LP 850) properly replaced static blackhole in RIB")
    logger.info("✓ BGP→Zebra→RIB interaction working correctly")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
