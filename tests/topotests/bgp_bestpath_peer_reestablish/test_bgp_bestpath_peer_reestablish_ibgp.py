#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_bestpath_peer_reestablish_ibgp.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Nvidia
# Ashwini Reddy
#

"""
Test BGP bestpath selection after peer re-establishes - iBGP + eBGP scenario.

This test reproduces the production bug from GitHub issue #20447 where
iBGP + eBGP path combinations fail to properly re-evaluate bestpath
after a peer re-establishes.

Topology (matches production scenario):
                  ┌─────────┐
    ┌─────────────│  isp1   │─────────────┐
    │    eBGP     │ AS 1111 │    eBGP     │
    │   LP 850    └─────────┘   LP 750    │
    │                                      │
┌───▼────┐                           ┌────▼───┐
│ core01 │◄────────iBGP──────────────►│ core02 │
│ AS 100 │                            │ AS 100 │
└───┬────┘                           └────┬───┘
    │    eBGP                   eBGP      │
    │   LP 650                  LP 650    │
    │   ┌─────────┐                       │
    └───│  isp2   │───────────────────────┘
        │ AS 2222 │
        └─────────┘

Test:
- isp1 advertises 10.0.0.0/24 to core01 (LP 850) and core02 (LP 750)
- isp2 advertises 10.0.0.0/24 to both cores (LP 650)
- core01 and core02 are iBGP peers
- After isp1→core01 link flaps, core01 should re-select the eBGP path (LP 850)
  NOT the iBGP path from core02 (LP 750)
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
    """Build topology matching production scenario"""
    
    # Core routers (iBGP peers, AS 100)
    tgen.add_router("core01")
    tgen.add_router("core02")
    
    # ISP routers
    tgen.add_router("isp1")  # AS 1111
    tgen.add_router("isp2")  # AS 2222
    
    # isp1 connects to both cores
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["isp1"])
    switch.add_link(tgen.gears["core01"])
    
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["isp1"])
    switch.add_link(tgen.gears["core02"])
    
    # isp2 connects to both cores
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["isp2"])
    switch.add_link(tgen.gears["core01"])
    
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["isp2"])
    switch.add_link(tgen.gears["core02"])
    
    # iBGP link between cores
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["core01"])
    switch.add_link(tgen.gears["core02"])


def setup_module(mod):
    """Set up the pytest environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    logger.info("Setting up iBGP + eBGP topology")
    
    router_list = tgen.routers()

    # Configure isp1 (AS 1111)
    isp1 = tgen.gears["isp1"]
    isp1.vtysh_cmd(
        """
        configure terminal
        interface isp1-eth0
         ip address 10.1.1.1/30
        !
        interface isp1-eth1
         ip address 10.1.2.1/30
        !
        router bgp 1111
         bgp router-id 1.1.1.1
         no bgp ebgp-requires-policy
         neighbor 10.1.1.2 remote-as 100
         neighbor 10.1.2.2 remote-as 100
         address-family ipv4 unicast
          network 10.0.0.0/24
         exit-address-family
        !
        """
    )

    # Configure isp2 (AS 2222)
    isp2 = tgen.gears["isp2"]
    isp2.vtysh_cmd(
        """
        configure terminal
        interface isp2-eth0
         ip address 10.2.1.1/30
        !
        interface isp2-eth1
         ip address 10.2.2.1/30
        !
        router bgp 2222
         bgp router-id 2.2.2.2
         no bgp ebgp-requires-policy
         neighbor 10.2.1.2 remote-as 100
         neighbor 10.2.2.2 remote-as 100
         address-family ipv4 unicast
          network 10.0.0.0/24
         exit-address-family
        !
        """
    )

    # Configure core01 (AS 100, route-reflector client)
    core01 = tgen.gears["core01"]
    core01.vtysh_cmd(
        """
        configure terminal
        interface core01-eth0
         ip address 10.1.1.2/30
        !
        interface core01-eth1
         ip address 10.2.1.2/30
        !
        interface core01-eth2
         ip address 192.168.0.1/30
        !
        route-map SET_LP_850 permit 10
         set local-preference 850
        !
        route-map SET_LP_650 permit 10
         set local-preference 650
        !
        router bgp 100
         bgp router-id 100.0.0.1
         no bgp ebgp-requires-policy
         neighbor 10.1.1.1 remote-as 1111
         neighbor 10.2.1.1 remote-as 2222
         neighbor 192.168.0.2 remote-as 100
         neighbor 192.168.0.2 update-source 192.168.0.1
         address-family ipv4 unicast
          neighbor 10.1.1.1 route-map SET_LP_850 in
          neighbor 10.2.1.1 route-map SET_LP_650 in
         exit-address-family
        !
        """
    )

    # Configure core02 (AS 100, route-reflector client)
    core02 = tgen.gears["core02"]
    core02.vtysh_cmd(
        """
        configure terminal
        interface core02-eth0
         ip address 10.1.2.2/30
        !
        interface core02-eth1
         ip address 10.2.2.2/30
        !
        interface core02-eth2
         ip address 192.168.0.2/30
        !
        route-map SET_LP_750 permit 10
         set local-preference 750
        !
        route-map SET_LP_650 permit 10
         set local-preference 650
        !
        router bgp 100
         bgp router-id 100.0.0.2
         no bgp ebgp-requires-policy
         neighbor 10.1.2.1 remote-as 1111
         neighbor 10.2.2.1 remote-as 2222
         neighbor 192.168.0.1 remote-as 100
         neighbor 192.168.0.1 update-source 192.168.0.2
         address-family ipv4 unicast
          neighbor 10.1.2.1 route-map SET_LP_750 in
          neighbor 10.2.2.1 route-map SET_LP_650 in
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
    """Test that all BGP sessions come up"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test BGP convergence - eBGP and iBGP sessions")
    
    core01 = tgen.gears["core01"]

    def _bgp_peers_established(router):
        """Check all peers are established"""
        output = router.vtysh_cmd("show bgp neighbor json")
        try:
            neighbors = json.loads(output)
        except:
            return "Failed to parse BGP neighbor output"
        
        expected_peers = ["10.1.1.1", "10.2.1.1", "192.168.0.2"]
        for peer in expected_peers:
            if peer not in neighbors:
                return "Peer {} not found".format(peer)
            if neighbors[peer].get("bgpState") != "Established":
                return "Peer {} not established: {}".format(
                    peer, neighbors[peer].get("bgpState", "unknown")
                )
        return None

    test_func = functools.partial(_bgp_peers_established, core01)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BGP sessions failed to establish: {}".format(result)


def test_initial_bestpath_ebgp_lp850():
    """Test that core01 initially selects eBGP path from isp1 (LP 850)"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test initial bestpath - should be eBGP LP 850")
    
    core01 = tgen.gears["core01"]

    def _check_bestpath(router, expected_lp, expected_type):
        """Check bestpath has expected LP and path type"""
        output = router.vtysh_cmd("show bgp ipv4 unicast {} json".format(TEST_PREFIX))
        try:
            routes = json.loads(output)
        except:
            return "Failed to parse route output"
        
        if "paths" not in routes:
            return "No paths found"

        for path in routes["paths"]:
            if path.get("bestpath", {}).get("overall", False):
                actual_lp = path.get("locPrf", 0)
                path_type = "internal" if path.get("peer", {}).get("type") == "internal" else "external"
                
                if actual_lp != expected_lp:
                    return "Expected LP {} got {}".format(expected_lp, actual_lp)
                if path_type != expected_type:
                    return "Expected {} path got {}".format(expected_type, path_type)
                return None
        
        return "No bestpath found"

    # Should select eBGP path with LP 850
    test_func = functools.partial(_check_bestpath, core01, 850, "external")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Initial bestpath incorrect: {}".format(result)
    
    logger.info("✓ Initial bestpath correctly selected eBGP LP 850")


def test_peer_shutdown_falls_back():
    """Test that when isp1→core01 goes down, core01 falls back to another path"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test peer shutdown and fallback")
    
    core01 = tgen.gears["core01"]

    # Shutdown isp1 session on core01
    logger.info("Shutting down isp1→core01 BGP session")
    core01.vtysh_cmd(
        """
        configure terminal
        router bgp 100
         neighbor 10.1.1.1 shutdown
        """
    )

    def _check_bestpath_not_850(router):
        """Verify LP 850 path is NOT selected"""
        output = router.vtysh_cmd("show bgp ipv4 unicast {} json".format(TEST_PREFIX))
        try:
            routes = json.loads(output)
        except:
            return "Failed to parse"
        
        if "paths" not in routes:
            return "No paths"

        for path in routes["paths"]:
            if path.get("bestpath", {}).get("overall", False):
                actual_lp = path.get("locPrf", 0)
                if actual_lp == 850:
                    return "Still selecting LP 850 after shutdown"
                if actual_lp in [750, 650]:  # Either iBGP or other eBGP
                    return None
        
        return "Unexpected bestpath"

    test_func = functools.partial(_check_bestpath_not_850, core01)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Fallback failed: {}".format(result)
    
    logger.info("✓ Correctly fell back after peer shutdown")


def test_peer_reestablish_selects_ebgp_lp850():
    """
    CRITICAL TEST: When isp1→core01 re-establishes, core01 should select
    the eBGP path (LP 850), NOT the iBGP path from core02 (LP 750).
    
    This reproduces GitHub issue #20447 where iBGP path incorrectly remains
    selected after eBGP peer re-establishes.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("CRITICAL TEST: Peer re-establish with iBGP + eBGP")
    
    core01 = tgen.gears["core01"]

    # Re-enable isp1 session
    logger.info("Re-enabling isp1→core01 BGP session")
    core01.vtysh_cmd(
        """
        configure terminal
        router bgp 100
         no neighbor 10.1.1.1 shutdown
        """
    )

    def _check_bestpath_ebgp_850(router):
        """Verify eBGP LP 850 path is selected (NOT iBGP LP 750)"""
        output = router.vtysh_cmd("show bgp ipv4 unicast {} json".format(TEST_PREFIX))
        try:
            routes = json.loads(output)
        except:
            return "Failed to parse"
        
        if "paths" not in routes:
            return "No paths"

        for path in routes["paths"]:
            if path.get("bestpath", {}).get("overall", False):
                actual_lp = path.get("locPrf", 0)
                path_type = "internal" if path.get("peer", {}).get("type") == "internal" else "external"
                
                if actual_lp != 850:
                    return "Expected LP 850, got LP {} (BUG: iBGP path selected?)".format(actual_lp)
                if path_type != "external":
                    return "Expected external path, got {} (BUG: iBGP selected!)".format(path_type)
                return None
        
        return "No bestpath found"

    # CRITICAL: Must select eBGP LP 850, not iBGP LP 750
    test_func = functools.partial(_check_bestpath_ebgp_850, core01)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "BUG REPRODUCED (GitHub #20447): After peer re-establish, "
        "eBGP path (LP 850) not selected. Result: {}".format(result)
    )
    
    logger.info("✓ PASS: eBGP path (LP 850) correctly selected after re-establish")
    logger.info("✓ Did NOT incorrectly select iBGP path (LP 750)")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
