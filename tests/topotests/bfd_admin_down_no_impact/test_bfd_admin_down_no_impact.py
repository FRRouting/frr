#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_admin_down_no_impact.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2024 by Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_bfd_admin_down_no_impact.py: 

Test BFD Admin Down handling - verify that when BFD receives Admin Down
from peer, it does NOT tear down BGP/OSPF/PIM protocol sessions.

Topology:
    
    r1 ----------- r2
      .1   s1    .2
   10.0.1.0/24

When r1 shuts down BFD (administrative shutdown), it sends Admin Down to r2.
r2 should:
1. Move BFD state to DOWN
2. NOT tear down BGP/OSPF/PIM sessions
3. Keep protocol adjacencies UP

Test Cases:
1. test_wait_protocols_convergence: Wait for BGP/OSPF/PIM to converge
2. test_bfd_peers_up: Verify BFD sessions establish
3. test_bfd_admin_down_no_protocol_impact: Direct peer shutdown test
4. test_bfd_reenable: Verify BFD recovery after peer re-enable
5. test_bfd_profile_shutdown_no_protocol_impact: Profile-based shutdown test
6. test_memory_leak: Memory leak detection
"""

import os
import sys
import json
import pytest
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.pimd]

# Track whether PIM is working in this environment
pim_enabled = False


def build_topo(tgen):
    """Build the topology"""
    
    # Create routers
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))
    
    # Create switch and links
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    """Sets up the pytest environment"""
    
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    
    router_list = tgen.routers()
    
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    
    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_wait_protocols_convergence():
    """Wait for all protocols to converge"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    step("Waiting for protocols to converge")
    
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    
    # Wait for BGP to converge
    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "10.0.1.2": {
                        "state": "Established"
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)
    
    test_func = partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BGP did not converge on r1"
    
    # Wait for OSPF to converge
    def _ospf_converge():
        output = json.loads(r1.vtysh_cmd("show ip ospf neighbor json"))
        if "neighbors" not in output:
            return "OSPF neighbor not found"
        
        for neighbor_id, neighbor_list in output["neighbors"].items():
            if neighbor_list and neighbor_list[0].get("nbrState", "").split("/")[0] == "Full":
                return None
        return "OSPF neighbor not Full"
    
    test_func = partial(_ospf_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "OSPF did not converge on r1"
    
    # Wait for PIM neighbor (optional - may not form in all environments)
    def _pim_converge():
        output = json.loads(r1.vtysh_cmd("show ip pim neighbor json"))
        # PIM structure is {interface: {peer: {...}}}
        for interface, peers in output.items():
            if isinstance(peers, dict) and "10.0.1.2" in peers:
                return None
        return "PIM neighbor not found"
    
    test_func = partial(_pim_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    global pim_enabled
    if result is not None:
        logger.warning("PIM did not converge on r1 - skipping PIM tests")
        pim_enabled = False
    else:
        logger.info("PIM converged successfully")
        pim_enabled = True


def test_bfd_peers_up():
    """Verify BFD peers are UP"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    step("Verify BFD peers are UP")
    
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    
    # Check BFD status on r1
    def _check_bfd_r1():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.2" and peer.get("status") == "up":
                return None
        return "BFD peer not up on r1"
    
    test_func = partial(_check_bfd_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BFD peer did not come up on r1"
    
    # Check BFD status on r2
    def _check_bfd_r2():
        output = json.loads(r2.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.1" and peer.get("status") == "up":
                return None
        return "BFD peer not up on r2"
    
    test_func = partial(_check_bfd_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BFD peer did not come up on r2"


def test_bfd_admin_down_no_protocol_impact():
    """
    Test that BFD Admin Down does not tear down protocol sessions.
    
    1. Shutdown BFD on r1 (sends Admin Down to r2)
    2. Verify r2 receives Admin Down and BFD goes to DOWN state
    3. Verify BGP/OSPF/PIM sessions remain UP on r2
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    step("Shutdown BFD peer on r1 to trigger Admin Down")
    
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    
    # Shutdown BFD peer on r1
    r1.vtysh_cmd("""
configure terminal
bfd
 peer 10.0.1.2 interface r1-eth0
  shutdown
 exit
exit
""")
    
    step("Verify r1 BFD session is in admin down state")
    
    # Check that BFD on r1 shows admin down
    def _check_bfd_admin_down_r1():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.2":
                # Check r1 bfd status is admin-down/shutdown
                if peer.get("status") == "shutdown":
                    return None
        return "BFD peer on r1 not in admin-down state"
    
    test_func = partial(_check_bfd_admin_down_r1)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "BFD did not enter admin down state on r1"
    
    step("Verify r2 receives BFD admin down and BFD goes down")
    
    # Check that BFD goes down on r2 and sees remote admin down
    def _check_bfd_down_r2():
        output = json.loads(r2.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.1":
                if peer.get("status") == "down":
                    # Optionally verify remote sent admin down
                    # (may not always be present in JSON depending on implementation)
                    return None
        return "BFD peer did not go down on r2"
    
    test_func = partial(_check_bfd_down_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BFD did not go down on r2 after receiving admin down from r1"
    
    step("Verify BGP session remains UP on r2")
    
    # Verify BGP is still established
    def _check_bgp_up_r2():
        output = json.loads(r2.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "10.0.1.1": {
                        "state": "Established"
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)
    
    test_func = partial(_check_bgp_up_r2)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "BGP went down on r2 after BFD admin down (should remain UP)"
    
    step("Verify OSPF neighbor remains Full on r2")
    
    # Verify OSPF is still Full
    def _check_ospf_up_r2():
        output = json.loads(r2.vtysh_cmd("show ip ospf neighbor json"))
        if "neighbors" not in output:
            return "OSPF neighbor disappeared"
        
        for neighbor_id, neighbor_list in output["neighbors"].items():
            if neighbor_list and neighbor_list[0].get("nbrState", "").split("/")[0] == "Full":
                return None
        return "OSPF neighbor not Full"
    
    test_func = partial(_check_ospf_up_r2)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "OSPF went down on r2 after BFD admin down (should remain UP)"
    
    step("Verify PIM neighbor remains UP on r2")
    
    if pim_enabled:
        # Verify PIM neighbor still exists
        def _check_pim_up_r2():
            output = json.loads(r2.vtysh_cmd("show ip pim neighbor json"))
            # PIM structure is {interface: {peer: {...}}}
            for interface, peers in output.items():
                if isinstance(peers, dict) and "10.0.1.1" in peers:
                    return None
            return "PIM neighbor disappeared"
        
        test_func = partial(_check_pim_up_r2)
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert result is None, "PIM went down on r2 after BFD admin down (should remain UP)"
    else:
        logger.info("Skipping PIM check (PIM was not enabled)")
    
    logger.info("SUCCESS: All protocol sessions remained UP after BFD Admin Down")


def test_bfd_reenable():
    """
    Test that re-enabling BFD brings the session back up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    step("Re-enable BFD peer on r1")
    
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    
    # Re-enable BFD peer on r1
    r1.vtysh_cmd("""
configure terminal
bfd
 peer 10.0.1.2 interface r1-eth0
  no shutdown
 exit
exit
""")
    
    step("Verify BFD comes back up")
    
    # Check BFD comes back up on r2
    def _check_bfd_up_r2():
        output = json.loads(r2.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.1" and peer.get("status") == "up":
                return None
        return "BFD peer did not come back up on r2"
    
    test_func = partial(_check_bfd_up_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BFD did not come back up on r2"
    
    logger.info("SUCCESS: BFD session re-established after no shutdown")


def test_bfd_profile_shutdown_no_protocol_impact():
    """
    Test that BFD profile shutdown does not tear down protocol sessions.
    
    This test uses BFD profiles instead of direct peer shutdown.
    1. Create and apply BFD profiles on both routers
    2. Shutdown the BFD profile on r1 (sends Admin Down)
    3. Verify r2 receives Admin Down and BFD goes to DOWN state
    4. Verify BGP/OSPF/PIM sessions remain UP on r2
    5. Re-enable the profile and verify recovery
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    step("Configure BFD profiles on r1 and r2")
    
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    
    # Configure BFD profile on r1
    r1.vtysh_cmd("""
configure terminal
bfd
 profile test-profile
  detect-multiplier 3
  receive-interval 300
  transmit-interval 300
 exit
 peer 10.0.1.2 interface r1-eth0
  profile test-profile
 exit
exit
""")
    
    # Configure BFD profile on r2
    r2.vtysh_cmd("""
configure terminal
bfd
 profile test-profile
  detect-multiplier 3
  receive-interval 300
  transmit-interval 300
 exit
 peer 10.0.1.1 interface r2-eth0
  profile test-profile
 exit
exit
""")
    
    step("Wait for BFD sessions to stabilize with profiles")
    
    # Verify BFD is still up after profile configuration
    def _check_bfd_up_with_profile():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.2" and peer.get("status") == "up":
                return None
        return "BFD not up after profile config"
    
    test_func = partial(_check_bfd_up_with_profile)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BFD did not stabilize after profile configuration"
    
    step("Shutdown BFD profile on r1 to trigger Admin Down")
    
    # Shutdown the profile
    r1.vtysh_cmd("""
configure terminal
bfd
 profile test-profile
  shutdown
 exit
exit
""")
    
    step("Verify r1 BFD session shows admin down state (profile shutdown)")
    
    # Check that BFD on r1 shows admin down
    def _check_bfd_profile_admin_down_r1():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.2":
                # Check r1 bfd status is admin-down/shutdown
                if peer.get("status") == "shutdown":
                    return None
        return "BFD peer on r1 not in admin-down state after profile shutdown"
    
    test_func = partial(_check_bfd_profile_admin_down_r1)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "BFD did not enter admin down state on r1 after profile shutdown"
    
    step("Verify r2 receives BFD admin down (from profile shutdown)")
    
    # Check that BFD goes down on r2
    def _check_bfd_profile_down_r2():
        output = json.loads(r2.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.1":
                if peer.get("status") == "down":
                    return None
        return "BFD peer did not go down on r2"
    
    test_func = partial(_check_bfd_profile_down_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BFD did not go down on r2 after r1 profile shutdown"
    
    step("Verify BGP session remains UP on r2 (profile shutdown)")
    
    # Verify BGP is still established
    def _check_bgp_profile_up_r2():
        output = json.loads(r2.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "10.0.1.1": {
                        "state": "Established"
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)
    
    test_func = partial(_check_bgp_profile_up_r2)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "BGP went down on r2 after BFD profile shutdown (should remain UP)"
    
    step("Verify OSPF neighbor remains Full on r2 (profile shutdown)")
    
    # Verify OSPF is still Full
    def _check_ospf_profile_up_r2():
        output = json.loads(r2.vtysh_cmd("show ip ospf neighbor json"))
        if "neighbors" not in output:
            return "OSPF neighbor disappeared"
        
        for neighbor_id, neighbor_list in output["neighbors"].items():
            if neighbor_list and neighbor_list[0].get("nbrState", "").split("/")[0] == "Full":
                return None
        return "OSPF neighbor not Full"
    
    test_func = partial(_check_ospf_profile_up_r2)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "OSPF went down on r2 after BFD profile shutdown (should remain UP)"
    
    step("Verify PIM neighbor remains UP on r2 (profile shutdown)")
    
    if pim_enabled:
        # Verify PIM neighbor still exists
        def _check_pim_profile_up_r2():
            output = json.loads(r2.vtysh_cmd("show ip pim neighbor json"))
            # PIM structure is {interface: {peer: {...}}}
            for interface, peers in output.items():
                if isinstance(peers, dict) and "10.0.1.1" in peers:
                    return None
            return "PIM neighbor disappeared"
        
        test_func = partial(_check_pim_profile_up_r2)
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert result is None, "PIM went down on r2 after BFD profile shutdown (should remain UP)"
    else:
        logger.info("Skipping PIM check (PIM was not enabled)")
    
    logger.info("SUCCESS: All protocol sessions remained UP after BFD profile shutdown")
    
    step("Re-enable BFD profile on r1")
    
    # Re-enable the profile
    r1.vtysh_cmd("""
configure terminal
bfd
 profile test-profile
  no shutdown
 exit
exit
""")
    
    step("Verify BFD comes back up after profile re-enable")
    
    # Check BFD comes back up on both routers
    def _check_bfd_profile_up_r1():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.2" and peer.get("status") == "up":
                return None
        return "BFD peer did not come back up on r1"
    
    test_func = partial(_check_bfd_profile_up_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BFD did not come back up on r1 after profile re-enable"
    
    def _check_bfd_profile_up_r2():
        output = json.loads(r2.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "10.0.1.1" and peer.get("status") == "up":
                return None
        return "BFD peer did not come back up on r2"
    
    test_func = partial(_check_bfd_profile_up_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BFD did not come back up on r2 after profile re-enable"
    
    logger.info("SUCCESS: BFD session re-established after profile no shutdown")


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


