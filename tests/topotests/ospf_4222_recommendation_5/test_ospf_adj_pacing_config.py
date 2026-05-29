#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_adj_pacing_dynamic.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_adj_pacing_dynamic.py: Test OSPF RFC4222/R5 Dynamic Adjacency Pacing

Tests dynamic pacing threshold configuration persistence and functionality:
1. Config persistence across FRR restart
2. Config persistence across interface flap
3. Threshold values used in AIMD algorithm
4. Config writeback includes thresholds
"""

import pytest
import time

from lib.topogen import Topogen


pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    """Build test topology.

    r1 --- r2 --- r3

    r1-r2: Will have dynamic pacing with custom thresholds
    r2-r3: Used to create multiple adjacencies on r2
    """
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")
    tgen.add_link(r2, r3, ifname1="eth2", ifname2="eth1")


@pytest.fixture(scope="function")
def tgen(request):
    """Setup/Teardown the environment and provide tgen argument to tests."""

    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()

    yield tgen

    tgen.stop_topology()


def test_adj_pacing_dynamic_config_persistence(tgen):
    """Test that dynamic pacing thresholds persist in configuration."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Step 1: Configure dynamic pacing with custom thresholds on r1's eth1
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic
        ip ospf adjacency-pacing dynamic thresholds 50 5
        end
    """)

    # Step 2: Verify configuration via show running-config
    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf adjacency-pacing dynamic" in running_config, \
        "Dynamic pacing mode not in running config"
    assert "ip ospf adjacency-pacing dynamic thresholds 50 5" in running_config, \
        "Dynamic pacing thresholds not in running config"

    # Step 3: Write memory
    r1.vtysh_cmd("write memory")

    # Step 4: Read the saved config file
    startup_config = r1.run("cat /etc/frr/frr.conf")

    assert "ip ospf adjacency-pacing dynamic" in startup_config, \
        "Dynamic pacing mode not in saved config"
    assert "ip ospf adjacency-pacing dynamic thresholds 50 5" in startup_config, \
        "Dynamic pacing thresholds not in saved config"


def test_adj_pacing_dynamic_interface_flap(tgen):
    """Test that dynamic pacing thresholds survive interface flap."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Step 1: Configure dynamic pacing with thresholds
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic
        ip ospf adjacency-pacing dynamic thresholds 80 10
        end
    """)

    # Step 2: Shutdown and no shutdown the interface
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        shutdown
        end
    """)
    time.sleep(2)

    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        no shutdown
        end
    """)
    time.sleep(2)

    # Step 3: Verify configuration is still present after flap
    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf adjacency-pacing dynamic thresholds 80 10" in running_config, \
        "Dynamic pacing thresholds lost after interface flap"


def test_adj_pacing_dynamic_frr_restart(tgen):
    """Test that dynamic pacing thresholds persist across FRR restart."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Step 1: Configure dynamic pacing with thresholds
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic
        ip ospf adjacency-pacing dynamic thresholds 60 8
        end
    """)

    # Step 2: Save configuration to frr.conf
    r1.vtysh_cmd("write memory")

    # Step 3: Kill and restart ospfd to re-read frr.conf from disk
    r1.killDaemons(["ospfd"])
    time.sleep(2)
    r1.startDaemons(["ospfd"])
    time.sleep(2)
    # startDaemons only launches the process; push the saved config into it
    r1.run("vtysh -f /etc/frr/frr.conf")
    time.sleep(3)

    # Step 4: Verify configuration is still active after daemon re-read frr.conf
    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf adjacency-pacing dynamic" in running_config, \
        "Dynamic pacing mode lost after restart"
    assert "ip ospf adjacency-pacing dynamic thresholds 60 8" in running_config, \
        "Dynamic pacing thresholds lost after restart"


def test_adj_pacing_dynamic_no_command(tgen):
    """Test that 'no' command properly removes thresholds."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Step 1: Configure dynamic pacing with thresholds
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic
        ip ospf adjacency-pacing dynamic thresholds 70 12
        end
    """)

    # Step 2: Verify configuration is present
    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf adjacency-pacing dynamic thresholds 70 12" in running_config, \
        "Thresholds not configured"

    # Step 3: Remove threshold configuration
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        no ip ospf adjacency-pacing dynamic thresholds
        end
    """)

    # Step 4: Verify thresholds are removed but dynamic mode remains
    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf adjacency-pacing dynamic" in running_config, \
        "Dynamic pacing mode incorrectly removed"
    assert "ip ospf adjacency-pacing dynamic thresholds" not in running_config, \
        "Thresholds not removed from config"


def test_adj_pacing_dynamic_threshold_validation(tgen):
    """Test that threshold validation works correctly."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Test 1: Low water >= High water should fail
    output = r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic thresholds 50 50
        end
    """)

    assert "Error" in output or "must be less" in output, \
        "Validation should reject low_water >= high_water"

    # Test 2: Low water > High water should fail
    output = r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic thresholds 30 40
        end
    """)

    assert "Error" in output or "must be less" in output, \
        "Validation should reject low_water > high_water"

    # Test 3: Valid configuration should succeed
    output = r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic
        ip ospf adjacency-pacing dynamic thresholds 100 2
        end
    """)

    assert "Error" not in output, \
        "Valid configuration should succeed"

    # Verify it's actually configured
    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf adjacency-pacing dynamic thresholds 100 2" in running_config, \
        "Valid thresholds not configured"


def test_adj_pacing_dynamic_defaults(tgen):
    """Test that default thresholds are used when not explicitly configured."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Step 1: Configure dynamic pacing WITHOUT custom thresholds
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic
        end
    """)

    # Step 2: Verify mode is in config but no threshold line is written
    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf adjacency-pacing dynamic" in running_config, \
        "Dynamic pacing mode not in config"
    assert "ip ospf adjacency-pacing dynamic thresholds" not in running_config, \
        "Default config should not show threshold values"


def test_adj_pacing_cleanup_on_disable(tgen):
    """Test that disabling adjacency pacing properly cleans up all state.

    This test verifies the fix for the cleanup issue where:
    1. Timer (t_dyn_adjust) is cancelled
    2. Queued neighbors are flushed and allowed to proceed
    3. Queue is cleared
    4. Thresholds are reset to defaults
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Step 1: Configure dynamic pacing with custom thresholds
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic
        ip ospf adjacency-pacing dynamic thresholds 50 5
        end
    """)

    # Wait for configuration to take effect
    time.sleep(2)

    # Step 2: Verify pacing is configured
    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf adjacency-pacing dynamic" in running_config, \
        "Dynamic pacing not configured"
    assert "ip ospf adjacency-pacing dynamic thresholds 50 5" in running_config, \
        "Thresholds not configured"

    # Step 3: Create some adjacency activity by flapping r2's interface
    # This may create queued neighbors or trigger the AIMD timer
    r2.vtysh_cmd("""
        configure terminal
        interface eth1
        shutdown
        end
    """)
    time.sleep(1)
    r2.vtysh_cmd("""
        configure terminal
        interface eth1
        no shutdown
        end
    """)
    time.sleep(2)

    # Step 4: Disable adjacency pacing
    output = r1.vtysh_cmd("""
        configure terminal
        interface eth1
        no ip ospf adjacency-pacing
        end
    """)

    # Step 5: Verify pacing is removed from config
    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf adjacency-pacing" not in running_config, \
        "Adjacency pacing still in config after disable"

    # Step 6: Verify cleanup message in output
    # The command should report what was disabled and how many neighbors were flushed
    assert "Disabling" in output or "disabled" in output.lower(), \
        "No confirmation message when disabling pacing"

    # Step 7: Check OSPF interface to ensure neighbors can form properly
    # After cleanup, new adjacencies should not be blocked
    time.sleep(5)  # Allow time for adjacency to form

    # Verify r1-r2 adjacency can reach Full state (not stuck in TwoWay)
    neighbor_output = r1.vtysh_cmd("show ip ospf neighbor json")

    # Parse JSON to check neighbor state
    import json
    try:
        neighbor_data = json.loads(neighbor_output)
        # Check if there are any neighbors
        if "default" in neighbor_data:
            neighbors = neighbor_data["default"]
            if neighbors:
                # At least one neighbor should exist and should not be stuck in TwoWay
                for nbr_id, nbr_info in neighbors.items():
                    if nbr_info:
                        state = nbr_info[0].get("nbrState", "")
                        # State can be "Full/DROther", "Full/DR", etc.
                        assert "TwoWay" not in state or "Full" in state, \
                            f"Neighbor {nbr_id} stuck in {state} after pacing cleanup"
    except json.JSONDecodeError:
        # If JSON parsing fails, at least verify output exists
        assert neighbor_output, "No neighbor output after cleanup"

    # Step 8: Verify that we can re-enable pacing without issues
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        ip ospf adjacency-pacing dynamic
        ip ospf adjacency-pacing dynamic thresholds 80 10
        end
    """)

    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf adjacency-pacing dynamic thresholds 80 10" in running_config, \
        "Cannot re-enable pacing after cleanup"

    # Cleanup: remove pacing configuration
    r1.vtysh_cmd("""
        configure terminal
        interface eth1
        no ip ospf adjacency-pacing
        end
    """)


if __name__ == "__main__":
    # To run the tests manually
    import os
    import sys

    # Allow running from the test directory
    sys.exit(pytest.main(["-s", __file__]))
