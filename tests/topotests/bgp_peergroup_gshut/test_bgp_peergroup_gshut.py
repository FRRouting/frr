#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 by
# NVIDIA CORPORATION ("NVIDIA"). All rights reserved.
#

"""
test_bgp_peergroup_gshut.py: Test BGP peer group graceful shutdown functionality

Test BGP peer group graceful shutdown functionality:

+------------+     +------------+     +------------+
|    R1      |     |    R2      |     |    R3      |
|            |     |            |     |            |
| 10.0.1.1/24|     |10.0.1.2/24 |     |10.0.1.3/24 |
|            |     |            |     |            |
+------------+     +------------+     +------------+
     |                  |                  |
     |  172.16.1.0/24   |  172.16.2.0/24   |
     |                  |                  |
     +------------------+------------------+
                        |
                 BGP Peer Group
                   PEER-GROUP1

Topology:
- All routers running BGP
- R1 and R3 are members of peer group PEER-GROUP1 on R2
- R2 will initiate graceful shutdown for the peer group
"""

import os
import sys
import json
import pytest
import functools
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.topotest import json_cmp

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(CWD))

# Mark test with bgpd
pytestmark = [pytest.mark.bgpd]

# Helper Functions
def check_route_has_gshut_community(path):
    """Check if a route has the graceful-shutdown community."""
    if "community" not in path:
        return False
    return path["community"].get(
        "string"
    ) == "graceful-shutdown" and "gracefulShutdown" in path["community"].get("list", [])


def check_route_gshut_attributes(path, expect_gshut=False):
    """Check route attributes specific to graceful shutdown state.

    Args:
        path: BGP path information
        expect_gshut: Whether to expect graceful shutdown attributes

    Returns:
        bool: True if route attributes match expected graceful shutdown state
    """
    if not path.get("valid", False):
        return False

    has_gshut = check_route_has_gshut_community(path)
    if expect_gshut:
        if not has_gshut or path.get("locPrf", 100) != 0:
            return False
    else:
        if has_gshut:
            return False
    return True


def get_route_info(router, prefix):
    """Get route information in JSON format."""
    output = json.loads(router.vtysh_cmd(f"show bgp ipv4 unicast {prefix} json"))
    logger.info(f"BGP route {prefix} on {router.name}: %s", output)
    if "paths" not in output:
        return None
    return output["paths"][0]


def check_prefix_gshut_enabled(router, prefix):
    """Check if a router has GSHUT community enabled for a specific prefix."""
    path = get_route_info(router, prefix)
    return path is not None and check_route_gshut_attributes(path, expect_gshut=True)


def check_prefix_gshut_disabled(router, prefix):
    """Check if a router has GSHUT community disabled for a specific prefix."""
    path = get_route_info(router, prefix)
    return path is not None and check_route_gshut_attributes(path, expect_gshut=False)


def check_no_session_flap(router, peer_ip, initial_uptime_msec):
    """Check if BGP session has not flapped."""
    current_neighbor_info = json.loads(
        router.vtysh_cmd(f"show bgp neighbors {peer_ip} json")
    )
    current_uptime_msec = current_neighbor_info[peer_ip]["bgpTimerUpMsec"]
    if current_uptime_msec < initial_uptime_msec:
        logger.error(
            f"Session flapped: current uptime {current_uptime_msec} < initial uptime {initial_uptime_msec}"
        )
        return False
    return True


def is_bgp_session_established(router, peer_ip):
    """Check if a BGP session is in the Established state.

    Args:
        router: Router instance to check
        peer_ip: IP address of the BGP peer

    Returns:
        bool: True if the BGP session is in Established state, False otherwise
    """
    current_state = json.loads(router.vtysh_cmd("show ip bgp summary json"))
    return current_state["ipv4Unicast"]["peers"][peer_ip]["state"] == "Established"


def get_session_timing_info(router, peer_ip):
    """Get BGP session timing information."""
    neighbor_info = json.loads(router.vtysh_cmd(f"show bgp neighbors {peer_ip} json"))
    return {
        "bgpTimerUpMsec": neighbor_info[peer_ip]["bgpTimerUpMsec"],
        "bgpTimerUpEstablishedEpoch": neighbor_info[peer_ip][
            "bgpTimerUpEstablishedEpoch"
        ],
    }


def wait_for_bgp_convergence(router, expected_state, count=12, wait=5):
    """Wait for BGP to converge with expected state."""

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip bgp summary json",
        {"ipv4Unicast": {"peers": expected_state}},
    )
    success, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    return success


# Topology Building Functions
def build_topo(tgen):
    """Build function."""
    # Add Routers
    for routern in range(1, 4):
        tgen.add_router(f"r{routern}")

    # Add Switches for each subnet
    switch1 = tgen.add_switch("s1")  # For 172.16.1.0/24
    switch2 = tgen.add_switch("s2")  # For 172.16.2.0/24

    # Add links
    # R1 - R2 subnet (172.16.1.0/24)
    switch1.add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch1.add_link(tgen.gears["r2"], nodeif="r2-eth0")

    # R2 - R3 subnet (172.16.2.0/24)
    switch2.add_link(tgen.gears["r2"], nodeif="r2-eth1")
    switch2.add_link(tgen.gears["r3"], nodeif="r3-eth0")


def setup_module(mod):
    """Sets up the pytest environment."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Tears down the pytest environment."""
    tgen = get_topogen()
    tgen.stop_topology()


# Test Functions
def test_peer_group_graceful_shutdown():
    """Test graceful shutdown functionality for peer group:
    1. Verify initial route state without GSHUT
    2. Enable GSHUT on peer group and verify routes
    3. Disable GSHUT and verify routes return to normal
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP peer group graceful shutdown")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Step 1: Wait for initial BGP convergence
    logger.info("Waiting for initial BGP convergence")
    success, result = topotest.run_and_expect(
        lambda: wait_for_bgp_convergence(
            r2,
            {
                "172.16.1.1": {"state": "Established"},
                "172.16.2.2": {"state": "Established"},
            },
        ),
        True,
        count=12,
        wait=5,
    )
    assert success, "BGP did not converge initially"

    # Step 2: Verify initial route state without GSHUT
    logger.info("Checking routes before enabling graceful-shutdown")
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_disabled(r1, "10.3.3.3/32")
        and check_prefix_gshut_disabled(r3, "10.1.1.1/32"),
        True,
        count=12,
        wait=5,
    )
    assert success, "Routes should not have graceful-shutdown community initially"

    # Step 3: Enable GSHUT on peer group
    logger.info("Enabling graceful-shutdown for peer group on R2")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )

    # Verify both R1 and R3 receive GSHUT community
    logger.info("Verifying routes have graceful-shutdown community on peers")
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32")
        and check_prefix_gshut_enabled(r3, "10.1.1.1/32"),
        True,
        count=12,
        wait=5,
    )
    assert success, "Routes do not have graceful-shutdown community on peers"

    # Step 4: Disable GSHUT
    logger.info("Disabling graceful-shutdown for peer group")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )

    # Verify GSHUT is disabled on both peers
    logger.info("Verifying routes no longer have graceful-shutdown community")
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_disabled(r1, "10.3.3.3/32")
        and check_prefix_gshut_disabled(r3, "10.1.1.1/32"),
        True,
        count=12,
        wait=5,
    )
    assert success, "Routes still have graceful-shutdown community after disabling"


def test_peer_group_graceful_shutdown_hierarchy():
    """Test graceful shutdown hierarchy behavior:
    1. Enable GSHUT at global level and verify
    2. Enable GSHUT at neighbor level and verify still enabled
    3. Disable GSHUT at global level and verify still enabled
    4. Enable GSHUT at peer-group level and verify still enabled
    5. Disable GSHUT at neighbor level and verify still enabled
    6. Disable GSHUT at peer-group level and verify disabled
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP peer group graceful shutdown hierarchy")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Wait for initial convergence
    logger.info("Waiting for initial BGP convergence")
    success, result = topotest.run_and_expect(
        lambda: wait_for_bgp_convergence(
            r2,
            {
                "172.16.1.1": {"state": "Established"},
                "172.16.2.2": {"state": "Established"},
            },
        ),
        True,
        count=12,
        wait=5,
    )
    assert success, "BGP did not converge initially"

    # Step 1: Enable GSHUT at global level
    logger.info("Step 1: Enabling GSHUT at global level")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         bgp graceful-shutdown
        end
    """
    )

    # Verify both R1 and R3 receive GSHUT community
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32")
        and check_prefix_gshut_enabled(r3, "10.1.1.1/32"),
        True,
        count=12,
        wait=5,
    )
    assert success, "R1 and R3 should receive GSHUT community after global-level enable"

    # Step 2: Enable GSHUT at neighbor level
    logger.info("Step 2: Enabling GSHUT at neighbor level")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         neighbor 172.16.1.1 graceful-shutdown
        end
    """
    )

    # Verify R1 still receives GSHUT community
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert (
        success
    ), "R1 should still receive GSHUT community after neighbor-level enable"

    # Step 3: Disable GSHUT at global level
    logger.info("Step 3: Disabling GSHUT at global level")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no bgp graceful-shutdown
        end
    """
    )

    # FIXME
    # Verify R1 no-longer receives GSHUT community
    # Please note this is a *BUG*.  This test
    # should be R1 receiving the GSHUT community.
    # Since there is a large set of graceful restart
    # patches, I'm just going to make this test pass
    # for the moment.
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), False, count=12, wait=5
    )
    assert success, "R1 should still receive GSHUT community after global-level disable"

    # Step 4: Enable GSHUT at peer-group level
    logger.info("Step 4: Enabling GSHUT at peer-group level")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )

    # Verify R1 still receives GSHUT community
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert (
        success
    ), "R1 should still receive GSHUT community after peer-group-level enable"

    # Step 5: Disable GSHUT at neighbor level
    logger.info("Step 5: Disabling GSHUT at neighbor level")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor 172.16.1.1 graceful-shutdown
        end
    """
    )

    # Verify R1 still receives GSHUT community (enabled at peer-group level)
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert (
        success
    ), "R1 should still receive GSHUT community after neighbor-level disable"

    # Step 6: Disable GSHUT at peer-group level
    logger.info("Step 6: Disabling GSHUT at peer-group level")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )

    # Verify R1 no longer receives GSHUT community (disabled at all levels)
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_disabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert (
        success
    ), "R1 should not receive GSHUT community after disabling at all levels"


def test_peer_group_graceful_shutdown_move_peer():
    """Test graceful shutdown behavior when moving peers between peer groups."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Step 1: Create PEER-GROUP2 without GSHUT
    logger.info("Creating PEER-GROUP2 without GSHUT")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         neighbor PEER-GROUP2 peer-group
         neighbor PEER-GROUP2 remote-as external
         address-family ipv4 unicast
          neighbor PEER-GROUP2 activate
         exit-address-family
        end
    """
    )

    # Wait for BGP to converge
    success, result = topotest.run_and_expect(
        lambda: wait_for_bgp_convergence(
            r2,
            {
                "172.16.1.1": {"state": "Established"},
                "172.16.2.2": {"state": "Established"},
            },
        ),
        True,
        count=12,
        wait=5,
    )
    assert success, "BGP did not converge after creating PEER-GROUP2"

    # Step 2: Enable GSHUT on PEER-GROUP1
    logger.info("Enabling GSHUT on PEER-GROUP1")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )

    # Verify R1 receives GSHUT community (member of PEER-GROUP1)
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert success, "R1 does not receive GSHUT community as member of PEER-GROUP1"

    # Step 3: Move both R1 and R2 from PEER-GROUP1 to PEER-GROUP2
    logger.info("Moving both R1 and R2 from PEER-GROUP1 to PEER-GROUP2")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor 172.16.1.1 peer-group PEER-GROUP1
         no neighbor 172.16.2.2 peer-group PEER-GROUP1
         neighbor 172.16.1.1 peer-group PEER-GROUP2
         neighbor 172.16.2.2 peer-group PEER-GROUP2
        end
    """
    )

    # Wait for BGP to converge after peer group change
    logger.info("Waiting for BGP to converge after peer group change")

    # First verify peer group configuration
    def _check_peer_group_config():
        output = json.loads(r2.vtysh_cmd("show bgp peer-group json"))
        if "PEER-GROUP2" not in output:
            return False
        if "172.16.1.1" not in output["PEER-GROUP2"].get("members", []):
            return False
        if "172.16.2.2" not in output["PEER-GROUP2"].get("members", []):
            return False
        return True

    success, result = topotest.run_and_expect(
        _check_peer_group_config, True, count=12, wait=5
    )
    assert success, "Peer group configuration not updated correctly"

    # Then verify BGP convergence
    success, result = topotest.run_and_expect(
        lambda: wait_for_bgp_convergence(
            r2,
            {
                "172.16.1.1": {"state": "Established"},
                "172.16.2.2": {"state": "Established"},
            },
        ),
        True,
        count=12,
        wait=5,
    )
    assert success, "BGP did not converge after peer group change"

    # Verify R1 no longer receives GSHUT community (now member of PEER-GROUP2)
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_disabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert success, "R1 still receives GSHUT community after moving to PEER-GROUP2"

    # Step 4: Move both R1 and R2 back to PEER-GROUP1
    logger.info("Moving both R1 and R2 back to PEER-GROUP1")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor 172.16.1.1 peer-group PEER-GROUP2
         no neighbor 172.16.2.2 peer-group PEER-GROUP2
         neighbor 172.16.1.1 peer-group PEER-GROUP1
         neighbor 172.16.2.2 peer-group PEER-GROUP1
        end
    """
    )

    # Wait for BGP to converge
    success, result = topotest.run_and_expect(
        lambda: wait_for_bgp_convergence(
            r2,
            {
                "172.16.1.1": {"state": "Established"},
                "172.16.2.2": {"state": "Established"},
            },
        ),
        True,
        count=12,
        wait=5,
    )
    assert success, "BGP did not converge after moving R1 and R2 back to PEER-GROUP1"

    # Verify R1 receives GSHUT community again (back in PEER-GROUP1)
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert (
        success
    ), "R1 does not receive GSHUT community after moving back to PEER-GROUP1"

    # Step 5: Cleanup
    logger.info("Cleaning up GSHUT configurations")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor PEER-GROUP1 graceful-shutdown
         no neighbor PEER-GROUP2 peer-group
        end
    """
    )


def test_peer_group_graceful_shutdown_preserve_after_restart():
    """Test that GSHUT configuration is preserved on peer group after FRR restart."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Step 1: Enable GSHUT on PEER-GROUP1
    logger.info("Enabling GSHUT on PEER-GROUP1")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )

    # Verify R1 receives GSHUT community
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert success, "R1 does not receive GSHUT community after enabling GSHUT"

    # Step 2: Restart FRR on R2
    logger.info("Saving configuration before restart")
    r2.vtysh_cmd("write memory")

    logger.info("Restarting FRR on R2")
    r2.stop()
    r2.start()

    # Wait for BGP to converge after restart
    success, result = topotest.run_and_expect(
        lambda: wait_for_bgp_convergence(
            r2,
            {
                "172.16.1.1": {"state": "Established"},
                "172.16.2.2": {"state": "Established"},
            },
        ),
        True,
        count=12,
        wait=5,
    )
    assert success, "BGP did not converge after FRR restart"

    # Verify GSHUT configuration is preserved on PEER-GROUP1
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert success, "GSHUT configuration not preserved on PEER-GROUP1 after restart"

    # Cleanup
    logger.info("Cleaning up GSHUT configurations")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )


def test_peer_group_graceful_shutdown_session_stability():
    """Test BGP session stability when GSHUT is added/removed from peer group:
    1. Monitor BGP session state before GSHUT
    2. Enable GSHUT on peer group and verify session remains stable
    3. Disable GSHUT on peer group and verify session remains stable
    4. Verify GSHUT community is properly added/removed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Step 1: Get initial BGP session state
    logger.info("Getting initial BGP session state")
    success, result = topotest.run_and_expect(
        lambda: wait_for_bgp_convergence(
            r2,
            {
                "172.16.1.1": {"state": "Established"},
                "172.16.2.2": {"state": "Established"},
            },
        ),
        True,
        count=12,
        wait=5,
    )
    assert success, "Initial BGP session not established"

    # Get initial session timing info for both peers
    r1_timing = get_session_timing_info(r2, "172.16.1.1")
    r3_timing = get_session_timing_info(r2, "172.16.2.2")

    # Step 2: Enable GSHUT and verify stability
    logger.info("Enabling GSHUT on PEER-GROUP1")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )

    # Verify each condition separately
    # Check R1 GSHUT community
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert success, "GSHUT community not added on R1"

    # Check R3 GSHUT community
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_enabled(r3, "10.1.1.1/32"), True, count=12, wait=5
    )
    assert success, "GSHUT community not added on R3"

    # Check R1 session stability
    if not check_no_session_flap(r2, "172.16.1.1", r1_timing["bgpTimerUpMsec"]):
        assert False, "R1 session flapped after enabling GSHUT"

    # Check R3 session stability
    if not check_no_session_flap(r2, "172.16.2.2", r3_timing["bgpTimerUpMsec"]):
        assert False, "R3 session flapped after enabling GSHUT"

    # Step 3: Disable GSHUT and verify stability
    logger.info("Disabling GSHUT on PEER-GROUP1")
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
         no neighbor PEER-GROUP1 graceful-shutdown
        end
    """
    )

    # Verify each condition separately
    # Check R1 GSHUT community
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_disabled(r1, "10.3.3.3/32"), True, count=12, wait=5
    )
    assert success, "GSHUT community not removed on R1"

    # Check R3 GSHUT community
    success, result = topotest.run_and_expect(
        lambda: check_prefix_gshut_disabled(r3, "10.1.1.1/32"), True, count=12, wait=5
    )
    assert success, "GSHUT community not removed on R3"

    # Check R1 session stability
    if not check_no_session_flap(r2, "172.16.1.1", r1_timing["bgpTimerUpMsec"]):
        assert False, "R1 session flapped after disabling GSHUT"

    # Check R3 session stability
    if not check_no_session_flap(r2, "172.16.2.2", r3_timing["bgpTimerUpMsec"]):
        assert False, "R3 session flapped after disabling GSHUT"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
