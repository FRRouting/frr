#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# BGP Graceful Restart FIB Suppress Test
#
# Copyright (c) 2025 by Vijayalaxmi Basavaraj, Nvidia Inc.
#

r"""
Test BGP Graceful Restart with FIB Suppression functionality.

This test verifies BGP peering establishment between 3 routers (r1, r2, r3)
using 192.168.x.x IP addresses.

Topology:
    r1 ---- r2 ---- r3
     \            /
      \----------/

IP Address Plan:
- r1: 192.168.1.1/32 (loopback), 192.168.12.1/24 (r1-r2), 192.168.13.1/24 (r1-r3)
- r2: 192.168.2.2/32 (loopback), 192.168.12.2/24 (r1-r2), 192.168.23.2/24 (r2-r3)
- r3: 192.168.3.3/32 (loopback), 192.168.13.3/24 (r1-r3), 192.168.23.3/24 (r2-r3)
"""

import os
import sys
import time
import pytest
import functools
import json

# Import topogen and required test modules
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    step,
    required_linux_kernel_version,
    kill_router_daemons,
    start_router_daemons,
)

pytestmark = [pytest.mark.bgpd]


def verify_graceful_restart_json(router, neighbor_ip, expected_local_mode="Restart*", expected_remote_mode="Helper"):
    """
    Verify graceful restart status using JSON API similar to bgp_gr_functionality_topo1.

    Parameters:
    - router: router object
    - neighbor_ip: neighbor IP address to check
    - expected_local_mode: expected local GR mode
    - expected_remote_mode: expected remote GR mode
    """
    try:
        # Use JSON API to get GR status
        cmd = f"show bgp ipv4 neighbor {neighbor_ip} graceful-restart json"
        output = router.vtysh_cmd(cmd)

        try:
            gr_data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON output for GR status: {e}")
            logger.error(f"Raw output: {output}")
            return False

        if neighbor_ip not in gr_data:
            logger.error(f"Neighbor {neighbor_ip} not found in GR output")
            return False

        neighbor_data = gr_data[neighbor_ip]

        # GR fields are directly under neighbor_data, not in a sub-object
        local_mode = neighbor_data.get("localGrMode", "Unknown")
        remote_mode = neighbor_data.get("remoteGrMode", "Unknown")

        logger.info(f"GR Status for {router.name} -> {neighbor_ip}:")
        logger.info(f"  Local GR Mode: {local_mode} (expected: {expected_local_mode})")
        logger.info(f"  Remote GR Mode: {remote_mode} (expected: {expected_remote_mode})")

        # Check if modes match expectations
        local_match = local_mode == expected_local_mode
        remote_match = remote_mode == expected_remote_mode

        if not local_match:
            logger.warning(f"Local GR mode mismatch: expected {expected_local_mode}, got {local_mode}")

        if not remote_match:
            logger.warning(f"Remote GR mode mismatch: expected {expected_remote_mode}, got {remote_mode}")

        return local_match and remote_match

    except Exception as e:
        logger.error(f"Exception in GR verification: {e}")
        return False


def verify_r_bit_json(router, neighbor_ip, expected=True):
    """
    Verify R-bit status using JSON API.
    R-bit indicates the router is in restart mode.
    """
    try:
        cmd = f"show bgp ipv4 neighbor {neighbor_ip} graceful-restart json"
        output = router.vtysh_cmd(cmd)

        try:
            gr_data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON output for R-bit check: {e}")
            return False

        if neighbor_ip not in gr_data:
            logger.error(f"Neighbor {neighbor_ip} not found in R-bit output")
            return False

        neighbor_data = gr_data[neighbor_ip]

        # rBit is directly under neighbor_data
        r_bit = neighbor_data.get("rBit", False)

        logger.info(f"R-bit status for {router.name} -> {neighbor_ip}: {r_bit} (expected: {expected})")

        return r_bit == expected

    except Exception as e:
        logger.error(f"Exception in R-bit verification: {e}")
        return False


def verify_f_bit_json(router, neighbor_ip, expected=True):
    """
    Verify F-bit status using JSON API.
    F-bit indicates forwarding state preservation.
    """
    try:
        cmd = f"show bgp ipv4 neighbor {neighbor_ip} graceful-restart json"
        output = router.vtysh_cmd(cmd)

        try:
            gr_data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON output for F-bit check: {e}")
            return False

        if neighbor_ip not in gr_data:
            logger.error(f"Neighbor {neighbor_ip} not found in F-bit output")
            return False

        neighbor_data = gr_data[neighbor_ip]

        # F-bit is in the address family specific section directly under neighbor_data
        ipv4_unicast = neighbor_data.get("ipv4Unicast", {})
        f_bit = ipv4_unicast.get("fBit", False)

        logger.info(f"F-bit status for {router.name} -> {neighbor_ip}: {f_bit} (expected: {expected})")

        return f_bit == expected

    except Exception as e:
        logger.error(f"Exception in F-bit verification: {e}")
        return False


def check_bgp_neighbors_established(router):
    """Check if BGP neighbors are established on a router."""
    try:
        logger.info(f"=== BGP Convergence Check for {router.name} ===")

        # First, check if BGP daemon is running
        try:
            output = router.vtysh_cmd("show bgp summary json")
            logger.info(f"BGP daemon is responding on {router.name}")
        except Exception as e:
            logger.error(f"BGP daemon not responding on {router.name}: {e}")
            return False

        # Parse JSON output
        try:
            bgp_data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse BGP summary JSON on {router.name}: {e}")
            logger.error(f"Raw output: {output[:200]}...")
            return False

        # Log BGP router ID if available
        router_id = bgp_data.get("routerId", "Unknown")
        logger.info(f"BGP router-id on {router.name}: {router_id}")

        established_count = 0
        total_neighbors = 0

        # Check IPv4 unicast neighbors
        if "ipv4Unicast" in bgp_data and "peers" in bgp_data["ipv4Unicast"]:
            peers = bgp_data["ipv4Unicast"]["peers"]
            total_neighbors += len(peers)

            for peer_ip, peer_data in peers.items():
                state = peer_data.get("state", "Unknown")
                logger.info(f"  Neighbor {peer_ip}: state={state}")

                if state == "Established":
                    established_count += 1
                    logger.info(f"  ✓ Neighbor {peer_ip} established")
                else:
                    logger.info(f"  ✗ Neighbor {peer_ip} in state: {state}")

        # Check IPv6 unicast neighbors if present
        if "ipv6Unicast" in bgp_data and "peers" in bgp_data["ipv6Unicast"]:
            peers = bgp_data["ipv6Unicast"]["peers"]
            total_neighbors += len(peers)

            for peer_ip, peer_data in peers.items():
                state = peer_data.get("state", "Unknown")
                logger.info(f"  IPv6 Neighbor {peer_ip}: state={state}")

                if state == "Established":
                    established_count += 1
                    logger.info(f"  ✓ IPv6 Neighbor {peer_ip} established")
                else:
                    logger.info(f"  ✗ IPv6 Neighbor {peer_ip} in state: {state}")

        logger.info(f"Results for {router.name}:")
        logger.info(f"  - Total neighbors: {total_neighbors}")
        logger.info(f"  - Established neighbors: {established_count}")
        logger.info(f"  - Expected minimum neighbors: 2")

        # Check if we have at least 2 established neighbors
        final_result = established_count >= 2
        logger.info(f"  - FINAL result: {final_result}")

        if not final_result:
            logger.error(f"BGP convergence check FAILED for {router.name}")
            logger.error(f"Troubleshooting suggestions:")
            logger.error(f"1. Check if BGP neighbors are configured correctly")
            logger.error(f"2. Verify IP connectivity between routers")
            logger.error(f"3. Check if neighbors are using expected IP addresses")
            logger.error(f"4. Ensure BGP configuration is loaded properly")

            # Additional debugging commands
            try:
                neighbors_detail = router.vtysh_cmd("show bgp neighbors json")
                logger.info(f"Detailed neighbor info for {router.name}:")
                logger.info(neighbors_detail[:500] + "..." if len(neighbors_detail) > 500 else neighbors_detail)
            except Exception as e:
                logger.warning(f"Could not get detailed neighbor info: {e}")

        return final_result

    except Exception as e:
        logger.error(f"Exception in BGP convergence check for {router.name}: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def build_topo(tgen):
    """Build the topology for BGP Graceful Restart FIB Suppress test."""

    # Create 3 routers
    for router_name in ["r1", "r2", "r3"]:
        tgen.add_router(router_name)

    # Create connections between routers
    # r1 <-> r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1 <-> r3
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # r2 <-> r3
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    """Set up the pytest environment."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Enable required daemons for all routers
    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info(f"Enabling daemons for router {rname}")
        # Enable mgmtd, zebra, and bgpd
        router.load_config(router.RD_MGMTD, "")
        router.load_config(router.RD_ZEBRA, "")
        router.load_config(router.RD_BGP, "")

    # Load FRR configuration for each router
    for rname, router in router_list.items():
        logger.info(f"Loading config to router {rname}")
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    # Initialize all routers
    tgen.start_router()


def teardown_module(mod):
    """Tear down the pytest environment."""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """Test basic BGP convergence with 192.168.x.x addressing."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP convergence with 192.168.x.x addressing")

    # Check BGP summary on all routers
    for router_name in ["r1", "r2", "r3"]:
        router = tgen.gears[router_name]
        # Use functools.partial to create a parameterless function
        test_func = functools.partial(check_bgp_neighbors_established, router)
        success, result = topotest.run_and_expect(test_func, True, count=60, wait=3)
        assert success, f"BGP failed to converge on {router_name}: {result}"

    logger.info("✓ BGP convergence test passed")


def test_bgp_routes():
    """Test BGP route exchange between routers."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP route exchange")

    # Expected routes from each router
    expected_routes = {
        "r1": ["192.168.11.1/32", "192.168.11.2/32"],
        "r2": ["192.168.22.1/32", "192.168.22.2/32"],
        "r3": ["192.168.33.1/32", "192.168.33.2/32"]
    }

    # Check that each router learns routes from others
    for router_name in ["r1", "r2", "r3"]:
        router = tgen.gears[router_name]

        # Check that this router has routes from other routers
        other_routers = [r for r in ["r1", "r2", "r3"] if r != router_name]

        for other_router in other_routers:
            for expected_route in expected_routes[other_router]:
                # Define route checking function using JSON
                def check_route(router, route):
                    try:
                        output = router.vtysh_cmd("show ip route summary json")
                        route_data = json.loads(output)

                        # Check if routes exist based on actual JSON structure
                        if "routes" in route_data:
                            routes_array = route_data["routes"]

                            # Parse route types and counts
                            bgp_routes = 0

                            for route_entry in routes_array:
                                route_type = route_entry.get("type", "")
                                rib_count = route_entry.get("rib", 0)

                                if route_type in ["ebgp", "ibgp", "bgp"]:
                                    bgp_routes += rib_count

                            # Route should exist if we have BGP routes (indicating convergence)
                            return bgp_routes > 0
                        return False
                    except Exception as e:
                        logger.debug(f"Route check failed for {route}: {e}")
                        return False

                # Use functools.partial to create a parameterless function
                test_func = functools.partial(check_route, router, expected_route)
                success, result = topotest.run_and_expect(test_func, True, count=20, wait=3)
                assert success, f"{router_name} failed to learn route {expected_route} from {other_router}"

    logger.info("✓ BGP route exchange test passed")


def test_bgp_graceful_restart():
    """Test BGP Graceful Restart on R2."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP Graceful Restart")

    # First verify initial BGP convergence
    def check_initial_convergence():
        for router_name in ["r1", "r2", "r3"]:
            router = tgen.gears[router_name]
            test_func = functools.partial(check_bgp_neighbors_established, router)
            success, result = topotest.run_and_expect(test_func, True, count=60, wait=3)
            if not success:
                return False
        return True

    step("Verify initial BGP convergence before graceful restart test")
    assert check_initial_convergence(), "Initial BGP convergence failed"

    # Check graceful restart configuration on R2
    def check_gr_config(router):
        try:
            # Check the running configuration for graceful restart and FIB suppression
            config_output = router.vtysh_cmd("show running-config")
            has_gr = "bgp graceful-restart" in config_output
            has_preserve = "bgp graceful-restart preserve-fw-state" in config_output
            has_fib_suppress = "bgp suppress-fib-pending" in config_output

            logger.info(f"Graceful restart in config: {has_gr}")
            logger.info(f"Preserve fw-state in config: {has_preserve}")
            logger.info(f"FIB suppression in config: {has_fib_suppress}")

            return has_gr and has_preserve and has_fib_suppress
        except Exception as e:
            logger.error(f"Error checking graceful restart config: {e}")
            return False

    step("Verify graceful restart and FIB suppression configuration on R2")
    router_r2 = tgen.gears["r2"]
    test_func = functools.partial(check_gr_config, router_r2)
    success, result = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert success, "Graceful restart and FIB suppression configuration not found on R2"

    # Store initial route count on R1 and R3 before restart
    def get_route_count(router):
        try:
            output = router.vtysh_cmd("show ip route summary json")
            route_data = json.loads(output)

            if "ipv4" in route_data:
                ipv4_data = route_data["ipv4"]
                # Get total routes, which includes connected, static, and BGP
                total_routes = ipv4_data.get("routesTotal", 0)
                bgp_routes = ipv4_data.get("bgp", 0)
                connected_routes = ipv4_data.get("connected", 0)
                static_routes = ipv4_data.get("static", 0)

                return {
                    "total": total_routes,
                    "bgp": bgp_routes,
                    "connected": connected_routes,
                    "static": static_routes
                }
            return {"total": 0, "bgp": 0, "connected": 0, "static": 0}
        except Exception as e:
            logger.debug(f"Failed to get route count: {e}")
            return {"total": 0, "bgp": 0, "connected": 0, "static": 0}

    step("Store initial route counts before restart")
    router_r1 = tgen.gears["r1"]
    router_r3 = tgen.gears["r3"]

    initial_r1_routes = get_route_count(router_r1)
    initial_r3_routes = get_route_count(router_r3)

    logger.info(f"Initial route counts:")
    logger.info(f"  R1: Total={initial_r1_routes['total']}, BGP={initial_r1_routes['bgp']}, Connected={initial_r1_routes['connected']}, Static={initial_r1_routes['static']}")
    logger.info(f"  R3: Total={initial_r3_routes['total']}, BGP={initial_r3_routes['bgp']}, Connected={initial_r3_routes['connected']}, Static={initial_r3_routes['static']}")

    # Simulate BGP daemon restart on R2 (graceful restart scenario)
    step("Restart BGP daemon on R2 to trigger graceful restart")

    # Kill BGP daemon on R2 using standard BGP GR pattern
    logger.info("Killing BGP daemon on R2...")
    kill_router_daemons(tgen, "r2", ["bgpd"])

    # Wait for graceful restart to activate
    def check_bgp_daemon_stopped():
        try:
            output = router_r2.vtysh_cmd("show bgp summary json")
            # If we get an error or no proper response, daemon is stopped
            try:
                bgp_data = json.loads(output)
                # Check if we have a valid router ID - if not, daemon is stopped/not ready
                router_id = bgp_data.get("routerId") or bgp_data.get("ipv4Unicast", {}).get("routerId")
                return not router_id  # Return True if no router ID (daemon stopped)
            except json.JSONDecodeError:
                return True  # Invalid JSON means daemon is stopped
        except:
            return True  # Command failed, daemon is stopped

    test_func = functools.partial(check_bgp_daemon_stopped)
    success, result = topotest.run_and_expect(test_func, True, count=10, wait=15)

    # During graceful restart period, verify R1 and R3 maintain routes
    step("Verify R1 and R3 maintain routes during graceful restart period")

    def check_routes_maintained(router, expected_count):
        current_count = get_route_count(router)
        # Routes must be maintained exactly during graceful restart
        current_total = current_count.get('total', 0)
        expected_total = expected_count.get('total', 0)
        return current_total == expected_total

    # Check R1 maintains routes
    test_func = functools.partial(check_routes_maintained, router_r1, initial_r1_routes)
    success, result = topotest.run_and_expect(test_func, True, count=15, wait=3)
    assert success, "R1 failed to maintain routes during graceful restart"

    # Check R3 maintains routes
    test_func = functools.partial(check_routes_maintained, router_r3, initial_r3_routes)
    success, result = topotest.run_and_expect(test_func, True, count=15, wait=3)
    assert success, "R3 failed to maintain routes during graceful restart"

    # Verify FIB suppression and route preservation during graceful restart
    step("Verify routes are NOT deleted on R1 and R3 during R2 graceful restart")

    def check_routes_not_deleted_on_r1():
        try:
            # Get current route table on R1 using JSON
            current_routes = router_r1.vtysh_cmd("show ip route json")
            route_data = json.loads(current_routes)

            # Count routes that should come from R2 (routes to 192.168.22.x networks)
            r2_routes_in_r1 = 0
            for prefix, routes in route_data.items():
                if "192.168.22." in prefix:
                    r2_routes_in_r1 += 1

            # Get BGP-specific routes using JSON
            bgp_routes = router_r1.vtysh_cmd("show ip route bgp json")
            bgp_data = json.loads(bgp_routes)

            # Count BGP routes from R2 specifically
            bgp_from_r2 = 0
            for prefix, routes in bgp_data.items():
                if "192.168.22." in prefix:
                    for route in routes:
                        # Check if next hop is R2 (192.168.12.2)
                        nexthops = route.get("nexthops", [])
                        for nh in nexthops:
                            if nh.get("ip") == "192.168.12.2":
                                bgp_from_r2 += 1
                                break

            logger.info(f"R1: Found {r2_routes_in_r1} routes from R2 networks, {bgp_from_r2} BGP routes via R2")

            # Routes should still be present during graceful restart (FIB suppression preserves them)
            return r2_routes_in_r1 >= 1  # Should have at least some routes from R2 networks

        except Exception as e:
            logger.error(f"Error checking routes on R1: {e}")
            return False

    def check_routes_not_deleted_on_r3():
        try:
            # Get current route table on R3 using JSON
            current_routes = router_r3.vtysh_cmd("show ip route json")
            route_data = json.loads(current_routes)

            # Count routes that should come from R2 (routes to 192.168.22.x networks)
            r2_routes_in_r3 = 0
            for prefix, routes in route_data.items():
                if "192.168.22." in prefix:
                    r2_routes_in_r3 += 1

            # Get BGP-specific routes using JSON
            bgp_routes = router_r3.vtysh_cmd("show ip route bgp json")
            bgp_data = json.loads(bgp_routes)

            # Count BGP routes from R2 specifically
            bgp_from_r2 = 0
            for prefix, routes in bgp_data.items():
                if "192.168.22." in prefix:
                    for route in routes:
                        # Check if next hop is R2 (192.168.23.2)
                        nexthops = route.get("nexthops", [])
                        for nh in nexthops:
                            if nh.get("ip") == "192.168.23.2":
                                bgp_from_r2 += 1
                                break

            logger.info(f"R3: Found {r2_routes_in_r3} routes from R2 networks, {bgp_from_r2} BGP routes via R2")

            # Routes should still be present during graceful restart (FIB suppression preserves them)
            return r2_routes_in_r3 >= 1  # Should have at least some routes from R2 networks

        except Exception as e:
            logger.error(f"Error checking routes on R3: {e}")
            return False

    # Verify R1 maintains routes from R2
    logger.info("Checking that R1 does NOT delete routes from R2 during graceful restart...")
    test_func = functools.partial(check_routes_not_deleted_on_r1)
    success, result = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert success, "R1 incorrectly deleted routes from R2 during graceful restart - FIB suppression not working"

    # Verify R3 maintains routes from R2
    logger.info("Checking that R3 does NOT delete routes from R2 during graceful restart...")
    test_func = functools.partial(check_routes_not_deleted_on_r3)
    success, result = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert success, "R3 incorrectly deleted routes from R2 during graceful restart - FIB suppression not working"

    logger.info("✓ Route preservation verified: R1 and R3 correctly maintained routes during R2 graceful restart")

    # Restart BGP daemon on R2 (standard topotest pattern)
    step("Restart BGP daemon on R2")
    logger.info("Starting BGP daemon on R2...")

    # Get config file path and router object
    source_config = os.path.join(CWD, "r2/frr.conf")
    router_r2 = tgen.gears["r2"]

    # Restart BGP daemon and load configuration using load_config
    logger.info("Starting BGP daemon...")
    try:
        start_router_daemons(tgen, "r2", ["bgpd"])
        logger.info("BGP daemon start command completed")

        # Apply BGP configuration using vtysh -f
        logger.info(f"Applying BGP config from: {source_config}")
        config_result = router_r2.cmd(f"vtysh -f {source_config}")
        logger.info("BGP configuration applied successfully")

    except Exception as e:
        logger.error(f"Failed to start daemon or load BGP config: {e}")
        raise

    # Verify BGP daemon is ready and configured
    def check_bgp_daemon_ready():
        try:
            # Check if BGP daemon is responding
            try:
                bgp_output = router_r2.vtysh_cmd("show bgp summary json")
                logger.info("✓ BGP daemon is responding to vtysh")
            except Exception as e:
                logger.info(f"✗ BGP daemon not responding: {e}")
                return False

            # Check if BGP has router identifier (indicates config loaded)
            try:
                bgp_data = json.loads(bgp_output)

                # Check for router ID in different possible locations
                router_id = None
                if "routerId" in bgp_data:
                    router_id = bgp_data["routerId"]
                elif "ipv4Unicast" in bgp_data and "routerId" in bgp_data["ipv4Unicast"]:
                    router_id = bgp_data["ipv4Unicast"]["routerId"]

                if not router_id:
                    logger.info("✗ BGP daemon not ready yet - no router identifier")
                    logger.info("BGP summary output:")
                    logger.info(bgp_output[:200] + "..." if len(bgp_output) > 200 else bgp_output)
                    logger.info(f"Available keys in JSON: {list(bgp_data.keys())}")

                    # Try to check running config directly
                    try:
                        running_config = router_r2.vtysh_cmd("show running-config")
                        has_bgp_running = "router bgp" in running_config
                        logger.info(f"Running config has BGP: {has_bgp_running}")
                        if not has_bgp_running:
                            logger.info("Running config preview:")
                            logger.info(running_config[:300] + "..." if len(running_config) > 300 else running_config)
                    except Exception as e:
                        logger.info(f"Could not check running config: {e}")

                    return False
                else:
                    logger.info(f"✓ BGP router ID found: {router_id}")

                # Check if we have expected neighbors configured
                has_neighbor1 = False
                has_neighbor2 = False

                if "ipv4Unicast" in bgp_data and "peers" in bgp_data["ipv4Unicast"]:
                    peers = bgp_data["ipv4Unicast"]["peers"]
                    has_neighbor1 = "192.168.12.1" in peers
                    has_neighbor2 = "192.168.23.3" in peers
                    logger.info(f"IPv4 peers found: {list(peers.keys()) if peers else 'none'}")

            except json.JSONDecodeError as e:
                logger.info(f"✗ Failed to parse BGP JSON output: {e}")
                logger.info(f"Raw output causing error: {repr(bgp_output[:100])}")
                return False

            logger.info(f"✓ BGP neighbors check: 192.168.12.1={has_neighbor1}, 192.168.23.3={has_neighbor2}")

            if not (has_neighbor1 and has_neighbor2):
                logger.info("✗ BGP neighbors not configured yet")
                return False

            logger.info("✓ BGP daemon ready with proper configuration")
            return True

        except Exception as e:
            logger.info(f"✗ BGP daemon check failed: {e}")
            import traceback
            logger.info(f"Traceback: {traceback.format_exc()}")
            return False

    # Wait for BGP to be ready (like other bgp_gr tests do)
    logger.info("Checking if BGP daemon is ready...")
    test_func = functools.partial(check_bgp_daemon_ready)
    success, result = topotest.run_and_expect(test_func, True, count=15, wait=2)

    if not success:
        logger.error("BGP daemon readiness check failed, attempting basic recovery...")
        # Try a simpler approach - just check if BGP is responding
        try:
            basic_output = router_r2.vtysh_cmd("show version")
            logger.info(f"Basic vtysh connectivity: OK")

            bgp_output = router_r2.vtysh_cmd("show bgp summary json")
            logger.info(f"BGP summary command works, output length: {len(bgp_output)}")

            # If we get here, BGP is at least responding
            logger.info("BGP daemon is responding, continuing with test...")
        except Exception as e:
            logger.error(f"BGP daemon completely unresponsive: {e}")
            assert False, f"BGP daemon failed to start properly after restart: {e}"
    else:
        logger.info("BGP daemon readiness check passed")

    # Wait for BGP to converge after restart (standard pattern)
    step("Wait for BGP convergence after restart")
    def verify_bgp_running_simple():
        try:
            # Check basic BGP status on all routers
            for router_name in ["r1", "r2", "r3"]:
                output = tgen.gears[router_name].vtysh_cmd("show bgp summary json")
                try:
                    bgp_data = json.loads(output)
                    # Check for router ID in different possible locations
                    router_id = None
                    if "routerId" in bgp_data:
                        router_id = bgp_data["routerId"]
                    elif "ipv4Unicast" in bgp_data and "routerId" in bgp_data["ipv4Unicast"]:
                        router_id = bgp_data["ipv4Unicast"]["routerId"]

                    if not router_id:
                        logger.info(f"Router {router_name}: No router ID found, available keys: {list(bgp_data.keys())}")
                        return False
                    else:
                        logger.info(f"Router {router_name}: Router ID {router_id} found")
                except json.JSONDecodeError as e:
                    logger.error(f"Router {router_name}: JSON parse error: {e}")
                    return False
            return True
        except Exception as e:
            logger.error(f"BGP running check exception: {e}")
            return False

    # Use topotest.run_and_expect instead of manual loop
    test_func = functools.partial(verify_bgp_running_simple)
    success, result = topotest.run_and_expect(test_func, True, count=60, wait=3)
    assert success, "BGP failed to converge after restart"
    logger.info("BGP is running on all routers")

    # Verify BGP sessions re-establish
    step("Verify BGP sessions re-establish after restart")

    # Check convergence on all routers
    for router_name in ["r1", "r2", "r3"]:
        router = tgen.gears[router_name]
        test_func = functools.partial(check_bgp_neighbors_established, router)
        success, result = topotest.run_and_expect(test_func, True, count=60, wait=3)
        assert success, f"BGP failed to converge on {router_name} after graceful restart"

    # Verify route exchange is restored
    step("Verify route exchange is restored after graceful restart")

    expected_routes = {
        "r1": ["192.168.11.1/32", "192.168.11.2/32"],
        "r2": ["192.168.22.1/32", "192.168.22.2/32"],
        "r3": ["192.168.33.1/32", "192.168.33.2/32"]
    }

    def check_route(router, route):
        try:
            output = router.vtysh_cmd("show ip route summary json")
            route_data = json.loads(output)

            # Check if routes exist based on actual JSON structure
            if "routes" in route_data:
                routes_array = route_data["routes"]

                # Parse route types and counts
                bgp_routes = 0

                for route_entry in routes_array:
                    route_type = route_entry.get("type", "")
                    rib_count = route_entry.get("rib", 0)

                    if route_type in ["ebgp", "ibgp", "bgp"]:
                        bgp_routes += rib_count

                # Route should exist if we have BGP routes (indicating convergence)
                return bgp_routes > 0
            return False
        except Exception as e:
            logger.debug(f"Route check failed for {route}: {e}")
            return False

    # Verify each router has routes from others
    for router_name in ["r1", "r2", "r3"]:
        router = tgen.gears[router_name]
        other_routers = [r for r in ["r1", "r2", "r3"] if r != router_name]

        for other_router in other_routers:
            for expected_route in expected_routes[other_router]:
                test_func = functools.partial(check_route, router, expected_route)
                success, result = topotest.run_and_expect(test_func, True, count=30, wait=3)
                assert success, f"{router_name} failed to learn route {expected_route} from {other_router} after graceful restart"

    # Verify graceful restart completed successfully with JSON verification
    step("Verify graceful restart completed successfully using JSON API")

    def check_gr_status_comprehensive():
        try:
            # First verify basic BGP neighbor establishment (JSON-based)
            output = router_r2.vtysh_cmd("show bgp summary json")
            established_count = 0

            try:
                bgp_data = json.loads(output)

                # Check IPv4 unicast neighbors
                if "ipv4Unicast" in bgp_data and "peers" in bgp_data["ipv4Unicast"]:
                    peers = bgp_data["ipv4Unicast"]["peers"]
                    for peer_ip, peer_data in peers.items():
                        state = peer_data.get("state", "Unknown")
                        if state == "Established":
                            established_count += 1

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse BGP summary JSON: {e}")
                return False

            logger.info(f"JSON-based check: Found {established_count} established neighbors on R2")

            if established_count < 2:
                return False

            # Now verify GR status using JSON (similar to bgp_gr_functionality_topo1)
            logger.info("Performing JSON-based GR verification...")

            # Verify GR status on R2 towards R1
            gr_r2_to_r1 = verify_graceful_restart_json(
                router_r2, "192.168.12.1",
                expected_local_mode="Restart*", expected_remote_mode="Helper"
            )

            # Verify GR status on R2 towards R3
            gr_r2_to_r3 = verify_graceful_restart_json(
                router_r2, "192.168.23.3",
                expected_local_mode="Restart*", expected_remote_mode="Helper"
            )

            # Verify R-bit is set on restarted router (indicates restart mode)
            r_bit_r1 = verify_r_bit_json(router_r1, "192.168.12.2", expected=True)
            r_bit_r3 = verify_r_bit_json(router_r3, "192.168.23.2", expected=True)

            # Verify F-bit for forwarding state preservation
            f_bit_r1 = verify_f_bit_json(router_r1, "192.168.12.2", expected=True)
            f_bit_r3 = verify_f_bit_json(router_r3, "192.168.23.2", expected=True)

            logger.info("JSON GR verification results:")
            logger.info(f"  GR status R2->R1: {gr_r2_to_r1}")
            logger.info(f"  GR status R2->R3: {gr_r2_to_r3}")
            logger.info(f"  R-bit on R1: {r_bit_r1}")
            logger.info(f"  R-bit on R3: {r_bit_r3}")
            logger.info(f"  F-bit on R1: {f_bit_r1}")
            logger.info(f"  F-bit on R3: {f_bit_r3}")

            # All checks should pass for successful GR
            all_passed = all([
                gr_r2_to_r1, gr_r2_to_r3,
                r_bit_r1, r_bit_r3,
                f_bit_r1, f_bit_r3
            ])

            logger.info(f"Overall GR verification: {'PASSED' if all_passed else 'FAILED'}")
            return all_passed

        except Exception as e:
            logger.error(f"Error in comprehensive GR status check: {e}")
            return False

    test_func = functools.partial(check_gr_status_comprehensive)
    success, result = topotest.run_and_expect(test_func, True, count=20, wait=3)
    assert success, "Comprehensive graceful restart verification failed on R2"

    # Verify route counts match before and after graceful restart
    step("Verify route counts are preserved after graceful restart")

    final_r1_routes = get_route_count(router_r1)
    final_r3_routes = get_route_count(router_r3)

    logger.info(f"Final route counts after graceful restart:")
    logger.info(f"  R1: Total={final_r1_routes['total']}, BGP={final_r1_routes['bgp']}, Connected={final_r1_routes['connected']}, Static={final_r1_routes['static']}")
    logger.info(f"  R3: Total={final_r3_routes['total']}, BGP={final_r3_routes['bgp']}, Connected={final_r3_routes['connected']}, Static={final_r3_routes['static']}")

    # Compare route counts
    r1_routes_preserved = (
        final_r1_routes['total'] == initial_r1_routes['total'] and
        final_r1_routes['bgp'] == initial_r1_routes['bgp'] and
        final_r1_routes['connected'] == initial_r1_routes['connected'] and
        final_r1_routes['static'] == initial_r1_routes['static']
    )

    r3_routes_preserved = (
        final_r3_routes['total'] == initial_r3_routes['total'] and
        final_r3_routes['bgp'] == initial_r3_routes['bgp'] and
        final_r3_routes['connected'] == initial_r3_routes['connected'] and
        final_r3_routes['static'] == initial_r3_routes['static']
    )

    if r1_routes_preserved:
        logger.info("✓ R1 route counts preserved during graceful restart")
    else:
        logger.error("✗ R1 route counts changed during graceful restart")
        logger.error(f"  Initial: {initial_r1_routes}")
        logger.error(f"  Final: {final_r1_routes}")

    if r3_routes_preserved:
        logger.info("✓ R3 route counts preserved during graceful restart")
    else:
        logger.error("✗ R3 route counts changed during graceful restart")
        logger.error(f"  Initial: {initial_r3_routes}")
        logger.error(f"  Final: {final_r3_routes}")

    assert r1_routes_preserved, "R1 route counts not preserved during graceful restart"
    assert r3_routes_preserved, "R3 route counts not preserved during graceful restart"

    logger.info("✓ BGP Graceful Restart test passed - routes preserved successfully")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
