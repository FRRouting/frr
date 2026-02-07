#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_high_ecmp.py
#
# Copyright (c) 2025 by
# Nvidia Corporation
# Donald Sharp
#

"""
test_high_ecmp.py: Testing two routers with 256 interfaces and BGP setup
                   on it.

"""

import os
import re
import sys
import pytest
import json
from time import sleep

from lib.common_config import (
    kill_router_daemons,
    start_router_daemons,
)

pytestmark = [pytest.mark.bgpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

# Required to instantiate the topology builder class.

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Let's create 257 interfaces between the two switches
    for switch in range(1, 129):
        switch = tgen.add_switch("sw{}".format(switch))
        switch.add_link(r1)
        switch.add_link(r2)


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, "-s 180000000"),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_SHARP, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_OSPF, None),
                (TopoRouter.RD_OSPF6, None),
                (TopoRouter.RD_PIM, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_bgp_route_install_r1():
    failures = 0
    tgen = get_topogen()
    net = tgen.net
    expected_route_count = 2000

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Test that BGP routes are installed on r1")
    # First, extract IPv4 from r1
    lo_output = net["r1"].cmd("vtysh -c 'show interface lo'")

    # Extract IPv4 from the output
    ipv4_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", lo_output)

    if not ipv4_match:
        assert False, "Could not find IPv4 address on loopback interface"

    ipv4_nexthop = ipv4_match.group(1)

    print(f"\nUsing nexthops: IPv4={ipv4_nexthop}")

    # Install IPv4 routes
    ipv4_cmd = f"vtysh -c 'sharp install routes 39.99.0.0 nexthop {ipv4_nexthop} {expected_route_count}'"
    net["r1"].cmd(ipv4_cmd)

    # Initialize actual counts
    ipv4_actual_count = 0
    max_attempts = 12  # 60 seconds max (12 * 5)
    attempt = 0

    # Wait until IPv4 routes are installed
    while (ipv4_actual_count != expected_route_count) and attempt < max_attempts:
        sleep(5)
        attempt += 1

        # Get current IPv4 route count
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )

        try:
            ipv4_actual_count = int(ipv4_count_str)
        except ValueError:
            ipv4_actual_count = 0

        print(f"Attempt {attempt}")
        print(f"IPv4 Routes found: {ipv4_actual_count} / {expected_route_count}")

    # Verify we have the expected number of routes
    if ipv4_actual_count != expected_route_count:
        sys.stderr.write(
            f"Failed to install expected IPv4 routes: got {ipv4_actual_count}, expected {expected_route_count}\n"
        )
        failures += 1
    else:
        print("IPv4 routes successfully installed")


def test_bgp_established():
    "Test that BGP session between r1 and r2 is established"
    tgen = get_topogen()
    net = tgen.net

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Test that BGP session between r1 and r2 is established")
    # Create a function to check BGP peer status on r1
    def check_bgp_peer():
        output = net["r2"].cmd('vtysh -c "show bgp ipv4 uni summary json"')
        try:
            bgp_summary = json.loads(output)
            # Check if r2's peer is in Established state
            # logger.info(f"BGP summary: {bgp_summary}")
            logger.info("Failed peers: {}".format(bgp_summary["failedPeers"]))
            if bgp_summary.get("failedPeers") != 0:
                logger.info(f"Failed peers: {bgp_summary.get('failedPeers')}")
                return False

            # Check that each peer has received 2000 prefixes
            for peer, peer_data in bgp_summary.get("peers", {}).items():
                pfx_rcvd = peer_data.get("pfxRcd", 0)
                if pfx_rcvd != 2000:
                    logger.info(
                        f"Peer {peer} has received {pfx_rcvd} prefixes, expected 2000"
                    )
                    return False

            return True
        except (json.JSONDecodeError, KeyError):
            return False

    # Use run_and_expect to wait for BGP session to be established
    success, result = topotest.run_and_expect(
        check_bgp_peer,
        True,
        count=60,  # Wait up to 60 tries
        wait=1,  # 1 second between tries
    )

    assert success, "BGP session between r1 and r2 failed to establish"


def test_bgp_routes_on_r2():
    "Test that routes installed on r1 are properly received by r2"
    tgen = get_topogen()
    net = tgen.net
    expected_route_count = 2000

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Test that routes installed on r1 are properly received by r2")
    # Create a function to check the route count on r2
    def check_r2_routes():
        route_count = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        try:
            return int(route_count)
        except ValueError:
            return 0

    # Use run_and_expect to wait for the routes to appear on r2
    success, result = topotest.run_and_expect(
        check_r2_routes,
        expected_route_count,
        count=60,  # Wait up to 60 tries
        wait=1,  # 1 second between tries
    )

    assert success, f"Expected {expected_route_count} routes on r2 but found {result}"

    step("Test that all routes are installed in the FIB")
    # Create a function to check the FIB route count
    def check_fib_routes():
        output = net["r2"].cmd('vtysh -c "show ip route summary"')
        try:
            # Extract the eBGP route count from the summary
            for line in output.splitlines():
                if "ebgp" in line:
                    # Split on whitespace and get the FIB count (last number)
                    parts = line.split()
                    fib_count = int(parts[-1])
                    logger.info(f"eBGP FIB route count: {fib_count}")
                    return fib_count
            return 0
        except (ValueError, IndexError):
            return 0

    # Use run_and_expect to wait for all routes to be installed in the FIB
    success, result = topotest.run_and_expect(
        check_fib_routes,
        expected_route_count,
        count=60,  # Wait up to 60 tries
        wait=1,  # 1 second between tries
    )

    assert success, f"Expected {expected_route_count} routes in FIB but found {result}"

    step("Verify that the nexthop group for 39.99.0.0 routes has 128 members")
    # Create a function to check the nexthop group member count
    def check_nhg_members():
        output = net["r2"].cmd('vtysh -c "show ip route 39.99.0.0 json"')
        try:
            route_data = json.loads(output)
            # Find the first 39.99.0.0 route to get its nexthop group ID
            nhg_id = None
            for prefix, routes in route_data.items():
                if prefix.startswith("39.99.0.0"):
                    for route in routes:
                        if route.get("protocol") == "bgp":
                            nhg_id = route.get("nexthopGroupId")
                            break
                    if nhg_id:
                        break

            if not nhg_id:
                logger.info("Could not find nexthop group ID for 39.99.0.0 routes")
                return -1

            # Get the nexthop group details
            nhg_output = net["r2"].cmd(
                f'vtysh -c "show nexthop-group rib {nhg_id} json"'
            )
            nhg_data = json.loads(nhg_output)

            # The nexthop group data is nested under the nhg_id key
            nhg_info = nhg_data.get(str(nhg_id), {})
            member_count = len(nhg_info.get("nexthops", []))
            logger.info(f"Nexthop group {nhg_id} has {member_count} members")
            if (member_count != 128):
                logger.info(net["r2"].cmd(f'vtysh -c "show nexthop-group rib {nhg_id}" -c "show bgp ipv4 uni" -c "show ip route 33.99.0.0 nexthop-group"'))
            return member_count
        except (json.JSONDecodeError, KeyError) as e:
            logger.info(f"Error checking nexthop group members: {e}")
            return -1

    # Use run_and_expect to verify the nexthop group has 128 members
    success, result = topotest.run_and_expect(
        check_nhg_members,
        128,  # Expect 128 members
        count=60,  # Wait up to 60 tries
        wait=1,  # 1 second between tries
    )

    assert success, f"Expected 128 nexthop group members but found {result}"


def test_bgp_shutdown_some_links():
    "Test that shutting down interfaces r2-eth30-49 results in 20 failed BGP peers"
    tgen = get_topogen()
    net = tgen.net
    first_nhg = None

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Test that all BGP routes are using the same nexthop group")

    logger.info(net["r2"].cmd('vtysh -c "show ip route bgp nexthop"'))
    logger.info(net["r2"].cmd('vtysh -c "show nexthop-group rib"'))

    # First check that all BGP routes are using the same nexthop group
    def check_nhg_consistency():
        nonlocal first_nhg
        output = net["r2"].cmd('vtysh -c "show ip route bgp json"')
        try:
            nhg_data = json.loads(output)
            # logger.info(f"Nexthop group data: {nhg_data}")

            for prefix, routes in nhg_data.items():
                for route in routes:
                    if route.get("protocol") == "bgp":
                        current_nhg = route.get("nexthopGroupId")
                        if first_nhg is None:
                            first_nhg = current_nhg
                            if not first_nhg:
                                logger.info("First BGP route has no nexthop group")
                                return False
                        elif current_nhg != first_nhg:
                            logger.info(
                                f"Found different nexthop groups: {first_nhg} vs {current_nhg}"
                            )
                            return False

            if first_nhg is None:
                logger.info("No BGP routes found")
                return False

            logger.info(f"All BGP routes using nexthop group: {first_nhg}")
            return True
        except json.JSONDecodeError:
            logger.error("Failed to parse nexthop group data")
            return False

    # Use run_and_expect to verify nexthop group consistency
    success, result = topotest.run_and_expect(
        check_nhg_consistency,
        True,
        count=60,
        wait=1,
    )

    assert success, "BGP routes are not using the same nexthop group"

    # Shutdown interfaces r2-eth30 through r2-eth49
    step("Shutdown interfaces r2-eth30 through r2-eth49")
    for i in range(30, 50):
        net["r2"].cmd(f"ip link set r2-eth{i} down")

    step("Test that 20 BGP peers are failed")
    # Create a function to check BGP peer status on r2
    def check_failed_peers():
        output = net["r2"].cmd('vtysh -c "show bgp ipv4 uni summary json"')
        try:
            bgp_summary = json.loads(output)
            # failed_peers = bgp_summary.get("failedPeers", 0)
            failed_peers = 0
            # Check that peers r2-eth[30-49] are not in Established or Clearing state
            for peer, peer_data in bgp_summary.get("peers", {}).items():
                # Check if peer name matches r2-eth[30-49]
                if peer.startswith("r2-eth"):
                    try:
                        eth_num = int(peer.split("r2-eth")[1])
                        if 30 <= eth_num <= 49:
                            state = peer_data.get("state", "")
                            if state in ["Established", "Clearing"]:
                                logger.info(f"Peer {peer} is in {state} state")
                                return -1
                            else:
                                failed_peers += 1
                    except (ValueError, IndexError):
                        continue

            logger.info(f"Current failed peers: {failed_peers}")
            return failed_peers
        except (json.JSONDecodeError, KeyError):
            return -1

    # Use run_and_expect to wait for exactly 20 failed peers
    success, result = topotest.run_and_expect(
        check_failed_peers,
        20,  # Expect exactly 20 failed peers
        count=60,  # Wait up to 60 tries
        wait=1,  # 1 second between tries
    )

    assert success, f"Expected 20 failed BGP peers but found {result}"

    step("Verify that the nexthop group ID hasn't changed")
    # Verify that the nexthop group ID hasn't changed
    def verify_nhg_unchanged():
        output = net["r2"].cmd('vtysh -c "show ip route bgp json"')
        try:
            nhg_data = json.loads(output)
            for prefix, routes in nhg_data.items():
                for route in routes:
                    if route.get("protocol") == "bgp":
                        current_nhg = route.get("nexthopGroupId")
                        if current_nhg != first_nhg:
                            logger.info(
                                f"Nexthop group changed from {first_nhg} to {current_nhg}, trying again"
                            )
                            return False
            return True
        except json.JSONDecodeError:
            logger.error("Failed to parse nexthop group data")
            return False

    # Use run_and_expect to verify nexthop group consistency
    success, result = topotest.run_and_expect(
        verify_nhg_unchanged,
        True,
        count=60,
        wait=1,
    )

    assert success, "Nexthop group ID changed after interface shutdowns"

    step("Bring interfaces r2-eth30 through r2-eth49 back up")
    # Bring interfaces r2-eth30 through r2-eth49 back up
    for i in range(30, 50):
        net["r2"].cmd(f"ip link set r2-eth{i} up")

    step("Test that all BGP peers are established")
    # Create a function to check that all BGP peers are established
    def check_all_peers_established():
        output = net["r2"].cmd('vtysh -c "show bgp ipv4 uni summary json"')
        try:
            bgp_summary = json.loads(output)
            failed_peers = bgp_summary.get("failedPeers", 0)
            logger.info(f"Current failed peers: {failed_peers}")

            # Check that each peer has received 2000 prefixes
            for peer, peer_data in bgp_summary.get("peers", {}).items():
                pfx_rcvd = peer_data.get("pfxRcd", 0)
                if pfx_rcvd != 2000:
                    logger.info(
                        f"Peer {peer} has received {pfx_rcvd} prefixes, expected 2000"
                    )
                    return -1

            return failed_peers
        except (json.JSONDecodeError, KeyError):
            return -1

    # Use run_and_expect to wait for all peers to be established
    success, result = topotest.run_and_expect(
        check_all_peers_established,
        0,  # Expect 0 failed peers
        count=60,  # Wait up to 60 tries
        wait=1,  # 1 second between tries
    )

    assert success, f"Expected 0 failed BGP peers but found {result}"

    step("Verify that the original nexthop group is still being used")
    # Final verification that the original nexthop group is still being used
    def verify_final_nhg():
        output = net["r2"].cmd('vtysh -c "show ip route bgp json"')
        try:
            nhg_data = json.loads(output)
            for prefix, routes in nhg_data.items():
                for route in routes:
                    if route.get("protocol") == "bgp":
                        current_nhg = route.get("nexthopGroupId")
                        if current_nhg != first_nhg:
                            logger.error(
                                f"Nexthop group changed from {first_nhg} to {current_nhg}"
                            )
                            return False
            logger.info(
                f"All BGP routes still using original nexthop group: {first_nhg}"
            )
            return True
        except json.JSONDecodeError:
            logger.error("Failed to parse nexthop group data")
            return False

    # Use run_and_expect to verify final nexthop group consistency
    success, result = topotest.run_and_expect(
        verify_final_nhg,
        True,
        count=60,
        wait=1,
    )

    assert success, "Nexthop group ID changed after interfaces were brought back up"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
