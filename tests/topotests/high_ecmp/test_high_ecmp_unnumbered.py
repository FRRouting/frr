#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_high_ecmp.py
#
# Copyright (c) 2024 by
# Nvidia Corporation
# Donald Sharp
#
# Copyright (c) 2025 by Soumya Roy, <souroy@nvidia.com>

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
    for switch in range(1, 516):
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

    for rname, router in router_list.items():
        router.cmd("vtysh -f {}/{}/frr_unnumbered_bgp.conf".format(CWD, rname))


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_v6_rtadv():
    tgen = get_topogen()

    # Get the initial interface state and RA interval before making any changes
    interface_output = tgen.gears["r1"].vtysh_cmd("show interface r1-eth200 json")
    interface_data = json.loads(interface_output)

    # Check if the interface exists and get its current state
    interface_section = interface_data.get("r1-eth200", {})
    if not interface_section:
        logger.error("Interface r1-eth200 not found. Test cannot continue.")
        return

    # Get the RA interval
    ra_interval = interface_section.get("ndRouterAdvertisementsIntervalSecs")
    if ra_interval is None:
        # If RA interval isn't found, log a message and exit the test
        logger.error(
            "Could not find RA interval (ndRouterAdvertisementsIntervalSecs) in interface configuration. Test cannot continue."
        )
        return

    logger.info(f"Using RA interval of {ra_interval} seconds")

    # Function to get current RA state - returns the router advertisement sent count
    def _get_ra_state():
        output = tgen.gears["r1"].vtysh_cmd("show interface r1-eth200 json")
        data = json.loads(output)
        return data.get("r1-eth200", {}).get("ndRouterAdvertisementsSent")

    logger.info("Shutdown r1-eth200")
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
      interface r1-eth200
        shutdown
    """
    )

    # Verify interface is down before proceeding
    def _check_interface_down():
        output = tgen.gears["r1"].vtysh_cmd("show interface r1-eth200 json")
        return True if '"administrativeStatus":"down"' in output else False

    _, result = topotest.run_and_expect(_check_interface_down, True, count=10, wait=15)
    assert result is True, "Interface r1-eth200 did not go down after shutdown command"

    # Take snapshots for RA status when interface is down
    ra_sent_count1 = _get_ra_state()

    if ra_sent_count1 is None:
        logger.error("Could not get RA sent count. Test cannot continue.")
        return

    # We need to wait for at least ra_interval + buffer time(1 sec) to avoid
    # situation where any event was delayed or due to any processing delay
    logger.info(f"Waiting another {ra_interval + 1} seconds for RA timer...")
    sleep(ra_interval + 1)
    ra_sent_count2 = _get_ra_state()

    # Verify RA sent count didn't change when interface is down
    assert (
        ra_sent_count1 == ra_sent_count2
    ), f"RA sent count should not have changed when interface is down: was {ra_sent_count1}, now {ra_sent_count2}"

    logger.info("Do no shutdown for r1-eth200")
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
      interface r1-eth200
        no shutdown
    """
    )

    # Verify interface is up before proceeding
    def _check_interface_up():
        output = tgen.gears["r1"].vtysh_cmd("show interface r1-eth200 json")
        return True if '"administrativeStatus":"up"' in output else False

    _, result = topotest.run_and_expect(_check_interface_up, True, count=10, wait=15)
    assert result is True, "Interface r1-eth200 did not go up after no shutdown command"

    # Take snapshots for RA status when interface is up
    ra_sent_count1 = _get_ra_state()

    # We need to wait for at least ra_interval + buffer time(1 sec)
    logger.info(f"Waiting another {ra_interval + 1} seconds for RA timer...")
    sleep(ra_interval + 1)
    ra_sent_count2 = _get_ra_state()

    # Verify RA sent count changed when interface is up (RAs should be sent)
    assert (
        ra_sent_count1 != ra_sent_count2
    ), f"RA sent count should have changed when interface is up: was {ra_sent_count1}, still {ra_sent_count2}"

    logger.info("Remove r1-eth200")
    existing_config = tgen.gears["r1"].vtysh_cmd("show interface r1-eth200")
    tgen.gears["r1"].cmd(
        """
    sudo ip link set dev r1-eth200 down
    """
    )

    # Verify interface is down after ip link set down
    _, result = topotest.run_and_expect(_check_interface_down, True, count=10, wait=15)
    assert result is True, "Interface r1-eth200 did not go down after ip link set down"

    # Get current RA sent count
    ra_sent_count1 = _get_ra_state()

    # Wait for the RA interval
    logger.info(f"Waiting {ra_interval + 1} seconds for RA timer...")
    sleep(ra_interval + 1)

    # Get second RA sent count
    ra_sent_count2 = _get_ra_state()

    # Verify counts are the same when interface is down
    assert (
        ra_sent_count1 == ra_sent_count2
    ), f"RA sent count changed from {ra_sent_count1} to {ra_sent_count2} within {ra_interval + 1} seconds while interface is down"

    tgen.gears["r1"].cmd(
        """
    sudo ip link set dev r1-eth200 up
    """
    )

    # Verify interface is up after ip link set up
    _, result = topotest.run_and_expect(_check_interface_up, True, count=10, wait=15)
    assert result is True, "Interface r1-eth200 did not go up after ip link set up"


def test_bgp_route_cleanup():
    failures = 0
    net = get_topogen().net
    expected_route_count = 2000

    # First, extract IPv4 and IPv6 loopback addresses from r1
    lo_output = net["r1"].cmd("vtysh -c 'show interface lo'")

    # Extract IPv4 and IPv6 addresses from the output
    ipv4_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", lo_output)
    ipv6_match = re.search(r"inet6 ([0-9a-f:]+)/\d+", lo_output)

    if not ipv4_match or not ipv6_match:
        assert False, "Could not find IPv4 or IPv6 address on loopback interface"

    ipv4_nexthop = ipv4_match.group(1)
    ipv6_nexthop = ipv6_match.group(1)

    print(f"\nUsing nexthops: IPv4={ipv4_nexthop}, IPv6={ipv6_nexthop}")

    # Install IPv4 routes
    ipv4_cmd = f"vtysh -c 'sharp install routes 39.99.0.0 nexthop {ipv4_nexthop} {expected_route_count}'"
    net["r1"].cmd(ipv4_cmd)

    # Install IPv6 routes
    ipv6_cmd = f"vtysh -c 'sharp install routes 2100:cafe:: nexthop {ipv6_nexthop} {expected_route_count}'"
    net["r1"].cmd(ipv6_cmd)

    # Initialize actual counts
    ipv4_actual_count = 0
    ipv6_actual_count = 0
    max_attempts = 12  # 60 seconds max (12 * 5)
    attempt = 0

    # Wait until both IPv4 and IPv6 routes are installed
    while (
        ipv4_actual_count != expected_route_count
        or ipv6_actual_count != expected_route_count
    ) and attempt < max_attempts:
        sleep(5)
        attempt += 1

        # Get current IPv4 route count
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )

        # Get current IPv6 route count
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )

        try:
            ipv4_actual_count = int(ipv4_count_str)
        except ValueError:
            ipv4_actual_count = 0

        try:
            ipv6_actual_count = int(ipv6_count_str)
        except ValueError:
            ipv6_actual_count = 0

        print(f"Attempt {attempt}")
        print(f"IPv4 Routes found: {ipv4_actual_count} / {expected_route_count}")
        print(f"IPv6 Routes found: {ipv6_actual_count} / {expected_route_count}")

    # Verify we have the expected number of routes
    if ipv4_actual_count != expected_route_count:
        sys.stderr.write(
            f"Failed to install expected IPv4 routes: got {ipv4_actual_count}, expected {expected_route_count}\n"
        )
        failures += 1
    else:
        print("IPv4 routes successfully installed")

    if ipv6_actual_count != expected_route_count:
        sys.stderr.write(
            f"Failed to install expected IPv6 routes: got {ipv6_actual_count}, expected {expected_route_count}\n"
        )
        failures += 1
    else:
        print("IPv6 routes successfully installed")

    # Stop bgpd in r1 to trigger deletion of routes in r2
    kill_router_daemons(get_topogen(), "r1", ["bgpd"])

    # Initialize variables for post-removal check
    # Start with the original count
    ipv4_final_count = expected_route_count
    ipv6_final_count = expected_route_count
    expected_final_count = 0
    attempt = 0
    max_removal_attempts = 12

    # Wait until both IPv4 and IPv6 routes are fully removed
    while (
        ipv4_final_count != expected_final_count
        or ipv6_final_count != expected_final_count
    ) and attempt < max_removal_attempts:
        sleep(5)
        attempt += 1

        # Get current IPv4 route count
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )

        # Get current IPv6 route count
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )

        try:
            ipv4_final_count = int(ipv4_count_str)
        except ValueError:
            ipv4_final_count = 0

        try:
            ipv6_final_count = int(ipv6_count_str)
        except ValueError:
            ipv6_final_count = 0

        print(f"Route Removal Attempt {attempt}")
        print(f"IPv4 Routes remaining: {ipv4_final_count} / {expected_final_count}")
        print(f"IPv6 Routes remaining: {ipv6_final_count} / {expected_final_count}")

        # If both are already at expected count, break early
        if (
            ipv4_final_count == expected_final_count
            and ipv6_final_count == expected_final_count
        ):
            print("All routes successfully removed")
            break

    # Final verification
    if ipv4_final_count != expected_final_count:
        sys.stderr.write(
            f"Failed to remove IPv4 routes after {max_removal_attempts} attempts: "
            f"{ipv4_final_count} routes still present\n"
        )
        failures += 1
    else:
        print("IPv4 routes successfully removed")

    if ipv6_final_count != expected_final_count:
        sys.stderr.write(
            f"Failed to remove IPv6 routes after {max_removal_attempts} attempts: "
            f"{ipv6_final_count} routes still present\n"
        )
        failures += 1
    else:
        print("IPv6 routes successfully removed")

    start_router_daemons(get_topogen(), "r1", ["bgpd"])
    assert failures == 0, f"Test failed with {failures} failures"


def test_nothing():
    "Do Nothing"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
