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
import functools
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

    logger.info(f"Using nexthops: IPv4={ipv4_nexthop}, IPv6={ipv6_nexthop}")

    # Install IPv4 routes
    ipv4_cmd = f"vtysh -c 'sharp install routes 39.99.0.0 nexthop {ipv4_nexthop} {expected_route_count}'"
    net["r1"].cmd(ipv4_cmd)

    # Install IPv6 routes
    ipv6_cmd = f"vtysh -c 'sharp install routes 2100:cafe:: nexthop {ipv6_nexthop} {expected_route_count}'"
    net["r1"].cmd(ipv6_cmd)

    # Function to check route installation
    def _check_routes_installed():
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )

        ipv4_actual_count = int(ipv4_count_str) if ipv4_count_str.isdigit() else 0
        ipv6_actual_count = int(ipv6_count_str) if ipv6_count_str.isdigit() else 0

        return (
            ipv4_actual_count == expected_route_count
            and ipv6_actual_count == expected_route_count
        )

    # Wait for routes to be installed
    test_func = functools.partial(_check_routes_installed)
    success, result = topotest.run_and_expect(test_func, True, count=12, wait=5)

    if not success:
        # Get final counts for error reporting
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )
        ipv4_actual = int(ipv4_count_str) if ipv4_count_str.isdigit() else 0
        ipv6_actual = int(ipv6_count_str) if ipv6_count_str.isdigit() else 0

        if ipv4_actual != expected_route_count:
            sys.stderr.write(
                f"Failed to install expected IPv4 routes: got {ipv4_actual}, expected {expected_route_count}\n"
            )
            failures += 1
        if ipv6_actual != expected_route_count:
            sys.stderr.write(
                f"Failed to install expected IPv6 routes: got {ipv6_actual}, expected {expected_route_count}\n"
            )
            failures += 1
    else:
        logger.info("Routes successfully installed")

    # Configure BGP timers for faster convergence
    logger.info("Setting BGP keepalive=3, hold=10 for faster convergence")

    # Configure BGP timers on both routers
    for router_name in ["r1", "r2"]:
        router = net[router_name]
        timer_config = ["conf", "router bgp", "timers bgp 3 10", "exit", "exit"]

        cmd = "vtysh"
        for config_line in timer_config:
            cmd += f' -c "{config_line}"'

        router.cmd(cmd)

    # Clear BGP sessions on r2 to make timer changes effective
    net["r2"].cmd('vtysh -c "clear bgp *"')

    # Function to check if BGP sessions are established
    def _check_bgp_timers_applied():
        bgp_summary = net["r1"].cmd('vtysh -c "show bgp summary json"')
        summary_data = json.loads(bgp_summary)
        ipv4_peers = summary_data.get("ipv4Unicast", {}).get("peers", {})

        established_count = 0
        for peer_intf, peer_info in ipv4_peers.items():
            if peer_info.get("state") == "Established":
                established_count += 1

        return established_count > 0

    # Wait for BGP sessions to stabilize with new timers
    test_func = functools.partial(_check_bgp_timers_applied)
    success_timers, _ = topotest.run_and_expect(test_func, True, count=20, wait=2)

    if not success_timers:
        logger.info("Warning: BGP sessions may still be converging after timer change")

    # Test interface shutdown/restoration
    logger.info("Testing interface shutdown/restoration")

    # Known interfaces: r1-eth0 to r1-eth514
    interfaces = [f"r1-eth{i}" for i in range(515)]

    # Phase 1: Shutdown all interfaces
    for interface in interfaces:
        net["r1"].cmd(f"ip link set {interface} down")

    # Define test functions for route checking
    def _check_ipv4_routes_removed():
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        count = int(ipv4_count_str) if ipv4_count_str.isdigit() else 0
        return count == 0

    def _check_ipv6_routes_removed():
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )
        count = int(ipv6_count_str) if ipv6_count_str.isdigit() else 0
        return count == 0

    # Wait for IPv4 routes to be removed
    test_func = functools.partial(_check_ipv4_routes_removed)
    success_ipv4, _ = topotest.run_and_expect(test_func, True, count=15, wait=2)

    if not success_ipv4:
        sys.stderr.write("Interface down test failed - IPv4 routes not removed\n")
        failures += 1

    # Wait for IPv6 routes to be removed
    test_func = functools.partial(_check_ipv6_routes_removed)
    success_ipv6, _ = topotest.run_and_expect(test_func, True, count=15, wait=2)

    if not success_ipv6:
        sys.stderr.write("Interface down test failed - IPv6 routes not removed\n")
        failures += 1

    # Phase 2: Bring interfaces back up
    for interface in interfaces:
        net["r1"].cmd(f"ip link set {interface} up")

    # Define test functions for route restoration checking
    def _check_ipv4_routes_restored():
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        count = int(ipv4_count_str) if ipv4_count_str.isdigit() else 0
        return count == expected_route_count

    def _check_ipv6_routes_restored():
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )
        count = int(ipv6_count_str) if ipv6_count_str.isdigit() else 0
        return count == expected_route_count

    # Wait for IPv4 routes to be restored
    test_func = functools.partial(_check_ipv4_routes_restored)
    success_ipv4_restore, _ = topotest.run_and_expect(test_func, True, count=30, wait=3)

    if not success_ipv4_restore:
        sys.stderr.write("Interface restore test failed - IPv4 routes not restored\n")
        failures += 1

    # Wait for IPv6 routes to be restored
    test_func = functools.partial(_check_ipv6_routes_restored)
    success_ipv6_restore, _ = topotest.run_and_expect(test_func, True, count=30, wait=3)

    if not success_ipv6_restore:
        sys.stderr.write("Interface restore test failed - IPv6 routes not restored\n")
        failures += 1

    # BGP Graceful Restart test with interface down on r2
    logger.info("Testing BGP Graceful Restart")

    # Enable BGP Graceful Restart on r2
    gr_config_commands = ["conf", "router bgp", "bgp graceful-restart", "exit", "exit"]

    gr_cmd = "vtysh"
    for config_line in gr_config_commands:
        gr_cmd += f' -c "{config_line}"'

    net["r2"].cmd(gr_cmd)
    net["r2"].cmd('vtysh -c "clear bgp *"')

    # Function to check if GR is enabled
    def _check_gr_enabled_r2():
        neighbor_output = net["r2"].cmd('vtysh -c "show bgp neighbors r2-eth200"')
        return "Local GR Mode: Restart*" in neighbor_output

    # Wait for GR configuration to take effect
    test_func = functools.partial(_check_gr_enabled_r2)
    topotest.run_and_expect(test_func, True, count=5, wait=1)

    # Get list of interfaces on r2
    r2_interfaces = [f"r2-eth{i}" for i in range(515)]

    # Phase 1: Shutdown interfaces on r2
    for interface in r2_interfaces:
        net["r2"].cmd(f"ip link set {interface} down")

    # Wait for routes to be deleted (even with GR, routes should be deleted when interfaces go down)
    test_func = functools.partial(_check_ipv4_routes_removed)
    success_ipv4_deleted, _ = topotest.run_and_expect(test_func, True, count=10, wait=1)

    if not success_ipv4_deleted:
        sys.stderr.write(
            "GR interface down test failed - IPv4 routes not deleted from r2\n"
        )
        failures += 1

    test_func = functools.partial(_check_ipv6_routes_removed)
    success_ipv6_deleted, _ = topotest.run_and_expect(test_func, True, count=10, wait=1)

    if not success_ipv6_deleted:
        sys.stderr.write(
            "GR interface down test failed - IPv6 routes not deleted from r2\n"
        )
        failures += 1

    # Phase 2: Bring r2 interfaces back up
    for interface in r2_interfaces:
        net["r2"].cmd(f"ip link set {interface} up")

    # Wait for route restoration
    test_func = functools.partial(_check_ipv4_routes_restored)
    success_ipv4_restore, _ = topotest.run_and_expect(test_func, True, count=30, wait=3)

    if not success_ipv4_restore:
        sys.stderr.write(
            "GR interface recovery test failed - IPv4 routes not restored on r2\n"
        )
        failures += 1

    test_func = functools.partial(_check_ipv6_routes_restored)
    success_ipv6_restore, _ = topotest.run_and_expect(test_func, True, count=30, wait=3)

    if not success_ipv6_restore:
        sys.stderr.write(
            "GR interface recovery test failed - IPv6 routes not restored on r2\n"
        )
        failures += 1

    # Stop bgpd in r1 to trigger deletion of routes in r2
    kill_router_daemons(get_topogen(), "r1", ["bgpd"])

    # Function to check final route removal
    def _check_final_routes_removed():
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )

        ipv4_count = int(ipv4_count_str) if ipv4_count_str.isdigit() else 0
        ipv6_count = int(ipv6_count_str) if ipv6_count_str.isdigit() else 0

        return ipv4_count == 0 and ipv6_count == 0

    # Wait for final route removal
    test_func = functools.partial(_check_final_routes_removed)
    success_final, _ = topotest.run_and_expect(test_func, True, count=12, wait=5)

    if not success_final:
        # Get final counts for error reporting
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )
        ipv4_final = int(ipv4_count_str) if ipv4_count_str.isdigit() else 0
        ipv6_final = int(ipv6_count_str) if ipv6_count_str.isdigit() else 0

        if ipv4_final != 0:
            sys.stderr.write(
                f"Failed to remove IPv4 routes: {ipv4_final} routes still present\n"
            )
            failures += 1
        if ipv6_final != 0:
            sys.stderr.write(
                f"Failed to remove IPv6 routes: {ipv6_final} routes still present\n"
            )
            failures += 1

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
