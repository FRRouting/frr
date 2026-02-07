#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 NVIDIA Corporation
#               Donald Sharp
#
"""
Test static route cross-vrf nexthop resolution

This test verifies that:
1. A route in the same VRF should NOT be allowed to resolve via itself
   (preventing routing loops)
2. A route in different VRFs SHOULD be allowed to resolve via a prefix
   in another VRF even if the prefix is the same
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
from time import sleep

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


def build_topo(tgen):
    """
    Build simple topology with two routers:
    r1 has two VRFs (vrf_a and vrf_b)
    """
    # Create routers
    tgen.add_router("r1")

    # Create a switch with a link to r1 and r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Setup VRFs on r1
    r1 = tgen.gears["r1"]
    r1.net.add_l3vrf("vrf_a", 100)
    r1.net.add_l3vrf("vrf_b", 200)

    # Load configurations
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_same_vrf_no_self_resolution():
    """
    Test that a route in the same VRF cannot resolve via itself.

    In vrf_a, we attempt to install:
    10.0.0.0/24 via 10.0.0.3

    This should fail because 10.0.0.3 is within 10.0.0.0/24.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Checking that route does NOT resolve via itself in same VRF")

    def _check_route_not_installed():
        """Check that the self-resolving route is NOT installed but valid route is"""
        output = r1.vtysh_cmd("show ip route vrf vrf_a 10.0.0.0/24 json")
        logger.info("show ip route vrf vrf_a 10.0.0.0/24: {}".format(output))

        route_data = json.loads(output)

        # The route should exist since we have a valid route configured
        if "10.0.0.0/24" not in route_data:
            # Route doesn't exist at all - this is acceptable
            return "No Route entry"

        route_entry = route_data["10.0.0.0/24"]

        # Check if there are any nexthops at all
        if not route_entry:
            return "No Route entry"

        # Collect all nexthops across all entries
        all_nexthops = []
        for nh_entry in route_entry:
            if "nexthops" in nh_entry:
                all_nexthops.extend(nh_entry["nexthops"])

        if len(all_nexthops) != 2:
            return "Expected 2 nexthops for route 10.0.0.0/24, found {}".format(
                len(all_nexthops)
            )

        # Check each nexthop
        found_valid_nh = False
        found_invalid_nh = False

        for nh in all_nexthops:
            logger.info("Nexthop: {}".format(nh))
            nh_ip = nh.get("ip")
            is_active = nh.get("active", False)

            if nh_ip == "192.168.1.2":
                # This is the valid nexthop - should be active
                if not is_active:
                    return "Nexthop 192.168.1.2 should be active but is not"
                found_valid_nh = True
            elif nh_ip == "10.0.0.3":
                # This is the self-resolving nexthop - should NOT be active
                if is_active:
                    return "Nexthop 10.0.0.3 is active (should not be - routing loop)"
                found_invalid_nh = True

        if not found_valid_nh:
            return "Did not find expected valid nexthop 192.168.1.2"

        if not found_invalid_nh:
            return "Did not find expected invalid nexthop 10.0.0.3"

        # Everything is correct: 2 nexthops, valid one is active, invalid one is not
        return None

    test_func = functools.partial(_check_route_not_installed)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result


def test_cross_vrf_resolution():
    """
    Test that a route in a different VRF CAN resolve via a prefix in another VRF.

    In vrf_a, we have an active route: 10.0.0.0/24 via 192.168.1.2
    In vrf_b, we install: 10.0.0.0/24 via 10.0.0.3 nexthop-vrf vrf_a

    This should succeed because the nexthop is in a different VRF.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Checking that route CAN resolve via cross-vrf nexthop")

    def _check_route_installed():
        """Check that the cross-vrf route IS installed and active"""
        output = r1.vtysh_cmd("show ip route vrf vrf_b 10.0.0.0/24 json")
        logger.info("show ip route vrf vrf_b 10.0.0.0/24: {}".format(output))

        route_data = json.loads(output)

        # The route should exist
        if "10.0.0.0/24" not in route_data:
            return "Route 10.0.0.0/24 not found in vrf_b"

        route_entry = route_data["10.0.0.0/24"]

        # Check that there is at least one active nexthop
        found_active = False
        for nh_entry in route_entry:
            if "nexthops" in nh_entry:
                for nh in nh_entry["nexthops"]:
                    # Looking for nexthop 10.0.0.3 that goes via vrf_a
                    if nh.get("ip") == "10.0.0.3" and nh.get("active", False):
                        # Also check that it's using vrf_a for resolution
                        if nh.get("vrf") == "vrf_a":
                            found_active = True
                            break
            if found_active:
                break

        if not found_active:
            return "Route 10.0.0.0/24 via 10.0.0.3 vrf_a is not active"

        return None

    test_func = functools.partial(_check_route_installed)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result


def test_cross_vrf_with_different_prefix():
    """
    Test cross-vrf resolution with a completely different prefix.

    In vrf_a, we have: 192.168.1.0/24 (connected)
    In vrf_b, we install: 172.16.0.0/16 via 192.168.1.10 nexthop-vrf vrf_a

    This should work fine as it's cross-vrf and different prefixes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Checking cross-vrf route with different prefix")

    def _check_route_installed():
        """Check that the cross-vrf route with different prefix is installed"""
        output = r1.vtysh_cmd("show ip route vrf vrf_b 172.16.0.0/16 json")
        logger.info("show ip route vrf vrf_b 172.16.0.0/16: {}".format(output))

        route_data = json.loads(output)

        if "172.16.0.0/16" not in route_data:
            return "Route 172.16.0.0/16 not found in vrf_b"

        route_entry = route_data["172.16.0.0/16"]

        found_active = False
        for nh_entry in route_entry:
            if "nexthops" in nh_entry:
                for nh in nh_entry["nexthops"]:
                    if nh.get("ip") == "192.168.1.10" and nh.get("active", False):
                        found_active = True
                        break
            if found_active:
                break

        if not found_active:
            return "Route 172.16.0.0/16 via 192.168.1.10 vrf_a is not active"

        return None

    test_func = functools.partial(_check_route_installed)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
