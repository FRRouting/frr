#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2024 by Nvidia Inc.
# Donald Sharp
#
"""
Test weighted ECMP functionality with single router topology
"""

import os
import sys
import pytest
import json

pytestmark = [pytest.mark.sharpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version


def build_topo(tgen):
    tgen.add_router("r1")

    r1 = tgen.gears["r1"]

    # Create switches for the interfaces
    sw1 = tgen.add_switch("sw1")
    sw2 = tgen.add_switch("sw2")

    # Connect router to switches to create the required interfaces
    sw1.add_link(r1)
    sw2.add_link(r1)


def setup_module(module):
    "Setup topology"
    # Check kernel version - weighted ECMP requires kernel >= 6.12
    result = required_linux_kernel_version("6.12")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >= 6.12")

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, "-s 180000000 --nexthop-weight-16-bit"),
                (TopoRouter.RD_SHARP, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_weighted_ecmp():
    "Test weighted ECMP functionality"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Create a nexthop group with weighted nexthops
    logger.info("Creating nexthop group A with weighted nexthops")

    # Add nexthop group A with different weights
    r1.vtysh_cmd(
        """
        configure terminal
         nexthop-group A
          nexthop 10.0.1.2 r1-eth0 weight 4100000000
          nexthop 10.0.2.2 r1-eth1 weight 2000000000
          nexthop 10.0.1.3 r1-eth0 weight 5
          nexthop 10.0.2.3 r1-eth1 weight 1000000
        """
    )

    # Verify the nexthop group was created using run_and_expect
    logger.info("Verifying nexthop group A configuration")

    def check_weighted_nexthop_group():
        """Check if the weighted nexthop group is properly configured"""
        output = r1.vtysh_cmd("show nexthop-group rib json", isjson=True)

        if not isinstance(output, dict) or "default" not in output:
            return "Default VRF nexthop-group data not found"

        if not isinstance(output["default"], dict):
            return "Default VRF nexthop-group data is not a dict"

        vrf_map = output["default"]

        # Find the nexthop group with multiple nexthops (our weighted group)
        weighted_group = None
        for group_id, group_data in vrf_map.items():
            if group_data.get("nexthopCount", 0) > 1 and group_data.get("type") == "sharp":
                weighted_group = group_data
                break

        if weighted_group is None:
            return "Weighted nexthop group not found"

        if weighted_group["nexthopCount"] != 4:
            return "Expected 4 nexthops, got {}".format(weighted_group["nexthopCount"])

        if not weighted_group.get("valid", False):
            return "Nexthop group is not valid"

        if not weighted_group.get("installed", False):
            return "Nexthop group is not installed"

        # Check that all expected nexthops are present with correct weights
        nexthops = weighted_group["nexthops"]
        expected_nexthops = {
            "10.0.1.2": {"interface": "r1-eth0", "weight": 3985},
            "10.0.2.2": {"interface": "r1-eth1", "weight": 65535},
            "10.0.1.3": {"interface": "r1-eth0", "weight": 8},
            "10.0.2.3": {"interface": "r1-eth1", "weight": 29335},
        }

        found_nexthops = {}
        for nexthop in nexthops:
            ip = nexthop["ip"]
            interface = nexthop["interfaceName"]
            weight = nexthop["weight"]
            found_nexthops[ip] = {"interface": interface, "weight": weight}

        # Verify all expected nexthops are present
        for expected_ip, expected_data in expected_nexthops.items():
            if expected_ip not in found_nexthops:
                return "Nexthop {} not found".format(expected_ip)

            found_data = found_nexthops[expected_ip]
            if found_data["interface"] != expected_data["interface"]:
                return "Interface mismatch for {}: expected {}, got {}".format(
                    expected_ip, expected_data["interface"], found_data["interface"]
                )

            if found_data["weight"] != expected_data["weight"]:
                return "Weight mismatch for {}: expected {}, got {}".format(
                    expected_ip, expected_data["weight"], found_data["weight"]
                )

        return None  # Success

    success, result = topotest.run_and_expect(check_weighted_nexthop_group, None, 30, 1)
    assert success, "Weighted nexthop group verification failed: {}".format(result)

    logger.info(
        "Weighted ECMP test passed - nexthop group A created successfully with correct weights"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
