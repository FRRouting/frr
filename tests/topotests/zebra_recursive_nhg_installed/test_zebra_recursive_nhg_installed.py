#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_recursive_nhg_installed.py
#
# Copyright (c) 2024 by Donald Sharp, Nvidia Inc.
#

"""
test_zebra_recursive_nhg_installed.py: Test recursive next-hop group installation
"""

import os
import sys
import json
import pytest
import functools

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step


pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    "Sets up the pytest environment"
    # Single router with one interface
    topodef = {"r1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_recursive_nhg_installed():
    "Test recursive next-hop group installation"
    step("Test recursive next-hop group installation")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # Check that routes are installed
    step("Check that routes are installed")

    def check_routes_installed():
        output = r1.vtysh_cmd("show ip route json")
        output_json = json.loads(output)

        # Check 10.1.1.1/32 route
        if "10.1.1.1/32" not in output_json:
            return "10.1.1.1/32 route not found"
        route1 = output_json["10.1.1.1/32"][0]
        if not route1.get("installed", False):
            return "10.1.1.1/32 route not installed"

        # Check 10.1.1.2/32 route
        if "10.1.1.2/32" not in output_json:
            return "10.1.1.2/32 route not found"
        route2 = output_json["10.1.1.2/32"][0]
        if not route2.get("installed", False):
            return "10.1.1.2/32 route not installed"

        return None

    _, result = topotest.run_and_expect(check_routes_installed, None, count=30, wait=1)
    assert result is None, f"Routes not installed: {result}"


def test_zebra_recursive_nhg_nexthop_group():
    "Test recursive next-hop group ID"
    step("Test recursive next-hop group ID")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    def check_nexthop_group_id():
        output = r1.vtysh_cmd("show ip route json")
        output_json = json.loads(output)

        # Get the nexthop group ID for 10.1.1.1/32 route
        if "10.1.1.1/32" not in output_json:
            return "10.1.1.1/32 route not found"
        route1 = output_json["10.1.1.1/32"][0]
        nhg_id = route1["nexthopGroupId"]

        # Check that 10.1.1.2/32 route uses the same nexthop group ID
        if "10.1.1.2/32" not in output_json:
            return "10.1.1.2/32 route not found"
        route2 = output_json["10.1.1.2/32"][0]
        if "installedNexthopGroupId" not in route2:
            return "10.1.1.2/32 route has no nexthop group ID"
        if route2["installedNexthopGroupId"] != nhg_id:
            return f"10.1.1.2/32 route nexthop group ID {route2['installedNexthopGroupId']} does not match 10.1.1.1/32 route ID {nhg_id}"
        else:
            logger.info(
                f"10.1.1.2/32 route Installed Nexthop group ID {route2['installedNexthopGroupId']} matches 10.1.1.1/32 route NHG ID {nhg_id}"
            )

        return None

    _, result = topotest.run_and_expect(check_nexthop_group_id, None, count=30, wait=1)
    assert result is None, f"Nexthop group ID mismatch: {result}"
