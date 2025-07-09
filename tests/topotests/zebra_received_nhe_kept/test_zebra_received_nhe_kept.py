#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_received_nhe_kept.py
#
# Copyright (c) 2025 by Donald Sharp, Nvidia Inc.
#

"""
test_zebra_received_nhe_kept.py: Test of Zebra Next Hop Entry Kept
"""

import json
import sys

import pytest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from munet.testing.util import retry

# pylint: disable=C0413
from lib import topotest


def build_topo(tgen):
    "Build function"

    # Create router r1
    tgen.add_router("r1")

    # Create a switch to connect to r1's interface
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config("frr.conf")

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_zebra_received_nhe_kept():
    "Test that zebra keeps received next hop entries"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    @retry(retry_timeout=30, retry_sleep=0.25)
    def _check_zebra_routes():
        # Get the route information
        route_info = r1.vtysh_cmd("show ip route json")
        route_json = json.loads(route_info)

        # Get the NHG ID for 10.0.0.1
        nhg_id = None
        for prefix, route in route_json.items():
            if prefix == "10.0.0.1/32":
                nhg_id = route[0].get("receivedNexthopGroupId")
                break

        logger.info(
            "Verify all routes 10.0.0.1-.5 have the same NHG ID {}".format(nhg_id)
        )
        for i in range(1, 6):
            prefix = f"10.0.0.{i}/32"
            assert prefix in route_json, f"Route {prefix} not found"
            route = route_json[prefix][0]
            assert (
                "receivedNexthopGroupId" in route
            ), f"Route {prefix} missing receivedNexthopGroupId"
            assert (
                route["receivedNexthopGroupId"] == nhg_id
            ), f"Route {prefix} has different NHG ID"

        # Get the NHG information
        logger.info("Verify NHG {} has refcount of 10".format(nhg_id))
        nhg_info = r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
        nhg_json = json.loads(nhg_info)
        assert nhg_json[str(nhg_id)]["refCount"] == 10, "NHG refcount is not 10"

    assert not _check_zebra_routes()


def test_zebra_received_nhe_kept_remove_routes():
    "Test that zebra updates refcount when routes are removed"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Remove routes 10.0.0.3, 10.0.0.4, and 10.0.0.5")
    # Remove the routes
    for i in range(3, 6):
        r1.vtysh_cmd(
            "configure terminal\n no ip route 10.0.0.{}/32 10.0.0.0\n end".format(i)
        )

    # Wait for zebra to process the route removals
    def check_routes_removed():
        route_info = r1.vtysh_cmd("show ip route json")
        route_json = json.loads(route_info)

        # Check routes 10.0.0.1 and 10.0.0.2 exist
        for i in range(1, 3):
            prefix = f"10.0.0.{i}/32"
            if prefix not in route_json:
                return False

        # Check routes 10.0.0.3 through 10.0.0.5 don't exist
        for i in range(3, 6):
            prefix = f"10.0.0.{i}/32"
            if prefix in route_json:
                return False

        return True

    step("Wait for routes to be removed")
    _, result = topotest.run_and_expect(check_routes_removed, True, count=30, wait=1)
    assert result, "Routes were not properly removed"

    step("Get the route information")
    # Get the route information
    route_info = r1.vtysh_cmd("show ip route json")
    route_json = json.loads(route_info)

    # Get the NHG ID for 10.0.0.1
    nhg_id = None
    for prefix, route in route_json.items():
        if prefix == "10.0.0.1/32":
            nhg_id = route[0].get("receivedNexthopGroupId")
            break

    step("Verify NHG {} has refcount of 2".format(nhg_id))
    # Get the NHG information
    nhg_info = r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
    nhg_json = json.loads(nhg_info)
    assert nhg_json[str(nhg_id)]["refCount"] == 4, "NHG refcount is not 4"


def test_zebra_received_nhe_kept_add_routes():
    "Test that zebra updates refcount when routes are added"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Add routes 10.0.0.3 through 10.0.0.10")
    # Add the routes
    for i in range(3, 11):
        r1.vtysh_cmd(
            "configure terminal\n ip route 10.0.0.{}/32 10.0.0.0\n end".format(i)
        )

    # Wait for zebra to process the route additions
    def check_routes_added():
        route_info = r1.vtysh_cmd("show ip route json")
        route_json = json.loads(route_info)

        # Check all routes 10.0.0.1 through 10.0.0.10 exist
        for i in range(1, 11):
            prefix = f"10.0.0.{i}/32"
            if prefix not in route_json:
                return False
            route = route_json[prefix][0]
            if "receivedNexthopGroupId" not in route:
                return False

        return True

    step("Wait for routes to be added")
    _, result = topotest.run_and_expect(check_routes_added, True, count=30, wait=1)
    assert result, "Routes were not properly added"

    step("Get the route information")
    # Get the route information
    route_info = r1.vtysh_cmd("show ip route json")
    route_json = json.loads(route_info)

    # Get the NHG ID for 10.0.0.1
    nhg_id = None
    for prefix, route in route_json.items():
        if prefix == "10.0.0.1/32":
            nhg_id = route[0].get("receivedNexthopGroupId")
            break

    step("Verify all routes 10.0.0.1-.10 have the same NHG ID {}".format(nhg_id))
    # Verify all routes 10.0.0.1-.10 have the same NHG ID
    for i in range(1, 11):
        prefix = f"10.0.0.{i}/32"
        assert prefix in route_json, f"Route {prefix} not found"
        route = route_json[prefix][0]
        assert (
            "receivedNexthopGroupId" in route
        ), f"Route {prefix} missing receivedNexthopGroupId"
        assert (
            route["receivedNexthopGroupId"] == nhg_id
        ), f"Route {prefix} has different NHG ID"

    step("Verify NHG {} has refcount of 10".format(nhg_id))
    # Get the NHG information
    nhg_info = r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
    nhg_json = json.loads(nhg_info)
    assert nhg_json[str(nhg_id)]["refCount"] == 20, "NHG refcount is not 20"


def test_zebra_received_nhe_kept_remove_all_routes():
    "Test that zebra removes NHG when all routes are removed"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Get the NHG ID before removing routes")
    # Get the route information
    route_info = r1.vtysh_cmd("show ip route 10.0.0.1/32 json")
    route_json = json.loads(route_info)

    # Get the NHG ID for 10.0.0.1
    nhg_id = None
    for prefix, route in route_json.items():
        if prefix == "10.0.0.1/32":
            nhg_id = route[0].get("receivedNexthopGroupId")
            break

    step("Remove all routes 10.0.0.1 through 10.0.0.10")
    # Remove all routes
    for i in range(1, 11):
        r1.vtysh_cmd(
            "configure terminal\n no ip route 10.0.0.{}/32 10.0.0.0\n end".format(i)
        )

    # Wait for zebra to process the route removals
    def check_all_routes_removed():
        route_info = r1.vtysh_cmd("show ip route json")
        route_json = json.loads(route_info)

        # Check no 10.0.0.x routes exist
        for i in range(1, 11):
            prefix = f"10.0.0.{i}/32"
            if prefix in route_json:
                return False

        return True

    step("Wait for all routes to be removed")
    _, result = topotest.run_and_expect(
        check_all_routes_removed, True, count=30, wait=1
    )
    assert result, "Routes were not properly removed"

    step("Get NHG information")
    # Get all NHG information
    nhg_info = r1.vtysh_cmd("show nexthop-group rib json")
    nhg_json = json.loads(nhg_info)

    # Verify the specific NHG we looked up is no longer present
    assert (
        str(nhg_id) not in nhg_json
    ), f"NHG {nhg_id} still exists after removing all routes"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
