#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP redistribute processing.

Cover core redistribution scenarios:
1) ADD for a new redistribute route
2) ADD for an existing route:
   2a) same type (attribute update)
   2b) different types
   2c) attribute change causes route-map permit -> deny
3) ADD for an existing route, but denied by route-map
4) DELETE an existing route (route deleted)
5) Route-map change while route exists:
   5a) permit -> deny
   5b) deny -> permit
6) Redistribute config change:
   6a) no redistribute <type>
   6b) redistribute <type> added
7) Multiple redistribute types
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


def build_topo(tgen):
    """Build the topology: single router r1."""
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_bgp_route(r1, prefix, expected_present):
    """Check if a route is present/absent in BGP."""
    output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
    routes = output.get("routes", {})
    present = prefix in routes

    if expected_present:
        if not present:
            return f"Route {prefix} not found in BGP"
        return None
    else:
        if present:
            return f"Route {prefix} still present in BGP"
        return None


def test_1_add_new_redistribute_route():
    """Test 1: ADD for a new redistribute route."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("1. Verify initial static route 10.0.0.0/24 is redistributed into BGP")

    def _check():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "Static route not redistributed into BGP"


def test_2a_add_existing_route_same_type():
    """Test 2a: ADD for an existing route with same type (attribute update)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("2a. Add static route with different metric, verify BGP route updates")

    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.0/24 Null0
        ip route 10.0.0.0/24 Null0 tag 100
        end
        """
    )

    def _check():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.0/24 json"))
        paths = output.get("paths", [])
        if not paths:
            return "Route 10.0.0.0/24 not found"
        if paths[0].get("tag") == 100:
            return None
        return f"Tag not updated, got {paths[0].get('tag')}"

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "Route attribute not updated"


def test_2b_add_existing_route_different_type():
    """Test 2b: ADD for an existing route with different type."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("2b. Enable redistribute connected, add connected route for same prefix")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute connected
        exit-address-family
        exit
        interface lo
        ip address 10.0.0.1/24
        end
        """
    )

    def _check():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.0/24 json"))
        paths = output.get("paths", [])
        if not paths:
            return "Route 10.0.0.0/24 not found"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "Route not present after type change"

    r1.vtysh_cmd(
        """
        configure terminal
        interface lo
        no ip address 10.0.0.1/24
        end
        """
    )


def test_2c_attribute_change_causes_routemap_deny():
    """Test 2c: Route attribute change causes route-map to deny.

    A route with tag 100 is redistributed with a route-map that permits
    tag 100. When the route's tag changes to 200, the route-map no longer
    matches and the route should be withdrawn from BGP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("2c-1. Setup route-map that permits only tag 100")

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TAG100 permit 10
        match tag 100
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TAG100
        end
        """
    )

    step("2c-2. Verify route with tag 100 is in BGP")

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route with tag 100 should be in BGP"

    step("2c-3. Change route tag from 100 to 200")

    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.0/24 Null0 tag 100
        ip route 10.0.0.0/24 Null0 tag 200
        end
        """
    )

    step("2c-4. Verify route is withdrawn (tag 200 not permitted)")

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn (tag 200 not permitted by route-map)"

    step("2c-5. Cleanup: restore route with tag 100 and remove route-map")

    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.0/24 Null0 tag 200
        ip route 10.0.0.0/24 Null0 tag 100
        router bgp 65001
        address-family ipv4 unicast
        redistribute static
        end
        """
    )

    def _check_restored():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_restored, None, count=30, wait=1)
    assert result is None, "Route should be restored after cleanup"


def test_3_add_denied_by_routemap():
    """Test 3: ADD for an existing route, but denied by route-map."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("3a. Apply route-map to deny the static route")

    r1.vtysh_cmd(
        """
        configure terminal
        ip prefix-list PL_DENY seq 5 permit 10.0.0.0/24
        route-map RM_DENY deny 10
        match ip address prefix-list PL_DENY
        exit
        route-map RM_DENY permit 20
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_DENY
        end
        """
    )

    def _check():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "Route not withdrawn after route-map deny"

    step("3b. Cleanup: remove route-map from redistribute config")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no redistribute static route-map RM_DENY
        redistribute static
        end
        """
    )

    def _check_back():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_back, None, count=30, wait=1)
    assert result is None, "Route not restored after cleanup"


def test_4_delete_existing_route():
    """Test 4: DELETE an existing route."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("4. Delete static route, verify withdrawn from BGP")

    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.0/24 Null0 tag 100
        end
        """
    )

    def _check():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "Route not withdrawn after deletion"

    r1.vtysh_cmd(
        """
        configure terminal
        ip route 10.0.0.0/24 Null0
        end
        """
    )

    def _check_back():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_back, None, count=30, wait=1)
    assert result is None, "Route not restored"


def test_5a_routemap_permit_to_deny():
    """Test 5a: Route-map change from permit to deny."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("5a. Apply permit route-map, then change to deny")

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_PERMIT permit 10
        match ip address prefix-list PL_DENY
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_PERMIT
        end
        """
    )

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should be present with permit route-map"

    r1.vtysh_cmd(
        """
        configure terminal
        no route-map RM_PERMIT permit 10
        route-map RM_PERMIT deny 10
        match ip address prefix-list PL_DENY
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn after permit->deny"


def test_5b_routemap_deny_to_permit():
    """Test 5b: Route-map change from deny to permit."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("5b. Change route-map from deny to permit")

    r1.vtysh_cmd(
        """
        configure terminal
        no route-map RM_PERMIT deny 10
        route-map RM_PERMIT permit 10
        match ip address prefix-list PL_DENY
        end
        """
    )

    def _check():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "Route should be added after deny->permit"


def test_6a_no_redistribute():
    """Test 6a: no redistribute <type> withdraws routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("6a. Remove redistribute static, verify route withdrawn")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static
        end
        """
    )

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should be present"

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no redistribute static
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn after no redistribute"


def test_6b_redistribute_added():
    """Test 6b: redistribute <type> added redistributes existing routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("6b. Add redistribute static back, verify route appears")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static
        end
        """
    )

    def _check():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "Route should appear after redistribute added"


def test_7_multiple_redistribute_types():
    """Test 7: Multiple redistribute types configured."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("7. Configure both redistribute static and connected")

    r1.vtysh_cmd(
        """
        configure terminal
        ip route 10.1.0.0/24 Null0
        interface lo
        ip address 10.2.0.1/24
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static
        redistribute connected
        end
        """
    )

    def _check_both():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        routes = output.get("routes", {})
        missing = []
        if "10.1.0.0/24" not in routes:
            missing.append("10.1.0.0/24 (static)")
        if "10.2.0.0/24" not in routes:
            missing.append("10.2.0.0/24 (connected)")
        if missing:
            return f"Missing routes: {', '.join(missing)}"
        return None

    _, result = topotest.run_and_expect(_check_both, None, count=30, wait=1)
    assert result is None, "Both static and connected routes should be present"

    step("7. Remove redistribute connected, static should remain")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no redistribute connected
        end
        """
    )

    def _check_static_only():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        routes = output.get("routes", {})
        if "10.1.0.0/24" not in routes:
            return "Static route 10.1.0.0/24 missing"
        if "10.2.0.0/24" in routes:
            return "Connected route 10.2.0.0/24 should be gone"
        return None

    _, result = topotest.run_and_expect(_check_static_only, None, count=30, wait=1)
    assert result is None, "Only static route should remain"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
