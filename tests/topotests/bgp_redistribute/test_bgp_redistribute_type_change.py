#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP redistribute with route type changes in zebra RIB.

When zebra's RIB has multiple route sources for the same prefix, the
selected (best) route can change based on administrative distance (AD).
For example, static routes have AD 1 by default, while OSPF external
routes have AD 110. When a lower-AD route arrives, it replaces the
previous best route in the RIB.

BGP redistribute must handle these transitions correctly:
- When the selected route type matches the redistribute config, it
  should be in BGP
- When the selected route type does NOT match (e.g., OSPF selected but
  only "redistribute static" configured), the route should NOT be in BGP
- When the route type changes back (e.g., OSPF withdrawn, static
  re-selected), BGP must re-redistribute the route

Test scenarios:
1) test_1: Static route redistributed into BGP. OSPF route arrives with
   better AD and replaces static in RIB. When OSPF is withdrawn, static
   should be re-selected and re-redistributed into BGP.

2) test_2: Only "redistribute static" is configured. When OSPF route is
   selected (better AD), the route should NOT appear in BGP since the
   selected type doesn't match. When OSPF is withdrawn and static
   becomes selected, it should then be redistributed.

3) test_3: Both "redistribute static" and "redistribute ospf" configured
   with different prefixes. Verifies that multiple redistribute configs
   work independently without interference.
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

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.staticd]


def build_topo(tgen):
    """Build the topology: two routers r1 and r2 connected via OSPF."""
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # r1 configuration
    r1 = tgen.gears["r1"]
    r1.load_frr_config(os.path.join(CWD, "r1/frr_ospf.conf"))

    # r2 configuration
    r2 = tgen.gears["r2"]
    r2.load_frr_config(os.path.join(CWD, "r2/frr_ospf.conf"))

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


def get_selected_route(routes):
    """Find the selected route from a list of routes in JSON output."""
    for route in routes:
        if route.get("selected", False):
            return route
    return routes[0] if routes else None


def test_1_ospf_replaces_static_then_withdrawn():
    """
    Test route type transition: static -> OSPF -> static.

    Setup:
    - r1 has static route 10.99.0.0/24 with AD 200 (configured in frr_ospf.conf)
    - r1 has "redistribute static" and "redistribute ospf" configured
    - r1 and r2 are OSPF neighbors

    Scenario:
    1. Static route 10.99.0.0/24 (AD 200) is redistributed into BGP
    2. r2 redistributes connected 10.99.0.1/24 into OSPF
    3. OSPF route arrives at r1 with AD 110, which is better than static's
       AD 200, so OSPF replaces static as the selected route in RIB
    4. Route should still be in BGP (now from OSPF source)
    5. r2 stops redistributing into OSPF, OSPF route withdrawn
    6. Static route re-selected and should be re-redistributed into BGP

    This tests that BGP correctly handles route type transitions when the
    selected route in zebra RIB changes between different protocols.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("1a. Verify static route 10.99.0.0/24 is redistributed into BGP on r1")

    def _check_static_in_bgp():
        return check_bgp_route(r1, "10.99.0.0/24", True)

    _, result = topotest.run_and_expect(_check_static_in_bgp, None, count=30, wait=1)
    assert result is None, "Static route should be redistributed into BGP"

    step("1b. Wait for OSPF adjacency to form")

    def _check_ospf_neighbor():
        output = json.loads(r1.vtysh_cmd("show ip ospf neighbor json"))
        neighbors = output.get("neighbors", {})
        if not neighbors:
            return "No OSPF neighbors"
        for rid, nbr_list in neighbors.items():
            if isinstance(nbr_list, list) and nbr_list:
                nbr = nbr_list[0]
                state = nbr.get("nbrState", "")
                if "Full" in state:
                    return None
        return "OSPF neighbor not Full"

    _, result = topotest.run_and_expect(_check_ospf_neighbor, None, count=30, wait=1)
    assert result is None, "OSPF adjacency should be Full"

    step("1c. Add OSPF route for same prefix on r2 - OSPF has better AD (110 < 200)")

    # Redistribute connected routes into OSPF on r2 (loopback 10.99.0.1/24 is pre-configured)
    r2.vtysh_cmd(
        """
        configure terminal
        router ospf
        redistribute connected
        end
        """
    )

    # Wait for OSPF route to arrive and replace static in r1's RIB
    def _check_ospf_route():
        output = r1.vtysh_cmd("show ip route 10.99.0.0/24 json")
        data = json.loads(output)
        if "10.99.0.0/24" not in data:
            return "Route not found"
        route = get_selected_route(data["10.99.0.0/24"])
        if not route:
            return "No route found"
        if route.get("protocol") != "ospf":
            return f"Expected OSPF route selected, got {route.get('protocol')}"
        return None

    _, result = topotest.run_and_expect(_check_ospf_route, None, count=60, wait=1)
    assert result is None, "OSPF route should replace static route"

    step("1d. Verify BGP still has the route (now from OSPF)")

    _, result = topotest.run_and_expect(_check_static_in_bgp, None, count=30, wait=1)
    assert result is None, "Route should still be in BGP (from OSPF now)"

    step("1e. Remove OSPF route on r2 - static should be re-selected and re-redistributed")

    # Remove redistribute connected from OSPF
    r2.vtysh_cmd(
        """
        configure terminal
        router ospf
        no redistribute connected
        end
        """
    )

    # Wait for OSPF route to be withdrawn and static to be re-selected
    def _check_static_route():
        output = r1.vtysh_cmd("show ip route 10.99.0.0/24 json")
        data = json.loads(output)
        if "10.99.0.0/24" not in data:
            return "Route not found"
        route = get_selected_route(data["10.99.0.0/24"])
        if not route:
            return "No route found"
        if route.get("protocol") != "static":
            return f"Expected static route selected, got {route.get('protocol')}"
        return None

    _, result = topotest.run_and_expect(_check_static_route, None, count=60, wait=1)
    assert result is None, "Static route should be re-selected after OSPF withdrawal"

    step("1f. Verify static route is back in BGP")

    _, result = topotest.run_and_expect(_check_static_in_bgp, None, count=30, wait=1)
    assert result is None, "Static route should be re-redistributed into BGP"


def test_2_static_not_redistributed_when_ospf_selected():
    """
    Test type filtering: OSPF selected but only "redistribute static" configured.

    Setup (continues from test_1):
    - Static route 10.99.0.0/24 exists with AD 200
    - Both "redistribute static" and "redistribute ospf" initially configured

    Scenario:
    1. Enable OSPF redistribution on r2 so OSPF route (AD 110) is selected
    2. Remove "redistribute ospf" from r1's BGP config, keeping only
       "redistribute static"
    3. Route should NOT be in BGP because selected route is OSPF type but
       only static redistribution is configured
    4. Remove OSPF route (r2 stops redistributing)
    5. Static route becomes selected, now matches "redistribute static"
    6. Route should appear in BGP

    This tests that BGP correctly filters routes based on the selected
    route's type matching the redistribute configuration.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("2a. Add OSPF route on r2")

    # Redistribute connected routes into OSPF (loopback 10.99.0.1/24 is pre-configured)
    r2.vtysh_cmd(
        """
        configure terminal
        router ospf
        redistribute connected
        end
        """
    )

    # Wait for OSPF route to be selected
    def _check_ospf_selected():
        output = r1.vtysh_cmd("show ip route 10.99.0.0/24 json")
        data = json.loads(output)
        if "10.99.0.0/24" not in data:
            return "Route not found"
        route = get_selected_route(data["10.99.0.0/24"])
        if not route:
            return "No route found"
        if route.get("protocol") != "ospf":
            return f"Expected OSPF route selected, got {route.get('protocol')}"
        return None

    _, result = topotest.run_and_expect(_check_ospf_selected, None, count=60, wait=1)
    assert result is None, "OSPF route should be selected"

    step("2b. Disable redistribute OSPF, only static should be redistributed")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no redistribute ospf
        end
        """
    )

    # Route should not be in BGP since OSPF is selected but not redistributed
    def _check_not_in_bgp():
        return check_bgp_route(r1, "10.99.0.0/24", False)

    _, result = topotest.run_and_expect(_check_not_in_bgp, None, count=30, wait=1)
    assert result is None, "Route should not be in BGP (OSPF selected but not redistributed)"

    step("2c. Remove OSPF route - static should now be redistributed")

    # Remove redistribute connected from OSPF
    r2.vtysh_cmd(
        """
        configure terminal
        router ospf
        no redistribute connected
        end
        """
    )

    def _check_in_bgp():
        return check_bgp_route(r1, "10.99.0.0/24", True)

    _, result = topotest.run_and_expect(_check_in_bgp, None, count=60, wait=1)
    assert result is None, "Static route should be redistributed after OSPF withdrawal"


def test_3_multiple_redistribute_static_and_ospf():
    """
    Test multiple redistribute configs with different prefixes.

    Setup:
    - Both "redistribute static" and "redistribute ospf" configured on r1

    Scenario:
    1. Add static route 10.1.0.0/24 on r1 -> should be in BGP
    2. Add OSPF route 10.2.0.0/24 via r2 -> should be in BGP
    3. Both routes should coexist in BGP independently
    4. Remove "redistribute ospf" -> OSPF route should be withdrawn from BGP
    5. Static route should remain unaffected

    This tests that multiple redistribute configurations work independently
    without interfering with each other, and that removing one config only
    affects routes of that type.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("3a. Ensure redistribute static and ospf are configured")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static
        redistribute ospf
        end
        """
    )

    step("3b. Add static route 10.1.0.0/24 on r1")

    r1.vtysh_cmd(
        """
        configure terminal
        ip route 10.1.0.0/24 Null0
        end
        """
    )

    def _check_static_in_bgp():
        return check_bgp_route(r1, "10.1.0.0/24", True)

    _, result = topotest.run_and_expect(_check_static_in_bgp, None, count=30, wait=1)
    assert result is None, "Static route 10.1.0.0/24 should be in BGP"

    step("3c. Add OSPF route 10.2.0.0/24 on r2")

    # Add address and redistribute connected into OSPF
    r2.vtysh_cmd(
        """
        configure terminal
        interface lo
        ip address 10.2.0.1/24
        exit
        router ospf
        redistribute connected
        end
        """
    )

    def _check_ospf_in_bgp():
        return check_bgp_route(r1, "10.2.0.0/24", True)

    _, result = topotest.run_and_expect(_check_ospf_in_bgp, None, count=60, wait=1)
    assert result is None, "OSPF route 10.2.0.0/24 should be in BGP"

    step("3d. Verify both routes are present in BGP")

    def _check_both():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        routes = output.get("routes", {})
        missing = []
        if "10.1.0.0/24" not in routes:
            missing.append("10.1.0.0/24 (static)")
        if "10.2.0.0/24" not in routes:
            missing.append("10.2.0.0/24 (ospf)")
        if missing:
            return f"Missing routes: {', '.join(missing)}"
        return None

    _, result = topotest.run_and_expect(_check_both, None, count=30, wait=1)
    assert result is None, "Both static and OSPF routes should be in BGP"

    step("3e. Remove redistribute ospf, static should remain")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no redistribute ospf
        end
        """
    )

    def _check_static_only():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        routes = output.get("routes", {})
        if "10.1.0.0/24" not in routes:
            return "Static route 10.1.0.0/24 missing"
        if "10.2.0.0/24" in routes:
            return "OSPF route 10.2.0.0/24 should be gone"
        return None

    _, result = topotest.run_and_expect(_check_static_only, None, count=30, wait=1)
    assert result is None, "Only static route should remain"

    # Cleanup
    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.1.0.0/24 Null0
        end
        """
    )
    r2.vtysh_cmd(
        """
        configure terminal
        interface lo
        no ip address 10.2.0.1/24
        exit
        router ospf
        no redistribute connected
        end
        """
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
