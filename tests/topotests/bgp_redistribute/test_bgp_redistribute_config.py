#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP redistribute configuration changes.

Cover configuration change scenarios:
1) redistribute <type> -> redistribute <type> route-map X (add route-map)
2) redistribute <type> route-map X -> redistribute <type> (remove route-map)
3) redistribute <type> route-map X -> redistribute <type> route-map Y (change route-map)
4) redistribute <type> metric M -> redistribute <type> (remove metric)
5) redistribute <type> -> redistribute <type> metric M (add metric)
6) redistribute <type> route-map X -> redistribute <type> metric M (swap route-map for metric)
7) Route-map match clause change: match tag 100 -> match tag 200
8) Add match clause to existing route-map
9) Remove match clause from route-map
10) Prefix-list change: permit 10.0.0.0/24 -> permit 10.1.0.0/24
11) Prefix-list action change: permit -> deny
12) Add set metric to route-map
13) Change set metric value
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


def check_bgp_route_metric(r1, prefix, expected_metric):
    """Check if a route has the expected metric."""
    output = json.loads(r1.vtysh_cmd(f"show bgp ipv4 unicast {prefix} json"))
    paths = output.get("paths", [])
    if not paths:
        return f"Route {prefix} not found"
    metric = paths[0].get("metric", 0)
    if metric != expected_metric:
        return f"Expected metric {expected_metric}, got {metric}"
    return None


def reset_config(r1):
    """Reset to basic redistribute static config."""
    r1.vtysh_cmd(
        """
        configure terminal
        no route-map RM_TEST
        no route-map RM_TEST2
        no ip prefix-list PL_TEST
        router bgp 65001
        address-family ipv4 unicast
        redistribute static
        end
        """
    )


def test_1_add_routemap_to_redistribute():
    """Test 1: redistribute static -> redistribute static route-map X."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("1. Verify route is present with basic redistribute")

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should be present"

    step("1. Add route-map that denies the route")

    r1.vtysh_cmd(
        """
        configure terminal
        ip prefix-list PL_TEST seq 5 permit 10.0.0.0/24
        route-map RM_TEST deny 10
        match ip address prefix-list PL_TEST
        exit
        route-map RM_TEST permit 20
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn after adding deny route-map"


def test_2_remove_routemap_from_redistribute():
    """Test 2: redistribute static route-map X -> redistribute static."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("2. Remove route-map, route should reappear")

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
    assert result is None, "Route should reappear after removing route-map"


def test_3_change_routemap():
    """Test 3: redistribute static route-map X -> redistribute static route-map Y."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("3. Apply permit route-map, then change to deny route-map")

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        match ip address prefix-list PL_TEST
        exit
        route-map RM_TEST2 deny 10
        match ip address prefix-list PL_TEST
        exit
        route-map RM_TEST2 permit 20
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
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
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST2
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn after changing to deny route-map"

    reset_config(r1)


def test_4_remove_metric_from_redistribute():
    """Test 4: redistribute static metric M -> redistribute static."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("4. Add redistribute with metric, then remove metric")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static metric 500
        end
        """
    )

    def _check_metric_500():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 500)

    _, result = topotest.run_and_expect(_check_metric_500, None, count=30, wait=1)
    assert result is None, "Route should have metric 500"

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static
        end
        """
    )

    def _check_metric_0():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 0)

    _, result = topotest.run_and_expect(_check_metric_0, None, count=30, wait=1)
    assert result is None, "Route metric should be cleared"


def test_5_add_metric_to_redistribute():
    """Test 5: redistribute static -> redistribute static metric M."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("5. Add metric to existing redistribute")

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should be present"

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static metric 200
        end
        """
    )

    def _check_metric():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 200)

    _, result = topotest.run_and_expect(_check_metric, None, count=30, wait=1)
    assert result is None, "Route should have metric 200"

    reset_config(r1)


def test_6_swap_routemap_for_metric():
    """Test 6: redistribute static route-map X -> redistribute static metric M."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("6. Start with route-map, switch to metric")

    r1.vtysh_cmd(
        """
        configure terminal
        ip prefix-list PL_TEST seq 5 permit 10.0.0.0/24
        route-map RM_TEST permit 10
        match ip address prefix-list PL_TEST
        set metric 100
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_metric_100():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 100)

    _, result = topotest.run_and_expect(_check_metric_100, None, count=30, wait=1)
    assert result is None, "Route should have metric 100 from route-map"

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static metric 300
        end
        """
    )

    def _check_metric_300():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 300)

    _, result = topotest.run_and_expect(_check_metric_300, None, count=30, wait=1)
    assert result is None, "Route should have metric 300 after switching to metric config"

    reset_config(r1)


def test_6b_swap_metric_for_routemap():
    """Test 6b: redistribute static metric M -> redistribute static route-map X."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("6b. Start with metric, switch to route-map")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static metric 200
        end
        """
    )

    def _check_metric_200():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 200)

    _, result = topotest.run_and_expect(_check_metric_200, None, count=30, wait=1)
    assert result is None, "Route should have metric 200"

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_metric_0():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 0)

    _, result = topotest.run_and_expect(_check_metric_0, None, count=30, wait=1)
    assert result is None, "Route should have metric 0 after switching to route-map (stale metric cleared)"

    reset_config(r1)


def test_7_routemap_match_clause_change():
    """Test 7: Change route-map match clause: match tag 100 -> match tag 200."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("7. Create route with tag, use route-map matching tag")

    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.0/24 Null0
        ip route 10.0.0.0/24 Null0 tag 100
        route-map RM_TEST permit 10
        match tag 100
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should match tag 100"

    step("7. Change route-map to match tag 200")

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        match tag 200
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn after changing match tag"

    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.0/24 Null0 tag 100
        ip route 10.0.0.0/24 Null0
        end
        """
    )
    reset_config(r1)


def test_8_add_match_clause_to_routemap():
    """Test 8: Add match clause to existing route-map."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("8. Start with permit-all route-map, add restrictive match")

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should be present with permit-all route-map"

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        match tag 999
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn after adding non-matching clause"

    reset_config(r1)


def test_9_remove_match_clause_from_routemap():
    """Test 9: Remove match clause from route-map."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("9. Start with restrictive match, remove it")

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        match tag 999
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should not match tag 999"

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        no match tag
        end
        """
    )

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should appear after removing match clause"

    reset_config(r1)


def test_10_prefixlist_change():
    """Test 10: Prefix-list change: permit 10.0.0.0/24 -> permit 10.1.0.0/24."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("10. Use prefix-list in route-map, then change prefix-list")

    r1.vtysh_cmd(
        """
        configure terminal
        ip prefix-list PL_TEST seq 5 permit 10.0.0.0/24
        route-map RM_TEST permit 10
        match ip address prefix-list PL_TEST
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should match prefix-list"

    r1.vtysh_cmd(
        """
        configure terminal
        no ip prefix-list PL_TEST seq 5
        ip prefix-list PL_TEST seq 5 permit 10.1.0.0/24
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn after prefix-list change"

    reset_config(r1)


def test_11_prefixlist_action_change():
    """Test 11: Prefix-list action change: permit -> deny."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("11. Change prefix-list from permit to deny")

    r1.vtysh_cmd(
        """
        configure terminal
        ip prefix-list PL_TEST seq 5 permit 10.0.0.0/24
        route-map RM_TEST permit 10
        match ip address prefix-list PL_TEST
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_present():
        return check_bgp_route(r1, "10.0.0.0/24", True)

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, "Route should match permit prefix-list"

    r1.vtysh_cmd(
        """
        configure terminal
        no ip prefix-list PL_TEST seq 5
        ip prefix-list PL_TEST seq 5 deny 10.0.0.0/24
        ip prefix-list PL_TEST seq 10 permit any
        end
        """
    )

    def _check_gone():
        return check_bgp_route(r1, "10.0.0.0/24", False)

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "Route should be withdrawn after prefix-list deny"

    reset_config(r1)


def test_12_add_set_metric_to_routemap():
    """Test 12: Add set metric to route-map."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("12. Add set metric to existing route-map")

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_metric_0():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 0)

    _, result = topotest.run_and_expect(_check_metric_0, None, count=30, wait=1)
    assert result is None, "Route should have default metric"

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        set metric 150
        end
        """
    )

    def _check_metric_150():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 150)

    _, result = topotest.run_and_expect(_check_metric_150, None, count=30, wait=1)
    assert result is None, "Route should have metric 150"

    reset_config(r1)


def test_13_change_set_metric_value():
    """Test 13: Change set metric value in route-map."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("13. Change set metric value")

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        set metric 100
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_metric_100():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 100)

    _, result = topotest.run_and_expect(_check_metric_100, None, count=30, wait=1)
    assert result is None, "Route should have metric 100"

    r1.vtysh_cmd(
        """
        configure terminal
        route-map RM_TEST permit 10
        set metric 250
        end
        """
    )

    def _check_metric_250():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 250)

    _, result = topotest.run_and_expect(_check_metric_250, None, count=30, wait=1)
    assert result is None, "Route should have metric 250"

    reset_config(r1)


def test_14_redistribute_with_routemap_and_metric():
    """Test 14: redistribute static route-map X metric M (combined)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("14. Configure redistribute with both route-map and metric")

    r1.vtysh_cmd(
        """
        configure terminal
        ip prefix-list PL_TEST seq 5 permit 10.0.0.0/24
        route-map RM_TEST permit 10
        match ip address prefix-list PL_TEST
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST metric 100
        end
        """
    )

    def _check_metric_100():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 100)

    _, result = topotest.run_and_expect(_check_metric_100, None, count=30, wait=1)
    assert result is None, "Route should have metric 100 from redistribute config"

    step("14. Change to route-map only (should clear metric)")

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST
        end
        """
    )

    def _check_metric_0():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 0)

    _, result = topotest.run_and_expect(_check_metric_0, None, count=30, wait=1)
    assert result is None, "Metric should be cleared when switching to route-map only"

    reset_config(r1)


def test_15_redistribute_routemap_metric_to_metric_only():
    """Test 15: redistribute route-map+metric -> metric only."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("15. Start with route-map and metric, switch to metric only")

    r1.vtysh_cmd(
        """
        configure terminal
        ip prefix-list PL_TEST seq 5 permit 10.0.0.0/24
        route-map RM_TEST permit 10
        match ip address prefix-list PL_TEST
        set metric 999
        exit
        router bgp 65001
        address-family ipv4 unicast
        redistribute static route-map RM_TEST metric 100
        end
        """
    )

    # Route-map set metric should override redistribute metric
    def _check_metric_999():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 999)

    _, result = topotest.run_and_expect(_check_metric_999, None, count=30, wait=1)
    assert result is None, "Route should have metric 999 (route-map overrides redistribute metric)"

    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        redistribute static metric 200
        end
        """
    )

    def _check_metric_200():
        return check_bgp_route_metric(r1, "10.0.0.0/24", 200)

    _, result = topotest.run_and_expect(_check_metric_200, None, count=30, wait=1)
    assert result is None, "Route should have metric 200 after removing route-map"

    reset_config(r1)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
