#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Patrice Brissette <pbrisset@cisco.com>

"""
test_bgp_upa_ipv6.py

IPv6-specific tests for BGP UPA (draft-krierhorn-idr-upa-02).
Tests core UPA functionality with IPv6 address family.

Topology:

    peer1 (ExaBGP, AS 65002) --- s1 --- r1 (FRR, AS 65001)
    fd00::2/64                           fd00::1/64

peer1 injects two IPv6 prefixes with UPA Extended Communities:
  2001:db8:99:1::/64  UPA ExtCom  D-bit=0  originator=10.0.0.2
  2001:db8:99:2::/64  UPA ExtCom  D-bit=1  originator=10.0.0.2

Tests:
  1. BGP convergence
  2. UPA ExtCom received and decoded for IPv6
  3. Aggregate UPA origination (IPv6)
  4. Aggregate UPA withdrawal (IPv6)
  5. Max-routes rate limiting (IPv6)
  6. Global UPA originate-all (IPv6)
  7. UPA vs reachable precedence (IPv6)
  8. D-bit zebra blackhole installation (IPv6)
  9. Show commands (show bgp ipv6 upa)
  10. Statistics command (show bgp ipv6 upa statistics)
  11. Config persistence (IPv6 UPA config write)
"""

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer("peer1", ip="fd00::2", defaultRoute="via fd00::1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    router.start()

    peer = tgen.gears["peer1"]
    peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _bgp_ipv6_prefix_json(tgen, prefix):
    """Return the JSON dict for IPv6 *prefix* from r1's BGP RIB, or None."""
    output = tgen.gears["r1"].vtysh_cmd(
        "show bgp ipv6 unicast {} json".format(prefix)
    )
    data = json.loads(output)
    paths = data.get("paths")
    if not paths:
        return None
    return paths[0]


# ---------------------------------------------------------------------------
# Test 1: BGP convergence
# ---------------------------------------------------------------------------

def test_bgp_convergence():
    """
    Test 1: Verify BGP session convergence with IPv6 peering.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _converged():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp ipv6 unicast summary json")
        )
        peer_data = output.get("peers", {}).get("fd00::2")
        if not peer_data:
            return False
        return peer_data.get("state") == "Established"

    success, _ = topotest.run_and_expect(_converged, True, count=60, wait=1)
    assert success, "BGP session with fd00::2 did not converge"


# ---------------------------------------------------------------------------
# Test 2: UPA ExtCom received (IPv6)
# ---------------------------------------------------------------------------

def test_upa_extcom_received():
    """
    Test 2: Verify UPA Extended Community is decoded for IPv6 routes.

    ExaBGP sends:
    - 2001:db8:99:1::/64 with UPA ExtCom (D-bit=0)
    - 2001:db8:99:2::/64 with UPA ExtCom (D-bit=1)

    Verify ExtCom displays as "upa:10.0.0.2:no-drop" and "upa:10.0.0.2:drop"
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Wait for routes to be received
    def _routes_received():
        data1 = _bgp_ipv6_prefix_json(tgen, "2001:db8:99:1::/64")
        data2 = _bgp_ipv6_prefix_json(tgen, "2001:db8:99:2::/64")
        return data1 is not None and data2 is not None

    success, _ = topotest.run_and_expect(_routes_received, True, count=30, wait=1)
    assert success, "IPv6 UPA routes not received from ExaBGP"

    # Check D-bit=0 route
    data1 = _bgp_ipv6_prefix_json(tgen, "2001:db8:99:1::/64")
    extcom1 = data1.get("extendedCommunity", {}).get("string", "")
    assert "upa:10.0.0.2:no-drop" in extcom1.lower(), \
        f"Expected 'upa:10.0.0.2:no-drop' in ExtCom, got: {extcom1}"

    # Check D-bit=1 route
    data2 = _bgp_ipv6_prefix_json(tgen, "2001:db8:99:2::/64")
    extcom2 = data2.get("extendedCommunity", {}).get("string", "")
    assert "upa:10.0.0.2:drop" in extcom2.lower(), \
        f"Expected 'upa:10.0.0.2:drop' in ExtCom, got: {extcom2}"


# ---------------------------------------------------------------------------
# Test 3: Aggregate UPA origination (IPv6)
# ---------------------------------------------------------------------------

def test_aggregate_upa_origination():
    """
    Test 3: Verify IPv6 aggregate UPA origination.

    - Configure 2001:db8:10::/48 aggregate with UPA
    - Remove constituent routes 2001:db8:10:1::/64, 2001:db8:10:2::/64
    - Verify UPA routes originated with correct attributes
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Configure aggregate with UPA
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        aggregate-address 2001:db8:10::/48 upa
    """)

    # Verify aggregate is configured
    config = r1.vtysh_cmd("show running-config")
    print(f"\n=== DEBUG: Running config snippet ===\n{config}\n")
    assert "aggregate-address 2001:db8:10::/48" in config, "Aggregate not in config"

    # Wait for static routes to be in BGP
    def _routes_present():
        output = r1.vtysh_cmd("show bgp ipv6 unicast json")
        data = json.loads(output)
        routes = data.get("routes", {})
        return "2001:db8:10:1::/64" in routes and "2001:db8:10:2::/64" in routes

    success, _ = topotest.run_and_expect(_routes_present, True, count=30, wait=1)
    assert success, "Static IPv6 routes not in BGP RIB"

    print("\n=== DEBUG: Before withdrawal ===")
    before_output = r1.vtysh_cmd("show bgp ipv6 unicast summary")
    print(before_output)

    # Remove static routes to trigger UPA
    print("\n=== DEBUG: Removing static routes ===")
    r1.vtysh_cmd("""
        configure terminal
        no ipv6 route 2001:db8:10:1::/64 Null0
        no ipv6 route 2001:db8:10:2::/64 Null0
    """)

    # Give BGP time to process
    import time
    time.sleep(2)

    print("\n=== DEBUG: After withdrawal ===")
    after_output = r1.vtysh_cmd("show bgp ipv6 unicast")
    print(after_output)

    # Wait for UPA routes to be originated
    def _upa_originated():
        output = r1.vtysh_cmd("show bgp ipv6 unicast upa json")
        data = json.loads(output)
        return data.get("totalUpaRoutes", 0) >= 2

    success, _ = topotest.run_and_expect(_upa_originated, True, count=30, wait=1)
    assert success, "IPv6 UPA routes not originated"

    # Verify UPA routes in detail
    output = r1.vtysh_cmd("show bgp ipv6 unicast upa json")
    data = json.loads(output)

    # Debug output
    print(f"\n=== DEBUG: Total UPA routes: {data.get('totalUpaRoutes')} ===")
    print(f"=== DEBUG: UPA routes list: {json.dumps(data.get('routes', []), indent=2)} ===\n")

    assert data.get("totalUpaRoutes", 0) >= 2, \
        f"Expected at least 2 UPA routes, got {data.get('totalUpaRoutes')}"

    # Check one specific route
    route_output = r1.vtysh_cmd("show bgp ipv6 unicast 2001:db8:10:1::/64 json")
    route_data = json.loads(route_output)

    print(f"\n=== DEBUG: Route 2001:db8:10:1::/64 data: {json.dumps(route_data, indent=2)} ===\n")

    # Find UPA path
    upa_path = None
    if route_data.get("paths"):
        for path in route_data["paths"]:
            extcom_str = path.get("extendedCommunity", {}).get("string", "")
            if "upa:" in extcom_str.lower():
                upa_path = path
                break

    assert upa_path is not None, \
        f"UPA path not found for 2001:db8:10:1::/64. Available paths: {len(route_data.get('paths', []))}"

    # Verify origin
    assert upa_path.get("origin") == "incomplete", \
        f"Expected origin 'incomplete', got {upa_path.get('origin')}"

    # Verify extended community
    extcom_str = upa_path.get("extendedCommunity", {}).get("string", "")
    assert "upa:" in extcom_str.lower(), \
        f"UPA extended community not found in: {extcom_str}"

    # Cleanup
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        no aggregate-address 2001:db8:10::/48
    """)


# ---------------------------------------------------------------------------
# Test 4: Aggregate UPA withdrawal (IPv6)
# ---------------------------------------------------------------------------

def test_aggregate_upa_withdrawal():
    """
    Test 4: Verify IPv6 UPA withdrawal when constituent becomes reachable.

    - Configure aggregate with UPA
    - Remove constituent (triggers UPA)
    - Restore constituent (should withdraw UPA)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Configure aggregate
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        aggregate-address 2001:db8:10::/48 upa
    """)

    # Add and remove route to trigger UPA
    r1.vtysh_cmd("configure terminal\nipv6 route 2001:db8:10:3::/64 Null0")

    import time
    time.sleep(1)

    r1.vtysh_cmd("configure terminal\nno ipv6 route 2001:db8:10:3::/64 Null0")

    # Wait for UPA
    def _upa_present():
        output = r1.vtysh_cmd("show bgp ipv6 unicast upa json")
        data = json.loads(output)
        routes = data.get("routes", [])
        return any(r.get("network") == "2001:db8:10:3::/64" for r in routes)

    success, _ = topotest.run_and_expect(_upa_present, True, count=30, wait=1)
    assert success, "IPv6 UPA not originated"

    # Restore route (should withdraw UPA)
    r1.vtysh_cmd("configure terminal\nipv6 route 2001:db8:10:3::/64 Null0")

    # Wait for UPA withdrawal
    def _upa_withdrawn():
        output = r1.vtysh_cmd("show bgp ipv6 unicast upa json")
        data = json.loads(output)
        routes = data.get("routes", [])
        return not any(r.get("network") == "2001:db8:10:3::/64" for r in routes)

    success, _ = topotest.run_and_expect(_upa_withdrawn, True, count=30, wait=1)
    assert success, "IPv6 UPA not withdrawn after route restoration"

    # Cleanup
    r1.vtysh_cmd("""
        configure terminal
        no ipv6 route 2001:db8:10:3::/64 Null0
        router bgp 65001
        address-family ipv6 unicast
        no aggregate-address 2001:db8:10::/48
    """)


# ---------------------------------------------------------------------------
# Test 5: Max-routes rate limiting (IPv6)
# ---------------------------------------------------------------------------

def test_aggregate_upa_max_routes():
    """
    Test 5: Verify IPv6 UPA max-routes rate limiting.

    - Configure aggregate with max-routes 2
    - Remove 3 constituents
    - Verify only 2 UPA routes originated
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Configure aggregate with max-routes
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        aggregate-address 2001:db8:10::/48 upa max-routes 2
    """)

    # Add 3 routes then remove them
    r1.vtysh_cmd("""
        configure terminal
        ipv6 route 2001:db8:10:a::/64 Null0
        ipv6 route 2001:db8:10:b::/64 Null0
        ipv6 route 2001:db8:10:c::/64 Null0
    """)

    import time
    time.sleep(1)

    r1.vtysh_cmd("""
        configure terminal
        no ipv6 route 2001:db8:10:a::/64 Null0
        no ipv6 route 2001:db8:10:b::/64 Null0
        no ipv6 route 2001:db8:10:c::/64 Null0
    """)

    # Wait and verify only 2 UPA routes
    time.sleep(2)

    output = r1.vtysh_cmd("show bgp ipv6 unicast upa json")
    data = json.loads(output)

    # Count only UPA routes under the aggregate (2001:db8:10::/48)
    aggregate_upa_routes = [
        r for r in data.get("routes", [])
        if r.get("network", "").startswith("2001:db8:10:")
    ]

    upa_count = len(aggregate_upa_routes)
    assert upa_count == 2, f"Expected 2 UPA routes (max-routes limit), got {upa_count}"

    # Cleanup
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        no aggregate-address 2001:db8:10::/48
    """)


# ---------------------------------------------------------------------------
# Test 6: Global UPA originate-all (IPv6)
# ---------------------------------------------------------------------------

def test_global_upa_originate_all():
    """
    Test 6: Verify IPv6 global UPA (not tied to aggregates).

    - Configure 'upa originate-all' under address-family ipv6
    - Remove any prefix
    - Verify UPA originated
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Configure global UPA
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        upa originate-all
    """)

    # Add then remove a route
    r1.vtysh_cmd("configure terminal\nipv6 route 2001:db8:20:1::/64 Null0")

    import time
    time.sleep(1)

    r1.vtysh_cmd("configure terminal\nno ipv6 route 2001:db8:20:1::/64 Null0")

    # Wait for UPA
    def _global_upa_originated():
        output = r1.vtysh_cmd("show bgp ipv6 unicast upa json")
        data = json.loads(output)
        routes = data.get("routes", [])
        return any(r.get("network") == "2001:db8:20:1::/64" for r in routes)

    success, _ = topotest.run_and_expect(_global_upa_originated, True, count=30, wait=1)
    assert success, "Global IPv6 UPA not originated"

    # Cleanup
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        no upa originate-all
    """)


# ---------------------------------------------------------------------------
# Test 7: UPA vs reachable precedence (IPv6)
# ---------------------------------------------------------------------------

def test_upa_vs_reachable_precedence():
    """
    Test 7: Verify reachable IPv6 path wins over UPA in best-path selection.

    - Configure aggregate with UPA
    - Remove constituent (triggers UPA)
    - Verify UPA is best path
    - Restore constituent
    - Verify reachable path wins
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Configure aggregate
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        aggregate-address 2001:db8:10::/48 upa
    """)

    # Add route then remove it
    r1.vtysh_cmd("configure terminal\nipv6 route 2001:db8:10:d::/64 Null0")

    import time
    time.sleep(1)

    r1.vtysh_cmd("configure terminal\nno ipv6 route 2001:db8:10:d::/64 Null0")

    # Wait for UPA to be best path
    def _upa_is_best():
        output = r1.vtysh_cmd("show bgp ipv6 unicast 2001:db8:10:d::/64 json")
        data = json.loads(output)
        paths = data.get("paths", [])
        if not paths:
            return False
        best = paths[0]
        extcom = best.get("extendedCommunity", {}).get("string", "")
        return "upa:" in extcom.lower()

    success, _ = topotest.run_and_expect(_upa_is_best, True, count=30, wait=1)
    assert success, "UPA not best path when no reachable path exists"

    # Restore route
    r1.vtysh_cmd("configure terminal\nipv6 route 2001:db8:10:d::/64 Null0")

    # Wait for reachable to be best
    def _reachable_is_best():
        output = r1.vtysh_cmd("show bgp ipv6 unicast 2001:db8:10:d::/64 json")
        data = json.loads(output)
        paths = data.get("paths", [])
        if not paths:
            return False
        best = paths[0]
        extcom = best.get("extendedCommunity", {}).get("string", "")
        return "upa:" not in extcom.lower()

    success, _ = topotest.run_and_expect(_reachable_is_best, True, count=30, wait=1)
    assert success, "Reachable path did not win over UPA in best-path"

    # Cleanup
    r1.vtysh_cmd("""
        configure terminal
        no ipv6 route 2001:db8:10:d::/64 Null0
        router bgp 65001
        address-family ipv6 unicast
        no aggregate-address 2001:db8:10::/48
    """)


# ---------------------------------------------------------------------------
# Test 8: D-bit zebra blackhole (IPv6)
# ---------------------------------------------------------------------------

def test_received_upa_dbit_zebra():
    """
    Test 8: Verify D-bit=1 installs IPv6 blackhole in zebra RIB.

    ExaBGP sends 2001:db8:99:2::/64 with D-bit=1.
    Verify zebra RIB has blackhole entry.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Wait for route with D-bit=1 in zebra
    def _blackhole_installed():
        output = r1.vtysh_cmd("show ipv6 route 2001:db8:99:2::/64 json")
        data = json.loads(output)
        route_data = data.get("2001:db8:99:2::/64")
        if not route_data:
            return False
        nexthops = route_data[0].get("nexthops", [])
        # Check for "blackhole": true field, not "type": "blackhole"
        return any(nh.get("blackhole") is True for nh in nexthops)

    success, _ = topotest.run_and_expect(_blackhole_installed, True, count=30, wait=1)
    assert success, "IPv6 blackhole route (D-bit=1) not installed in zebra"


# ---------------------------------------------------------------------------
# Test 9: Show commands (IPv6)
# ---------------------------------------------------------------------------

def test_show_bgp_ipv6_upa():
    """
    Test 9: Verify 'show bgp ipv6 upa' command works.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Test command executes
    output = r1.vtysh_cmd("show bgp ipv6 upa")
    assert "UPA" in output or len(output) > 0, "show bgp ipv6 upa command failed"

    # Test JSON output
    output_json = r1.vtysh_cmd("show bgp ipv6 upa json")
    data = json.loads(output_json)
    assert isinstance(data, dict), "show bgp ipv6 upa json didn't return dict"


# ---------------------------------------------------------------------------
# Test 10: Statistics command (IPv6)
# ---------------------------------------------------------------------------

def test_show_bgp_ipv6_upa_statistics():
    """
    Test 10: Verify 'show bgp ipv6 upa statistics' command works.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Test command executes
    output = r1.vtysh_cmd("show bgp ipv6 upa statistics")
    assert "statistics" in output.lower() or len(output) > 0, \
        "show bgp ipv6 upa statistics command failed"

    # Test JSON output
    output_json = r1.vtysh_cmd("show bgp ipv6 upa statistics json")
    data = json.loads(output_json)
    assert isinstance(data, dict), "show bgp ipv6 upa statistics json didn't return dict"


# ---------------------------------------------------------------------------
# Test 11: Config persistence (IPv6)
# ---------------------------------------------------------------------------

def test_config_write_ipv6_upa():
    """
    Test 11: Verify IPv6 UPA configuration persists in running-config.

    - Configure aggregate with UPA
    - Verify 'show running-config' contains IPv6 UPA commands
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Configure aggregate with UPA options
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        aggregate-address 2001:db8:10::/48 upa drop max-routes 100
    """)

    # Check running config
    output = r1.vtysh_cmd("show running-config")

    assert "aggregate-address 2001:db8:10::/48" in output, \
        "IPv6 aggregate not in running-config"
    assert "upa" in output.lower(), \
        "UPA keyword not in running-config"
    assert "drop" in output or "max-routes" in output, \
        "UPA options not in running-config"

    # Cleanup
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        address-family ipv6 unicast
        no aggregate-address 2001:db8:10::/48
    """)
