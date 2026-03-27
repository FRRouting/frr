#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025
#
"""
Test the 'show static routes [json]' command in staticd.

Verifies:
  - Basic JSON structure for various nexthop types
  - active / inactive status per nexthop
  - reasonInactive strings for unreachable gateways
  - Blackhole and reject routes
  - Multi-nexthop routes with mixed active/inactive nexthops
  - IPv6 routes
  - Plain-text output contains expected keywords
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_show_static_json(r1):
    """Return parsed JSON from 'show static routes json'."""
    raw = r1.vtysh_cmd("show static routes json")
    return json.loads(raw)


def _find_route(routes, prefix):
    """Find a route entry by prefix string in the routes array."""
    for r in routes:
        if r.get("prefix") == prefix:
            return r
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_show_static_routes_json_structure(tgen=None):
    """The JSON output must have the expected top-level structure."""
    if tgen is None:
        tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        # Must have a "default" VRF key
        if "default" not in output:
            return "missing 'default' key in output"
        vrf = output["default"]
        if "routes" not in vrf:
            return "missing 'routes' in default VRF"
        routes = vrf["routes"]
        if not isinstance(routes, list):
            return "'routes' is not a list"
        if len(routes) == 0:
            return "no routes found yet"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"JSON structure check failed: {result}"


def test_show_static_gateway_reachable():
    """A static route via a directly-connected gateway should be active."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "192.168.1.0/24")
        if route is None:
            return "route 192.168.1.0/24 not found"
        nh = route["paths"][0]["nexthops"][0]
        if nh.get("type") != "ipv4-gateway":
            return f"unexpected type: {nh.get('type')}"
        if nh.get("gateway") != "10.1.0.2":
            return f"unexpected gateway: {nh.get('gateway')}"
        if nh.get("active") is not True:
            return f"expected active=true, got {nh.get('active')}"
        if nh.get("nhValid") is not True:
            return f"expected nhValid=true, got {nh.get('nhValid')}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Reachable gateway check failed: {result}"


def test_show_static_gateway_unreachable():
    """A static route via an unreachable gateway should be inactive with reason."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "192.168.2.0/24")
        if route is None:
            return "route 192.168.2.0/24 not found"
        nh = route["paths"][0]["nexthops"][0]
        if nh.get("active") is not False:
            return f"expected active=false, got {nh.get('active')}"
        if nh.get("nhValid") is not False:
            return f"expected nhValid=false, got {nh.get('nhValid')}"
        reason = nh.get("reasonInactive", "")
        if "not reachable" not in reason and "not yet registered" not in reason:
            return f"unexpected reasonInactive: {reason}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Unreachable gateway check failed: {result}"


def test_show_static_interface_route():
    """A static route via an existing interface should be active."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "192.168.3.0/24")
        if route is None:
            return "route 192.168.3.0/24 not found"
        nh = route["paths"][0]["nexthops"][0]
        if nh.get("type") != "interface":
            return f"unexpected type: {nh.get('type')}"
        if nh.get("interface") != "r1-eth0":
            return f"unexpected interface: {nh.get('interface')}"
        if nh.get("active") is not True:
            return f"expected active=true, got {nh.get('active')}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Interface route check failed: {result}"


def test_show_static_blackhole():
    """Blackhole routes should always be active."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "192.168.4.0/24")
        if route is None:
            return "route 192.168.4.0/24 not found"
        nh = route["paths"][0]["nexthops"][0]
        if nh.get("type") != "blackhole":
            return f"unexpected type: {nh.get('type')}"
        if nh.get("blackholeType") != "drop":
            return f"unexpected blackholeType: {nh.get('blackholeType')}"
        if nh.get("active") is not True:
            return f"expected active=true, got {nh.get('active')}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Blackhole route check failed: {result}"


def test_show_static_reject():
    """Reject routes should always be active."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "192.168.5.0/24")
        if route is None:
            return "route 192.168.5.0/24 not found"
        nh = route["paths"][0]["nexthops"][0]
        if nh.get("type") != "blackhole":
            return f"unexpected type: {nh.get('type')}"
        if nh.get("blackholeType") != "reject":
            return f"unexpected blackholeType: {nh.get('blackholeType')}"
        if nh.get("active") is not True:
            return f"expected active=true, got {nh.get('active')}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Reject route check failed: {result}"


def test_show_static_multi_nexthop():
    """Multi-nexthop route: reachable NH active, unreachable NH inactive."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "192.168.6.0/24")
        if route is None:
            return "route 192.168.6.0/24 not found"
        # All nexthops should be in the same path (same distance)
        nexthops = route["paths"][0]["nexthops"]
        if len(nexthops) < 2:
            return f"expected 2 nexthops, got {len(nexthops)}"

        # Build a map by gateway
        by_gw = {}
        for nh in nexthops:
            gw = nh.get("gateway", "")
            by_gw[gw] = nh

        # 10.1.0.2 should be active (directly connected)
        nh_good = by_gw.get("10.1.0.2")
        if nh_good is None:
            return "nexthop 10.1.0.2 not found"
        if nh_good.get("active") is not True:
            return f"10.1.0.2: expected active=true, got {nh_good.get('active')}"

        # 10.99.99.2 should be inactive
        nh_bad = by_gw.get("10.99.99.2")
        if nh_bad is None:
            return "nexthop 10.99.99.2 not found"
        if nh_bad.get("active") is not False:
            return f"10.99.99.2: expected active=false, got {nh_bad.get('active')}"
        if "reasonInactive" not in nh_bad:
            return "10.99.99.2: missing reasonInactive"

        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Multi-nexthop check failed: {result}"


def test_show_static_multi_nexthop_installed_but_inactive():
    """When a multi-nexthop route is installed (because at least one NH is
    valid), zebra marks ALL nexthops with routeState='installed' -- even the
    invalid one. The 'active' field must still correctly show false for the
    invalid nexthop, and a reasonInactive must be present.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "192.168.6.0/24")
        if route is None:
            return "route 192.168.6.0/24 not found"

        nexthops = route["paths"][0]["nexthops"]
        by_gw = {nh.get("gateway", ""): nh for nh in nexthops}

        nh_good = by_gw.get("10.1.0.2")
        nh_bad = by_gw.get("10.99.99.2")
        if nh_good is None or nh_bad is None:
            return "one of the nexthops not found yet"

        # Wait until the valid nexthop is actually installed by zebra
        if nh_good.get("routeState") != "installed":
            return f"10.1.0.2: routeState not yet installed ({nh_good.get('routeState')})"

        # THE BUG CHECK: zebra sets routeState=installed for ALL nexthops
        # in the path, including the invalid one.  That's the kernel behavior
        # we can't change.  But 'active' must correctly reflect reality.

        # The valid nexthop: installed AND active
        if nh_good.get("active") is not True:
            return f"10.1.0.2: expected active=true, got {nh_good.get('active')}"

        # The invalid nexthop: routeState may say 'installed' (the bug),
        # but active MUST be false
        if nh_bad.get("active") is not False:
            return (
                f"10.99.99.2: BUG - routeState={nh_bad.get('routeState')} "
                f"but active should be false, got {nh_bad.get('active')}"
            )

        # Must have a reason explaining why it's inactive
        reason = nh_bad.get("reasonInactive", "")
        if not reason:
            return "10.99.99.2: active=false but no reasonInactive provided"
        if "not reachable" not in reason and "not yet registered" not in reason:
            return f"10.99.99.2: unexpected reasonInactive: {reason}"

        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, f"Installed-but-inactive check failed: {result}"


def test_show_static_ipv6_gateway():
    """IPv6 static route via reachable gateway should be active."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "2001:db8:10::/48")
        if route is None:
            return "route 2001:db8:10::/48 not found"
        nh = route["paths"][0]["nexthops"][0]
        if nh.get("type") != "ipv6-gateway":
            return f"unexpected type: {nh.get('type')}"
        if nh.get("active") is not True:
            return f"expected active=true, got {nh.get('active')}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"IPv6 gateway check failed: {result}"


def test_show_static_ipv6_blackhole():
    """IPv6 blackhole route should be active."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "2001:db8:20::/48")
        if route is None:
            return "route 2001:db8:20::/48 not found"
        nh = route["paths"][0]["nexthops"][0]
        if nh.get("type") != "blackhole":
            return f"unexpected type: {nh.get('type')}"
        if nh.get("active") is not True:
            return f"expected active=true, got {nh.get('active')}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"IPv6 blackhole check failed: {result}"


def test_show_static_plain_text():
    """Plain-text output must contain key diagnostic strings."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = r1.vtysh_cmd("show static routes")
        # Must mention VRF
        if "VRF default:" not in output:
            return f"missing 'VRF default:' in output:\n{output}"
        # Must have at least one active nexthop
        if "active" not in output:
            return f"missing 'active' in output:\n{output}"
        # Must show IPv4 Unicast header
        if "IPv4 Unicast:" not in output:
            return f"missing 'IPv4 Unicast:' in output:\n{output}"
        # Must show some prefix
        if "192.168.1.0/24" not in output:
            return f"missing '192.168.1.0/24' in output:\n{output}"
        # Unreachable routes should show inactive reason
        if "inactive reason:" not in output:
            return f"missing 'inactive reason:' in output:\n{output}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Plain-text output check failed: {result}"


def test_show_static_plain_text_inactive_nexthop():
    """Plain-text: for the multi-NH route, the unreachable NH must show
    'inactive' (not misleadingly 'installed') with a reason string."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = r1.vtysh_cmd("show static routes")
        # Find the 192.168.6.0/24 section
        if "192.168.6.0/24" not in output:
            return "192.168.6.0/24 not in plain-text output"
        # The unreachable gateway line should be followed by "inactive"
        lines = output.splitlines()
        found_bad_nh = False
        for i, line in enumerate(lines):
            if "10.99.99.2" in line:
                found_bad_nh = True
                # Next line(s) should say "inactive"
                remaining = "\n".join(lines[i:i + 3])
                if "inactive" not in remaining:
                    return (
                        f"10.99.99.2 NH does not show 'inactive':\n{remaining}"
                    )
                if "inactive reason:" not in remaining:
                    return (
                        f"10.99.99.2 NH missing 'inactive reason:':\n{remaining}"
                    )
                break
        if not found_bad_nh:
            return "10.99.99.2 nexthop not found in plain-text output"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Plain-text inactive NH check failed: {result}"


def test_show_static_vrf_filter():
    """'show static routes vrf default' should work and match unfiltered output."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    output_all = _get_show_static_json(r1)
    output_filtered = json.loads(r1.vtysh_cmd("show static routes vrf default json"))

    # Both should have the default VRF with the same routes
    assert "default" in output_filtered, "missing 'default' in VRF-filtered output"
    all_routes = output_all["default"]["routes"]
    filtered_routes = output_filtered["default"]["routes"]
    assert len(all_routes) == len(filtered_routes), (
        f"route count mismatch: all={len(all_routes)} filtered={len(filtered_routes)}"
    )


def test_show_static_vrf_nonexistent():
    """'show static routes vrf BOGUS' should produce a warning."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    output = r1.vtysh_cmd("show static routes vrf BOGUS")
    assert "not found" in output or output.strip() == "", (
        f"Expected error for nonexistent VRF, got: {output}"
    )


def test_show_static_dynamic_route_add():
    """Adding a route dynamically should appear in show static routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Add a new static route
    r1.vtysh_cmd(
        """
        configure terminal
        ip route 172.16.99.0/24 10.1.0.2
        """
    )

    def _check():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        route = _find_route(routes, "172.16.99.0/24")
        if route is None:
            return "route 172.16.99.0/24 not found after adding"
        nh = route["paths"][0]["nexthops"][0]
        if nh.get("gateway") != "10.1.0.2":
            return f"unexpected gateway: {nh.get('gateway')}"
        if nh.get("active") is not True:
            return f"expected active=true, got {nh.get('active')}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, f"Dynamic route add check failed: {result}"

    # Clean up
    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 172.16.99.0/24 10.1.0.2
        """
    )


def test_show_static_dynamic_route_remove():
    """Removing a route should make it disappear from show static routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Add and then remove
    r1.vtysh_cmd(
        """
        configure terminal
        ip route 172.16.88.0/24 10.1.0.2
        """
    )

    def _check_present():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        if _find_route(routes, "172.16.88.0/24") is None:
            return "route 172.16.88.0/24 not found"
        return None

    _, result = topotest.run_and_expect(_check_present, None, count=30, wait=1)
    assert result is None, f"Route not present after add: {result}"

    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 172.16.88.0/24 10.1.0.2
        """
    )

    def _check_absent():
        output = _get_show_static_json(r1)
        routes = output["default"]["routes"]
        if _find_route(routes, "172.16.88.0/24") is not None:
            return "route 172.16.88.0/24 still present after removal"
        return None

    _, result = topotest.run_and_expect(_check_absent, None, count=30, wait=1)
    assert result is None, f"Route still present after remove: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
