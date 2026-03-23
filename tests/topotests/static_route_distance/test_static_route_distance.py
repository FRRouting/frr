#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test per-path administrative distance for static routes.

Design: administrative distance, metric, and tag live in static_path, which
is keyed by (table-id, distance, metric).  Tag is a modifiable leaf shared by
all nexthops in a path.  Different distances or metrics produce separate path
objects, enabling floating static routes (primary/backup) under a single
prefix.

Topology: r1 with three Ethernet interfaces, each connected to a switch
(s1/s2/s3), providing three independent nexthop addresses (NH1, NH2, NH3).
All tests run for both IPv4 and IPv6.

Test cases:

  1. AD replacement: reconfiguring the same nexthop with a new AD must
     update the existing RIB entry in place (NB_OP_MODIFY) and remove the
     stale old-distance zebra entry — not create a duplicate.

  2. Floating static route: two nexthops at different ADs under the same
     prefix; the lower-AD nexthop is active in the FIB and the higher-AD
     standby is promoted when the primary is removed.

  3. ECMP: two nexthops at the same AD are both active in the FIB.
     Removing one ECMP member leaves the other active at the same AD.

  4. ECMP with floating standby: primary ECMP group (NH1+NH2, AD 10) plus
     a standby (NH3, AD 20).  Removing primaries one by one shrinks the
     active group; the standby is promoted only when the last primary is
     removed.

  5. ECMP AD change (promote/demote): a nexthop moves in and out of the
     ECMP group by having its AD changed — covering both promotion
     (standby joins the ECMP group) and demotion (ECMP member becomes
     standby), and re-promotion back into the group.

  6. Delete standby only: deleting the standby nexthop must leave the
     primary completely unaffected; the standby RIB entry is fully
     withdrawn from zebra.

  7. Delete primary then standby: deleting the primary promotes the
     standby; deleting the standby fully withdraws the route from both
     RIB and FIB.

  8. Delete without distance and metric: 'no ip route X/M via Y' without
     distance and metric arguments performs a lazy search and removes the route
     regardless of the configured AD or metric.  Specifying distance or metric
     targets the exact (distance, metric) path group (unspecified parameters
     default to distance=1, metric=0).
"""
#

import functools
import json
import os
import sys

import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.staticd]

# Three nexthop addresses reachable via r1-eth0, eth1, eth2 respectively.
NH1_V4 = "192.0.2.2"
NH2_V4 = "198.51.100.2"
NH3_V4 = "203.0.113.2"
NH1_V6 = "2001:db8:0:1::2"
NH2_V6 = "2001:db8:0:2::2"
NH3_V6 = "2001:db8:0:3::2"

PREFIX_V4 = "10.0.0.0/24"
PREFIX_V6 = "2001:db8:f::/48"


def setup_module(mod):
    topodef = {"s1": ("r1",), "s2": ("r1",), "s3": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _route_distances(router, prefix, ipv6=False):
    """Return the set of administrative distances present in the RIB for prefix."""
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd(f"show ip{ip_ver} route {prefix} json")
    json_data = json.loads(output)
    if prefix not in json_data:
        return set()
    return {entry["distance"] for entry in json_data[prefix]}


def _route_nexthops(router, prefix, ipv6=False):
    """Return the set of nexthop IPs from the selected (best-path) route entry.

    The nexthop-level 'fib' flag in the JSON output indicates whether the nexthop group is installed
    in the kernel nexhop table — it can be true even for non-selected routes that
    share a nexhop group.  The route-level 'selected' flag is the correct
    indicator of which entry is the active best path.
    """
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd(f"show ip{ip_ver} route {prefix} json")
    json_data = json.loads(output)
    if prefix not in json_data:
        return set()
    active = set()
    for entry in json_data[prefix]:
        if not entry.get("selected"):
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("active"):
                active.add(nh.get("ip", nh.get("interfaceName", "")))
    return active


def _check_distances(router, prefix, expected, ipv6=False):
    """Return None when RIB distances equal expected, else return the actual set."""
    actual = _route_distances(router, prefix, ipv6)
    return None if actual == expected else actual


def _check_route(router, prefix, expected, ipv6=False):
    """Return None when active route nexthops equal expected, else return the actual set."""
    actual = _route_nexthops(router, prefix, ipv6)
    return None if actual == expected else actual


def _expect_distances(router, prefix, expected, ipv6=False):
    test_func = functools.partial(_check_distances, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


def _expect_route(router, prefix, expected, ipv6=False):
    test_func = functools.partial(_check_route, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


def _running_config_routes(router, prefix, ipv6=False):
    """Return the list of static-route lines for prefix in 'show running-config'."""
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd("show running-config")
    keyword = f"ip{ip_ver} route {prefix}"
    return [l.strip() for l in output.splitlines() if keyword in l]


def _check_running(router, prefix, expected_lines, ipv6=False):
    """Return None when running-config lines match expected_lines (as a set), else actual."""
    actual = set(_running_config_routes(router, prefix, ipv6))
    expected = set(expected_lines)
    return None if actual == expected else actual


def _expect_running(router, prefix, expected_lines, ipv6=False):
    test_func = functools.partial(
        _check_running, router, prefix, expected_lines, ipv6
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


# ---------------------------------------------------------------------------
# Test: AD replacement
# ---------------------------------------------------------------------------

def run_ad_replacement(ipv6=False):
    """
    Same nexthop reconfigured with a new AD must replace the old RIB entry
    and leave running-config with exactly one entry at the new AD.

    Steps:
      1. Install route via NH1 at AD 10.
      2. Reconfigure the same route via NH1 at AD 20.
      3. Verify only AD 20 is present in RIB; AD 10 entry is gone.
      4. Verify running-config shows exactly 'ip route ... NH1 20', not the old '... 10'.
      5. Clean up; verify running-config is empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: install at AD 10
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10\n")
    result = _expect_distances(r1, prefix, {10}, ipv6)
    assert result is None, f"AD replacement [1]: expected {{10}}, got {result}"

    # Step 2: same nexthop, new AD — must replace, not duplicate
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 20\n")
    result = _expect_distances(r1, prefix, {20}, ipv6)
    assert result is None, (
        f"AD replacement [2]: stale AD 10 present or AD 20 missing; got {result}"
    )

    # Step 3: running-config must show exactly one entry at AD 20, not AD 10
    expected_line = f"ip{ip_ver} route {prefix} {nh1} 20"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"AD replacement [3]: running-config mismatch; got {result}"
    )

    # Step 4: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 20\n")
    result = _expect_distances(r1, prefix, set(), ipv6)
    assert result is None, f"AD replacement [cleanup]: route not removed; got {result}"
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"AD replacement [cleanup]: stale running-config entry; got {result}"
    )


def test_ad_replacement_ipv4():
    "Same IPv4 nexthop reconfigured with new AD replaces old RIB entry."
    run_ad_replacement(ipv6=False)


def test_ad_replacement_ipv6():
    "Same IPv6 nexthop reconfigured with new AD replaces old RIB entry."
    run_ad_replacement(ipv6=True)


# ---------------------------------------------------------------------------
# Test: floating static route (two different nexthops, different ADs)
# ---------------------------------------------------------------------------

def run_floating_static(ipv6=False):
    """
    Two nexthops under the same prefix with independent ADs.

    Steps:
      1. Install primary NH1 at AD 10 and standby NH2 at AD 20.
      2. Verify NH1 is active in FIB (lower AD wins).
      3. Remove NH1; verify NH2 is promoted to active.
      4. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: primary + standby
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10\n"
        f"ip{ip_ver} route {prefix} {nh2} 20\n"
    )
    result = _expect_distances(r1, prefix, {10, 20}, ipv6)
    assert result is None, f"Floating static [1]: expected {{10,20}}, got {result}"

    # Step 2: lower-AD nexthop active
    result = _expect_route(r1, prefix, {nh1}, ipv6)
    assert result is None, f"Floating static [2]: expected {nh1} active, got {result}"

    # Step 3: remove primary → standby promoted
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n")
    result = _expect_route(r1, prefix, {nh2}, ipv6)
    assert result is None, (
        f"Floating static [3]: expected {nh2} active after primary removed, got {result}"
    )

    # Step 4: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh2} 20\n")
    result = _expect_distances(r1, prefix, set(), ipv6)
    assert result is None, f"Floating static [cleanup]: route not removed; got {result}"


def test_floating_static_ipv4():
    "IPv4 floating static: lower-AD nexthop active, standby promoted on primary removal."
    run_floating_static(ipv6=False)


def test_floating_static_ipv6():
    "IPv6 floating static: lower-AD nexthop active, standby promoted on primary removal."
    run_floating_static(ipv6=True)


# ---------------------------------------------------------------------------
# Test: ECMP (multiple nexthops at the same AD)
# ---------------------------------------------------------------------------

def run_ecmp(ipv6=False):
    """
    Two nexthops at the same AD are both active in the FIB (ECMP).
    Removing one ECMP member leaves the remaining one active.

    Steps:
      1. Install NH1 and NH2 both at AD 10.
      2. Verify both are active in FIB.
      3. Remove NH1; verify NH2 remains active at AD 10.
      4. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: two nexthops at same AD
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10\n"
        f"ip{ip_ver} route {prefix} {nh2} 10\n"
    )
    result = _expect_distances(r1, prefix, {10}, ipv6)
    assert result is None, f"ECMP [1]: expected single AD {{10}}, got {result}"

    # Step 2: both nexthops active (ECMP)
    result = _expect_route(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, f"ECMP [2]: expected both {nh1},{nh2} active, got {result}"

    # Step 3: remove one ECMP member
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n")
    result = _expect_route(r1, prefix, {nh2}, ipv6)
    assert result is None, (
        f"ECMP [3]: expected only {nh2} active after {nh1} removed, got {result}"
    )
    result = _expect_distances(r1, prefix, {10}, ipv6)
    assert result is None, f"ECMP [3]: AD should still be {{10}}, got {result}"

    # Step 4: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh2} 10\n")
    result = _expect_distances(r1, prefix, set(), ipv6)
    assert result is None, f"ECMP [cleanup]: route not removed; got {result}"


def test_ecmp_ipv4():
    "IPv4 ECMP: two nexthops at same AD both active; removing one leaves the other."
    run_ecmp(ipv6=False)


def test_ecmp_ipv6():
    "IPv6 ECMP: two nexthops at same AD both active; removing one leaves the other."
    run_ecmp(ipv6=True)


# ---------------------------------------------------------------------------
# Test: ECMP with floating standby
# ---------------------------------------------------------------------------

def run_ecmp_with_standby(ipv6=False):
    """
    ECMP primary group (NH1+NH2 at AD 10) plus a floating standby (NH3 at AD 20).

    Steps:
      1. Install NH1, NH2 at AD 10 and NH3 at AD 20.
      2. Verify NH1 and NH2 are active (ECMP); NH3 is in RIB but not FIB.
      3. Remove NH1; verify NH2 is the sole active nexhop at AD 10.
         NH3 remains standby (still not in FIB).
      4. Remove NH2 (last primary); verify NH3 is promoted to active.
      5. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    nh3 = NH3_V6 if ipv6 else NH3_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: ECMP primary + standby
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10\n"
        f"ip{ip_ver} route {prefix} {nh2} 10\n"
        f"ip{ip_ver} route {prefix} {nh3} 20\n"
    )
    result = _expect_distances(r1, prefix, {10, 20}, ipv6)
    assert result is None, f"ECMP+standby [1]: expected {{10,20}}, got {result}"

    # Step 2: NH1+NH2 active (ECMP), NH3 standby (not in FIB)
    result = _expect_route(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, (
        f"ECMP+standby [2]: expected {nh1},{nh2} active (ECMP), got {result}"
    )

    # Step 3: remove NH1 — NH2 sole primary, NH3 still standby
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n")
    result = _expect_route(r1, prefix, {nh2}, ipv6)
    assert result is None, (
        f"ECMP+standby [3]: expected only {nh2} active, NH3 still standby, got {result}"
    )
    result = _expect_distances(r1, prefix, {10, 20}, ipv6)
    assert result is None, (
        f"ECMP+standby [3]: expected {{10,20}} in RIB, got {result}"
    )

    # Step 4: remove last primary NH2 — standby NH3 promoted
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh2} 10\n")
    result = _expect_route(r1, prefix, {nh3}, ipv6)
    assert result is None, (
        f"ECMP+standby [4]: expected {nh3} promoted after all primaries removed, got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh3} 20\n")
    result = _expect_distances(r1, prefix, set(), ipv6)
    assert result is None, f"ECMP+standby [cleanup]: route not removed; got {result}"


def test_ecmp_with_standby_ipv4():
    "IPv4 ECMP primary group with floating standby; standby promoted when all primaries removed."
    run_ecmp_with_standby(ipv6=False)


def test_ecmp_with_standby_ipv6():
    "IPv6 ECMP primary group with floating standby; standby promoted when all primaries removed."
    run_ecmp_with_standby(ipv6=True)


# ---------------------------------------------------------------------------
# Test: promote/demote nexthops by changing AD
# ---------------------------------------------------------------------------

def run_ecmp_ad_change(ipv6=False):
    """
    A nexthop moves in and out of the ECMP group by having its AD changed.

    Steps:
      1. NH1 at AD 10 (sole primary), NH2 at AD 20 (standby).
         Verify NH1 active, NH2 not in FIB.
      2. Change NH2 AD 20 → 10: NH2 joins the ECMP group.
         Verify both NH1 and NH2 active; only AD 10 in RIB (AD 20 gone).
      3. Change NH1 AD 10 → 20: NH1 leaves the ECMP group and becomes standby.
         Verify NH2 sole primary at AD 10; NH1 standby at AD 20.
      4. Change NH1 AD 20 → 10: NH1 rejoins the ECMP group.
         Verify both NH1 and NH2 active again at AD 10.
      5. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: NH1 primary at AD 10, NH2 standby at AD 20
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10\n"
        f"ip{ip_ver} route {prefix} {nh2} 20\n"
    )
    result = _expect_route(r1, prefix, {nh1}, ipv6)
    assert result is None, f"ECMP AD change [1]: expected only {nh1} active, got {result}"
    result = _expect_distances(r1, prefix, {10, 20}, ipv6)
    assert result is None, f"ECMP AD change [1]: expected {{10,20}} in RIB, got {result}"

    # Step 2: promote NH2 into ECMP group (AD 20 → 10)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} 10\n")
    result = _expect_route(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, (
        f"ECMP AD change [2]: expected both {nh1},{nh2} active after NH2 promoted, got {result}"
    )
    result = _expect_distances(r1, prefix, {10}, ipv6)
    assert result is None, (
        f"ECMP AD change [2]: stale AD 20 still present after NH2 promoted, got {result}"
    )
    # running-config: both nexthops at AD 10, no stale AD 20 entry
    result = _expect_running(
        r1, prefix,
        [f"ip{ip_ver} route {prefix} {nh1} 10",
         f"ip{ip_ver} route {prefix} {nh2} 10"],
        ipv6,
    )
    assert result is None, (
        f"ECMP AD change [2]: running-config mismatch after NH2 promoted; got {result}"
    )

    # Step 3: demote NH1 to standby (AD 10 → 20)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 20\n")
    result = _expect_route(r1, prefix, {nh2}, ipv6)
    assert result is None, (
        f"ECMP AD change [3]: expected only {nh2} active after NH1 demoted, got {result}"
    )
    result = _expect_distances(r1, prefix, {10, 20}, ipv6)
    assert result is None, (
        f"ECMP AD change [3]: expected {{10,20}} in RIB after NH1 demoted, got {result}"
    )
    # running-config: NH2 at AD 10 (primary), NH1 at AD 20 (standby), no duplicate
    result = _expect_running(
        r1, prefix,
        [f"ip{ip_ver} route {prefix} {nh2} 10",
         f"ip{ip_ver} route {prefix} {nh1} 20"],
        ipv6,
    )
    assert result is None, (
        f"ECMP AD change [3]: running-config mismatch after NH1 demoted; got {result}"
    )

    # Step 4: NH1 rejoins ECMP group (AD 20 → 10)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10\n")
    result = _expect_route(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, (
        f"ECMP AD change [4]: expected both {nh1},{nh2} active after NH1 rejoined, got {result}"
    )
    result = _expect_distances(r1, prefix, {10}, ipv6)
    assert result is None, (
        f"ECMP AD change [4]: stale AD 20 still present after NH1 rejoined, got {result}"
    )
    # running-config: both nexthops at AD 10, no stale AD 20 entry
    result = _expect_running(
        r1, prefix,
        [f"ip{ip_ver} route {prefix} {nh1} 10",
         f"ip{ip_ver} route {prefix} {nh2} 10"],
        ipv6,
    )
    assert result is None, (
        f"ECMP AD change [4]: running-config mismatch after NH1 rejoined; got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10\n"
        f"no ip{ip_ver} route {prefix} {nh2} 10\n"
    )
    result = _expect_distances(r1, prefix, set(), ipv6)
    assert result is None, f"ECMP AD change [cleanup]: route not removed; got {result}"
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"ECMP AD change [cleanup]: stale running-config entry; got {result}"
    )


def test_ecmp_ad_change_ipv4():
    "IPv4: nexthop moves in and out of ECMP group by changing its AD."
    run_ecmp_ad_change(ipv6=False)


def test_ecmp_ad_change_ipv6():
    "IPv6: nexthop moves in and out of ECMP group by changing its AD."
    run_ecmp_ad_change(ipv6=True)


# ---------------------------------------------------------------------------
# Test: targeted deletion scenarios
# ---------------------------------------------------------------------------

def run_delete_standby(ipv6=False):
    """
    Deleting the standby nexhop must not affect the active primary.

    Steps:
      1. NH1 at AD 10 (primary), NH2 at AD 20 (standby).
      2. Delete NH2 (standby only).
      3. Verify NH1 still active; AD 20 entry completely gone from RIB.
      4. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: primary + standby
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10\n"
        f"ip{ip_ver} route {prefix} {nh2} 20\n"
    )
    result = _expect_distances(r1, prefix, {10, 20}, ipv6)
    assert result is None, f"Delete standby [1]: expected {{10,20}}, got {result}"

    # Step 2: delete standby only
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh2} 20\n")

    # Step 3: primary unaffected; standby RIB entry completely withdrawn
    result = _expect_distances(r1, prefix, {10}, ipv6)
    assert result is None, (
        f"Delete standby [3]: expected only {{10}} in RIB after standby deleted, got {result}"
    )
    result = _expect_route(r1, prefix, {nh1}, ipv6)
    assert result is None, (
        f"Delete standby [3]: primary {nh1} should still be active, got {result}"
    )

    # Step 4: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n")
    result = _expect_distances(r1, prefix, set(), ipv6)
    assert result is None, f"Delete standby [cleanup]: route not fully removed, got {result}"


def run_delete_primary_then_standby(ipv6=False):
    """
    Delete primary first (standby takes over), then delete standby; route must
    be completely withdrawn from RIB and FIB after the last nexhop is removed.

    Steps:
      1. NH1 at AD 10 (primary), NH2 at AD 20 (standby).
      2. Delete NH1; verify NH2 promoted and AD 10 entry gone.
      3. Delete NH2; verify route is completely gone from RIB and FIB.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: primary + standby
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10\n"
        f"ip{ip_ver} route {prefix} {nh2} 20\n"
    )
    result = _expect_distances(r1, prefix, {10, 20}, ipv6)
    assert result is None, f"Delete primary+standby [1]: expected {{10,20}}, got {result}"

    # Step 2: delete primary — standby promoted, AD 10 entry gone
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n")
    result = _expect_distances(r1, prefix, {20}, ipv6)
    assert result is None, (
        f"Delete primary+standby [2]: expected only {{20}} after primary deleted, got {result}"
    )
    result = _expect_route(r1, prefix, {nh2}, ipv6)
    assert result is None, (
        f"Delete primary+standby [2]: expected {nh2} promoted to active, got {result}"
    )

    # Step 3: delete standby — route fully withdrawn
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh2} 20\n")
    result = _expect_distances(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Delete primary+standby [3]: route should be fully gone, got {result}"
    )
    result = _expect_route(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Delete primary+standby [3]: FIB entry should be gone, got {result}"
    )


def test_delete_standby_ipv4():
    "IPv4: deleting the standby nexhop leaves the primary completely unaffected."
    run_delete_standby(ipv6=False)


def test_delete_standby_ipv6():
    "IPv6: deleting the standby nexhop leaves the primary completely unaffected."
    run_delete_standby(ipv6=True)


def test_delete_primary_then_standby_ipv4():
    "IPv4: delete primary (standby promoted), then delete standby (route fully withdrawn)."
    run_delete_primary_then_standby(ipv6=False)


def test_delete_primary_then_standby_ipv6():
    "IPv6: delete primary (standby promoted), then delete standby (route fully withdrawn)."
    run_delete_primary_then_standby(ipv6=True)


# ---------------------------------------------------------------------------
# Test: deletion without specifying distance
# ---------------------------------------------------------------------------

def run_delete_without_distance(ipv6=False):
    """
    'no ip route X/M via Y' without distance and metric arguments performs a
    lazy search: it finds and removes the nexthop regardless of what AD or
    metric was configured.  Specifying either distance or metric switches to
    exact-match mode (unspecified parameter defaults to distance=1 or metric=0).

    Steps:
      1. Install route via NH1 at non-default AD 50.
      2. Delete using 'no ip route X/M via NH1' with no distance specified.
      3. Verify route is completely gone.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: install at non-default AD 50
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 50\n")
    result = _expect_distances(r1, prefix, {50}, ipv6)
    assert result is None, f"Delete without distance [1]: expected {{50}}, got {result}"

    # Step 2: delete without specifying distance
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1}\n")

    # Step 3: route must be gone from RIB and running-config
    result = _expect_distances(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Delete without distance [3]: route at AD 50 not removed by 'no' without distance; got {result}"
    )
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Delete without distance [3]: stale running-config entry after delete; got {result}"
    )


def test_delete_without_distance_ipv4():
    "IPv4: 'no ip route X/M via Y' without distance and metric removes the route regardless of the configured AD or metric."
    run_delete_without_distance(ipv6=False)


def test_delete_without_distance_ipv6():
    "IPv6: 'no ip route X/M via Y' without distance and metric removes the route regardless of the configured AD or metric."
    run_delete_without_distance(ipv6=True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
