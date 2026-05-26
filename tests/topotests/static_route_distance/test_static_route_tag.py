#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test per-path tag for static routes.

Design: tag lives in static_path alongside distance and metric.  The
path-list key is nexthop identity (table-id, nh-type, vrf, gateway,
interface); distance, metric, and tag are non-key attributes.  Nexthops
sharing the same (distance, metric) form one ECMP group; tag is shared by
all nexthops in a group and is not part of the group identity.

Max-wins: when multiple nexthops in the same path group carry different
tags, the maximum nh->tag is used for the RIB.  On nexthop deletion, if
the deleted nexthop carried the current maximum, the tag is recalculated
to the maximum of the remaining nexthops' tags.  Max-wins is order-
independent, so the per-leaf callbacks are idempotent.

Topology: r1 with three Ethernet interfaces, each connected to a switch
(s1/s2/s3), providing three independent nexthop addresses (NH1, NH2, NH3).
All tests run for both IPv4 and IPv6.

Test cases:

  1. Basic tag: install a route with a tag; verify the tag appears in
     the RIB (show ip route json) and in running-config.

  2. Tag per path: NH1@AD10+tag=100 and NH2@AD20+tag=200.  Each path
     carries an independent tag.  Verify both paths have the correct
     tags in the RIB and running-config.

  3. Tag change: change the tag on an existing path; verify the new tag
     is reflected in the RIB and running-config, and the old tag is gone.

  4. Tag with AD change: NH1@AD10+tag=100 reconfigured to AD20+tag=200.
     Verify running-config shows exactly one entry at the new (AD, tag)
     with no stale entry at the old (AD, tag).

  4b. Tag preserved on AD-only change: NH1@AD10+tag=100 reconfigured to
     AD20+tag=100.  tag_modify does not re-fire; static_path_recalc_tag()
     must carry the tag to the new struct static_path.  Verify tag=100
     survives in the RIB and running-config.

  5. Same AD, different tag: NH1@AD10+tag=100 and NH2@AD10+tag=200.  Both
     share one struct static_path.  Max-wins: pn->tag = max(100, 200) =
     200.  YANG stores the operator-configured values per nexthop.  When
     NH2 (the max-tag holder) is removed, recalculation drops pn->tag to
     NH1's tag (100) in the RIB.

  6. Delete non-max: with NH1/tag=100 and NH2/tag=200 (max is 200),
     removing NH1 (the non-max nexthop) leaves pn->tag unchanged at 200.
     No recalculation fires when the deleted nexthop's tag is below the
     current max.

  7. Three nexthops, delete max-tag holder: NH1/tag=100, NH2/tag=200,
     NH3/tag=300 at the same AD.  pn->tag = 300.  Removing NH3 triggers
     recalculation; max(100, 200) = 200.  NH1 and NH2 remain as a
     two-nexthop ECMP group.

  8. Running-config format (tag + distance + metric): verify that all three
     non-default attributes appear correctly — 'ip route PREFIX NH tag T D
     metric M' — and that the default distance (1) is omitted when not set.

  9. Re-add a max-tag holder: NH2 is removed (recalc → NH1's tag becomes
     the new max), then re-added with a higher tag.  The re-added NH2
     becomes the new max and its tag takes effect.  A second removal of
     NH2 again recalculates correctly to NH1's tag.

  10. Tag recalculated when max-tag holder changes distance: NH2/tag=50
     and NH1/tag=100 share the same path at AD=10; NH1 carries the max
     (pn->tag=100).  Changing NH1's distance to 20 moves it to a new
     path.  The old path (AD=10, NH2 only) must reflect NH2's tag (50);
     the new path (AD=20, NH1) carries tag=100.

  11. Tag recalculated when max-tag holder changes metric: same setup as
     test 10 but NH1's metric changes from 100 to 200.  The old path
     (metric=100, NH2 only) must reflect NH2's tag (50); the new path
     (metric=200, NH1) carries tag=100.

  12. Tag preserved when non-max nexthop changes distance: NH2/tag=50 and
     NH1/tag=100 share AD=10; NH1 carries the max.  Changing NH2's (non-
     max) distance to 20 skips the old-path recalculation (the
     if (old_pn->tag == nh->tag) branch is false).  The old path (AD=10,
     NH1 only) must retain tag=100 unchanged.

  13. Tag recalculated when nexthop moves onto an existing tagged path:
     NH1@AD10+tag=50 and NH2@AD20+tag=100.  NH2 is reconfigured to AD=10,
     joining NH1's existing path.  static_path_recalc_tag(new_pn) selects
     NH2's tag because max(50, 100) = 100; the path tag becomes 100.
     The old AD=20 path is deleted.
"""

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

def _route_entries(router, prefix, ipv6=False):
    """Return the list of route-entry dicts from 'show ip route json'."""
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd(f"show ip{ip_ver} route {prefix} json")
    json_data = json.loads(output)
    return json_data.get(prefix, [])


def _route_tag_by_distance(router, prefix, ipv6=False):
    """Return dict mapping distance -> tag for RIB entries of prefix.

    Only valid when at most one entry exists per distance value.  When
    multiple entries share the same distance (different tags), use
    _route_nexthop_tags() instead.
    """
    return {
        e.get("distance", 0): e.get("tag", 0)
        for e in _route_entries(router, prefix, ipv6)
    }


def _route_nexthop_tags(router, prefix, ipv6=False):
    """Return set of (nexthop_ip, tag) tuples from RIB entries for prefix.

    Iterates all route entries and all nexthops within each entry,
    pairing each nexthop IP with the route-entry level tag.
    """
    result = set()
    for entry in _route_entries(router, prefix, ipv6):
        tag = entry.get("tag", 0)
        for nh in entry.get("nexthops", []):
            ip = nh.get("ip", "")
            if ip:
                result.add((ip, tag))
    return result


def _running_config_routes(router, prefix, ipv6=False):
    """Return static-route lines for prefix from 'show running-config'."""
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd("show running-config")
    keyword = f"ip{ip_ver} route {prefix}"
    return [l.strip() for l in output.splitlines() if keyword in l]


def _check_rib_tags(router, prefix, expected, ipv6=False):
    """Return None when {distance: tag} map equals expected, else actual."""
    actual = _route_tag_by_distance(router, prefix, ipv6)
    return None if actual == expected else actual


def _check_running(router, prefix, expected_lines, ipv6=False):
    """Return None when running-config lines equal expected (as set), else actual."""
    actual = set(_running_config_routes(router, prefix, ipv6))
    return None if actual == set(expected_lines) else actual


def _expect_rib_tags(router, prefix, expected, ipv6=False):
    test_func = functools.partial(_check_rib_tags, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


def _expect_running(router, prefix, expected_lines, ipv6=False):
    test_func = functools.partial(
        _check_running, router, prefix, expected_lines, ipv6
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


def _route_tag_by_dist_metric(router, prefix, ipv6=False):
    """Return dict mapping (distance, metric) -> tag for RIB entries of prefix."""
    return {
        (e.get("distance", 0), e.get("metric", 0)): e.get("tag", 0)
        for e in _route_entries(router, prefix, ipv6)
    }


def _check_rib_tags_by_dist_metric(router, prefix, expected, ipv6=False):
    """Return None when {(dist, metric): tag} map equals expected, else actual."""
    actual = _route_tag_by_dist_metric(router, prefix, ipv6)
    return None if actual == expected else actual


def _expect_rib_tags_by_dist_metric(router, prefix, expected, ipv6=False):
    test_func = functools.partial(_check_rib_tags_by_dist_metric, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


# ---------------------------------------------------------------------------
# Test 1: basic tag
# ---------------------------------------------------------------------------

def run_basic_tag(ipv6=False):
    """
    Install a route with a tag; verify tag in RIB and running-config.

    Steps:
      1. Install NH1 at AD 10 with tag 100.
      2. Verify RIB entry at AD 10 carries tag 100.
      3. Verify running-config shows 'ip route ... NH1 tag 100 10'.
      4. Clean up; verify RIB and running-config are empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: install with tag
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
    )

    # Step 2: RIB shows tag 100 at AD 10
    result = _expect_rib_tags(r1, prefix, {10: 100}, ipv6)
    assert result is None, f"Basic tag [2]: expected {{10: 100}}, got {result}"

    # Step 3: running-config shows tag
    expected_line = f"ip{ip_ver} route {prefix} {nh1} tag 100 10"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, f"Basic tag [3]: running-config mismatch; got {result}"

    # Step 4: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
    )
    result = _expect_rib_tags(r1, prefix, {}, ipv6)
    assert result is None, f"Basic tag [cleanup]: RIB not empty; got {result}"
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Basic tag [cleanup]: stale running-config entry; got {result}"
    )


def test_basic_tag_ipv4():
    "IPv4: route with tag appears with correct tag in RIB and running-config."
    run_basic_tag(ipv6=False)


def test_basic_tag_ipv6():
    "IPv6: route with tag appears with correct tag in RIB and running-config."
    run_basic_tag(ipv6=True)


# ---------------------------------------------------------------------------
# Test 2: tag per path
# ---------------------------------------------------------------------------

def run_tag_per_path(ipv6=False):
    """
    Two nexthops at different ADs carry independent tags.

    Steps:
      1. Install NH1 at AD 10 with tag 100, NH2 at AD 20 with tag 200.
      2. Verify RIB: AD 10 entry has tag 100, AD 20 entry has tag 200.
      3. Verify running-config shows both lines with correct tags.
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

    # Step 1: two paths with different tags
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 20 tag 200\n"
    )

    # Step 2: each path has its own tag in the RIB
    result = _expect_rib_tags(r1, prefix, {10: 100, 20: 200}, ipv6)
    assert result is None, (
        f"Tag per path [2]: expected {{10:100, 20:200}}, got {result}"
    )

    # Step 3: running-config shows both lines with correct tags
    result = _expect_running(
        r1, prefix,
        [
            f"ip{ip_ver} route {prefix} {nh1} tag 100 10",
            f"ip{ip_ver} route {prefix} {nh2} tag 200 20",
        ],
        ipv6,
    )
    assert result is None, (
        f"Tag per path [3]: running-config mismatch; got {result}"
    )

    # Step 4: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"no ip{ip_ver} route {prefix} {nh2} 20 tag 200\n"
    )
    result = _expect_rib_tags(r1, prefix, {}, ipv6)
    assert result is None, f"Tag per path [cleanup]: RIB not empty; got {result}"
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Tag per path [cleanup]: stale running-config entry; got {result}"
    )


def test_tag_per_path_ipv4():
    "IPv4: two paths at different ADs carry independent tags."
    run_tag_per_path(ipv6=False)


def test_tag_per_path_ipv6():
    "IPv6: two paths at different ADs carry independent tags."
    run_tag_per_path(ipv6=True)


# ---------------------------------------------------------------------------
# Test 3: tag change
# ---------------------------------------------------------------------------

def run_tag_change(ipv6=False):
    """
    Changing the tag on an existing path updates the RIB and running-config.

    Steps:
      1. Install NH1 at AD 10 with tag 100.
      2. Reconfigure with tag 200 (same nexthop, same AD).
      3. Verify RIB shows tag 200; old tag 100 is gone.
      4. Verify running-config shows 'tag 200', not 'tag 100'.
      5. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: install with tag 100
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
    )
    result = _expect_rib_tags(r1, prefix, {10: 100}, ipv6)
    assert result is None, f"Tag change [1]: expected {{10:100}}, got {result}"

    # Step 2: reconfigure with tag 200
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 200\n"
    )

    # Step 3: RIB shows tag 200
    result = _expect_rib_tags(r1, prefix, {10: 200}, ipv6)
    assert result is None, (
        f"Tag change [3]: expected {{10:200}}, got {result}"
    )

    # Step 4: running-config shows tag 200, not tag 100
    expected_line = f"ip{ip_ver} route {prefix} {nh1} tag 200 10"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"Tag change [4]: running-config mismatch; got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 10 tag 200\n"
    )
    result = _expect_rib_tags(r1, prefix, {}, ipv6)
    assert result is None, f"Tag change [cleanup]: RIB not empty; got {result}"
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Tag change [cleanup]: stale running-config entry; got {result}"
    )


def test_tag_change_ipv4():
    "IPv4: changing the tag on a path updates RIB and running-config."
    run_tag_change(ipv6=False)


def test_tag_change_ipv6():
    "IPv6: changing the tag on a path updates RIB and running-config."
    run_tag_change(ipv6=True)


# ---------------------------------------------------------------------------
# Test 4: tag with AD change
# ---------------------------------------------------------------------------

def run_tag_with_ad_change(ipv6=False):
    """
    Moving a nexthop to a new AD with a new tag leaves exactly one entry.

    Steps:
      1. Install NH1 at AD 10 with tag 100.
      2. Reconfigure NH1 at AD 20 with tag 200 (single command; move logic
         removes the old entry automatically).
      3. Verify RIB has only AD 20 with tag 200; AD 10 entry is gone.
      4. Verify running-config shows exactly 'ip route ... NH1 tag 200 20'.
      5. Clean up; verify RIB and running-config are empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: install at AD 10, tag 100
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
    )
    result = _expect_rib_tags(r1, prefix, {10: 100}, ipv6)
    assert result is None, f"Tag+AD change [1]: expected {{10:100}}, got {result}"

    # Step 2: move to AD 20 with tag 200
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 20 tag 200\n"
    )

    # Step 3: only AD 20 with tag 200 in RIB
    result = _expect_rib_tags(r1, prefix, {20: 200}, ipv6)
    assert result is None, (
        f"Tag+AD change [3]: expected {{20:200}}, stale AD 10 present or tag wrong; got {result}"
    )

    # Step 4: running-config shows exactly one entry at (AD 20, tag 200)
    expected_line = f"ip{ip_ver} route {prefix} {nh1} tag 200 20"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"Tag+AD change [4]: running-config mismatch; got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 20 tag 200\n"
    )
    result = _expect_rib_tags(r1, prefix, {}, ipv6)
    assert result is None, f"Tag+AD change [cleanup]: RIB not empty; got {result}"
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Tag+AD change [cleanup]: stale running-config entry; got {result}"
    )


def test_tag_with_ad_change_ipv4():
    "IPv4: nexthop moved to new AD with new tag leaves exactly one RIB/config entry."
    run_tag_with_ad_change(ipv6=False)


def test_tag_with_ad_change_ipv6():
    "IPv6: nexthop moved to new AD with new tag leaves exactly one RIB/config entry."
    run_tag_with_ad_change(ipv6=True)


# ---------------------------------------------------------------------------
# Test 4b: tag preserved when only AD changes (tag_modify does not re-fire)
# ---------------------------------------------------------------------------

def run_tag_preserved_on_ad_change(ipv6=False):
    """
    When only the AD changes (tag stays the same), the tag must survive the
    nexthop move.  tag_modify does not re-fire in this case, so the path
    relies on static_path_recalc_tag() to carry the tag to the new
    struct static_path.

    Steps:
      1. Install NH1 at AD 10 with tag 100.
      2. Reconfigure NH1 at AD 20, keeping tag 100.
      3. Verify RIB has only AD 20 with tag 100 (tag not lost).
      4. Verify running-config shows 'ip route ... NH1 tag 100 20'.
      5. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: install at AD 10, tag 100
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
    )
    result = _expect_rib_tags(r1, prefix, {10: 100}, ipv6)
    assert result is None, f"Tag preserved AD change [1]: expected {{10:100}}, got {result}"

    # Step 2: change only the AD to 20 (tag 100 unchanged)
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 20 tag 100\n"
    )

    # Step 3: RIB must show AD 20 with tag 100, not 0
    result = _expect_rib_tags(r1, prefix, {20: 100}, ipv6)
    assert result is None, (
        f"Tag preserved AD change [3]: tag lost after AD move; expected {{20:100}}, got {result}"
    )

    # Step 4: running-config shows the new entry
    expected_line = f"ip{ip_ver} route {prefix} {nh1} tag 100 20"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"Tag preserved AD change [4]: running-config mismatch; got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 20 tag 100\n"
    )
    result = _expect_rib_tags(r1, prefix, {}, ipv6)
    assert result is None, f"Tag preserved AD change [cleanup]: RIB not empty; got {result}"


def test_tag_preserved_on_ad_change_ipv4():
    "IPv4: tag survives a change to AD alone (tag_modify does not re-fire on AD change)."
    run_tag_preserved_on_ad_change(ipv6=False)


def test_tag_preserved_on_ad_change_ipv6():
    "IPv6: tag survives a change to AD alone (tag_modify does not re-fire on AD change)."
    run_tag_preserved_on_ad_change(ipv6=True)


# ---------------------------------------------------------------------------
# Helpers for same-AD tests
# ---------------------------------------------------------------------------

def _check_nexthop_tags(router, prefix, expected, ipv6=False):
    """Return None when (nexthop_ip, tag) set equals expected, else actual."""
    actual = _route_nexthop_tags(router, prefix, ipv6)
    return None if actual == expected else actual


def _expect_nexthop_tags(router, prefix, expected, ipv6=False):
    test_func = functools.partial(_check_nexthop_tags, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


# ---------------------------------------------------------------------------
# Test 5: same AD, different tag
# ---------------------------------------------------------------------------

def run_same_ad_different_tag(ipv6=False):
    """
    Both nexthops share one struct static_path (keyed by distance+metric).
    Max-wins in the RIB: pn->tag is the maximum nh->tag across the path.

    YANG stores what each nexthop was individually configured with.
    The C backend holds one shared path tag (pn->tag) and recalculates it
    as the new max when a nexthop is removed.

    Steps:
      1. Install NH1 at AD 10 with tag 100, NH2 at AD 10 with tag 200.
      2. Verify running-config shows NH1 with tag 100 and NH2 with tag 200
         (YANG stores the operator-configured values per nexthop).
      3. Verify RIB has both NHs as ECMP at AD 10, both with tag 200
         (max(100, 200) = 200).
      4. Remove NH2 (the max-tag holder); verify pn->tag is recalculated
         to max(100) = 100 — NH1 survives in config and RIB with tag 100.
      5. Clean up NH1; verify RIB and running-config are empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: two nexthops at same AD with independent tags
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 tag 200\n"
    )

    # Step 2: YANG datastore stores the operator-configured values, so
    # running-config shows NH1 with tag 100 and NH2 with tag 200.
    result = _expect_running(
        r1, prefix,
        [
            f"ip{ip_ver} route {prefix} {nh1} tag 100 10",
            f"ip{ip_ver} route {prefix} {nh2} tag 200 10",
        ],
        ipv6,
    )
    assert result is None, (
        f"Same-AD diff-tag [2]: running-config mismatch; got {result}"
    )

    # Step 3: RIB shows both NHs as ECMP at AD 10, both with tag 200.
    # Max-wins: max(100, 200) = 200.
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 200), (nh2, 200)}, ipv6)
    assert result is None, (
        f"Same-AD diff-tag [3]: expected ECMP {{(NH1,200),(NH2,200)}}; got {result}"
    )

    # Step 4: remove NH2 (the max-tag holder, tag=200).
    # pn->tag == nh->tag (200 == 200) triggers recalculation: max of the
    # remaining nexthops is NH1's tag (100), so pn->tag = 100.
    # Verify NH1 in running-config with tag 100 and in RIB with tag 100.
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh2} 10\n"
    )
    result = _expect_running(
        r1, prefix,
        [f"ip{ip_ver} route {prefix} {nh1} tag 100 10"],
        ipv6,
    )
    assert result is None, (
        f"Same-AD diff-tag [4]: NH1 config wrong after removing NH2; got {result}"
    )
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 100)}, ipv6)
    assert result is None, (
        f"Same-AD diff-tag [4]: NH1 not in RIB with tag 100 after removing NH2; got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n"
    )
    result = _expect_nexthop_tags(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Same-AD diff-tag [cleanup]: RIB not empty; got {result}"
    )
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Same-AD diff-tag [cleanup]: stale running-config entry; got {result}"
    )


def test_same_ad_different_tag_ipv4():
    "IPv4: same-AD nexthops share RIB tag via max-wins; YANG stores per-nexthop values."
    run_same_ad_different_tag(ipv6=False)


def test_same_ad_different_tag_ipv6():
    "IPv6: same-AD nexthops share RIB tag via max-wins; YANG stores per-nexthop values."
    run_same_ad_different_tag(ipv6=True)


# ---------------------------------------------------------------------------
# Test 6: delete non-max leaves RIB tag unchanged
# ---------------------------------------------------------------------------

def run_delete_non_max(ipv6=False):
    """
    Deleting a nexthop whose tag is below the current max leaves the RIB
    tag intact.

    NH1/tag=100 and NH2/tag=200 share AD=10; pn->tag = max(100, 200) = 200.
    NH1's tag (100) is below the max, so removing NH1 must not trigger a
    recalculation; the RIB tag stays at 200 and NH2 remains.

    Steps:
      1. Install NH1 at AD 10 with tag 100, NH2 at AD 10 with tag 200.
      2. Verify RIB: both NHs as ECMP, tag 200 (max-wins).
      3. Remove NH1 (below the max; pn->tag != nh->tag, no recalc).
      4. Verify RIB tag stays at 200; NH2 alone remains in RIB.
      5. Verify running-config shows only NH2 with tag 200.
      6. Clean up NH2; verify RIB and running-config are empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: two nexthops at same AD with different tags
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 tag 200\n"
    )

    # Step 2: RIB shows both NHs as ECMP, both with tag 200 (max-wins)
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 200), (nh2, 200)}, ipv6)
    assert result is None, (
        f"Delete non-max [2]: expected ECMP {{(NH1,200),(NH2,200)}}; got {result}"
    )

    # Step 3: remove NH1 (below max; pn->tag=200 != nh->tag=100, no recalc)
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n"
    )

    # Step 4: RIB tag stays at 200; NH2 alone remains
    result = _expect_nexthop_tags(r1, prefix, {(nh2, 200)}, ipv6)
    assert result is None, (
        f"Delete non-max [4]: expected {{(NH2,200)}}; got {result}"
    )

    # Step 5: running-config shows only NH2 with tag 200
    result = _expect_running(
        r1, prefix,
        [f"ip{ip_ver} route {prefix} {nh2} tag 200 10"],
        ipv6,
    )
    assert result is None, (
        f"Delete non-max [5]: running-config mismatch; got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh2} 10\n"
    )
    result = _expect_nexthop_tags(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Delete non-max [cleanup]: RIB not empty; got {result}"
    )
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Delete non-max [cleanup]: stale running-config entry; got {result}"
    )


def test_delete_non_max_ipv4():
    "IPv4: removing a below-max nexthop leaves the RIB tag unchanged."
    run_delete_non_max(ipv6=False)


def test_delete_non_max_ipv6():
    "IPv6: removing a below-max nexthop leaves the RIB tag unchanged."
    run_delete_non_max(ipv6=True)


# ---------------------------------------------------------------------------
# Test 7: three nexthops, delete max-tag holder — recalc picks new max
# ---------------------------------------------------------------------------

def run_three_nexthops_delete_max(ipv6=False):
    """
    With three nexthops at the same AD, deleting the max-tag holder causes
    the recalculation to pick the new max from the survivors.

    NH1/tag=100, NH2/tag=200, NH3/tag=300.  pn->tag = max = 300.  After
    removing NH3, the recalc gives max(100, 200) = 200.  NH1 and NH2 both
    remain as a two-nexthop ECMP group with tag 200.

    Steps:
      1. Install NH1/tag=100, NH2/tag=200, NH3/tag=300, all at AD 10.
      2. Verify RIB: all three NHs as ECMP with tag 300 (max-wins).
      3. Remove NH3 (the max-tag holder).
      4. Verify RIB tag is recalculated to 200 (the new max); NH1 and NH2
         remain as a two-nexthop ECMP group.
      5. Clean up NH1 and NH2; verify RIB and running-config are empty.
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

    # Step 1: three nexthops at same AD with distinct tags
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 tag 200\n"
        f"ip{ip_ver} route {prefix} {nh3} 10 tag 300\n"
    )

    # Step 2: RIB shows all three NHs as ECMP with tag 300 (max-wins)
    result = _expect_nexthop_tags(
        r1, prefix, {(nh1, 300), (nh2, 300), (nh3, 300)}, ipv6
    )
    assert result is None, (
        f"3-NH delete max [2]: expected ECMP {{(NH1,300),(NH2,300),(NH3,300)}}; "
        f"got {result}"
    )

    # Step 3: remove NH3 (the max-tag holder)
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh3} 10\n"
    )

    # Step 4: pn->tag recalculated to max(100, 200) = 200.  NH1 and NH2
    # remain as a two-nexthop ECMP group, both with tag 200.
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 200), (nh2, 200)}, ipv6)
    assert result is None, (
        f"3-NH delete max [4]: expected {{(NH1,200),(NH2,200)}}; got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10\n"
        f"no ip{ip_ver} route {prefix} {nh2} 10\n"
    )
    result = _expect_nexthop_tags(r1, prefix, set(), ipv6)
    assert result is None, (
        f"3-NH delete max [cleanup]: RIB not empty; got {result}"
    )
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"3-NH delete max [cleanup]: stale running-config entry; got {result}"
    )


def test_three_nexthops_delete_max_ipv4():
    "IPv4: with 3 same-AD nexthops, deleting the max-tag holder recalculates to the new max."
    run_three_nexthops_delete_max(ipv6=False)


def test_three_nexthops_delete_max_ipv6():
    "IPv6: with 3 same-AD nexthops, deleting the max-tag holder recalculates to the new max."
    run_three_nexthops_delete_max(ipv6=True)


# ---------------------------------------------------------------------------
# Test 8: running-config format with tag + non-default distance + non-default metric
# ---------------------------------------------------------------------------

def run_running_config_tag_metric(ipv6=False):
    """
    Verify the full running-config format when tag, distance, and metric are
    all non-default: 'ip route PREFIX NEXTHOP tag TAG DISTANCE metric METRIC'.

    Steps:
      1. Install NH1 at AD=10, metric=50, tag=100.
      2. Verify running-config shows 'ip route ... NH1 tag 100 10 metric 50'.
      3. Install NH2 at AD=1 (default), metric=20, tag=200.
      4. Verify running-config shows 'ip route ... NH2 tag 200 metric 20'
         (distance 1 is default → omitted).
      5. Clean up both; verify RIB and running-config are empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: non-default AD + non-zero metric + tag
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 100 metric 50\n"
    )

    # Step 2: full format: tag before distance, metric after distance
    expected_line = f"ip{ip_ver} route {prefix} {nh1} tag 100 10 metric 50"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"Tag+metric format [2]: expected '{expected_line}'; got {result}"
    )

    # Step 3: default AD (omitted) + non-zero metric + tag
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh2} tag 200 metric 20\n"
    )

    # Step 4: distance 1 is default → omitted in running-config
    result = _expect_running(
        r1, prefix,
        [
            f"ip{ip_ver} route {prefix} {nh1} tag 100 10 metric 50",
            f"ip{ip_ver} route {prefix} {nh2} tag 200 metric 20",
        ],
        ipv6,
    )
    assert result is None, (
        f"Tag+metric format [4]: running-config mismatch; got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1}\n"
        f"no ip{ip_ver} route {prefix} {nh2}\n"
    )
    result = _expect_rib_tags(r1, prefix, {}, ipv6)
    assert result is None, (
        f"Tag+metric format [cleanup]: RIB not empty; got {result}"
    )
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Tag+metric format [cleanup]: stale running-config entry; got {result}"
    )


def test_running_config_tag_metric_ipv4():
    "IPv4: tag + non-default distance + non-default metric all appear correctly in running-config."
    run_running_config_tag_metric(ipv6=False)


def test_running_config_tag_metric_ipv6():
    "IPv6: tag + non-default distance + non-default metric all appear correctly in running-config."
    run_running_config_tag_metric(ipv6=True)


# ---------------------------------------------------------------------------
# Test 9: re-add max-tag holder after recalculation
# ---------------------------------------------------------------------------

def run_readd_max_tag_holder(ipv6=False):
    """
    Re-adding a previously deleted max-tag holder with a higher tag makes
    it the new max and pn->tag is updated.  After a second deletion of the
    re-added nexthop, the recalc gives the surviving nexthop's tag.

    Steps:
      1. Install NH1/tag=100, NH2/tag=200 at AD 10.
         pn->tag = max(100, 200) = 200.
      2. Remove NH2 (the max-tag holder) → recalc → pn->tag = 100.
      3. Re-add NH2 with tag=300.  300 is the new max, so pn->tag=300.
      4. Verify RIB: NH1 and NH2 as ECMP with tag 300.
      5. Remove NH2 again → recalc → NH1 is the only remaining nexthop;
         pn->tag=100.
      6. Clean up NH1; verify RIB and running-config are empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: NH1/tag=100 then NH2/tag=200 → max(100, 200) = 200
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 tag 200\n"
    )
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 200), (nh2, 200)}, ipv6)
    assert result is None, (
        f"Re-add max [1]: expected ECMP {{(NH1,200),(NH2,200)}}; got {result}"
    )

    # Step 2: remove NH2 → recalc restores NH1's tag=100
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh2} 10\n"
    )
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 100)}, ipv6)
    assert result is None, (
        f"Re-add max [2]: expected {{(NH1,100)}} after removing NH2; got {result}"
    )

    # Step 3: re-add NH2 with tag=300; 300 is the new max
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh2} 10 tag 300\n"
    )

    # Step 4: RIB shows NH1 + NH2 as ECMP with tag 300 (NH2 is the new max)
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 300), (nh2, 300)}, ipv6)
    assert result is None, (
        f"Re-add max [4]: expected ECMP {{(NH1,300),(NH2,300)}}; got {result}"
    )

    # Step 5: remove NH2 again → recalc → NH1's tag=100 is restored
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh2} 10\n"
    )
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 100)}, ipv6)
    assert result is None, (
        f"Re-add max [5]: expected {{(NH1,100)}} after second removal of NH2; got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n"
    )
    result = _expect_nexthop_tags(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Re-add max [cleanup]: RIB not empty; got {result}"
    )
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Re-add max [cleanup]: stale running-config entry; got {result}"
    )


def test_readd_max_tag_holder_ipv4():
    "IPv4: re-adding the max-tag holder with a higher tag makes it win; re-deleting restores survivor."
    run_readd_max_tag_holder(ipv6=False)


def test_readd_max_tag_holder_ipv6():
    "IPv6: re-adding the max-tag holder with a higher tag makes it win; re-deleting restores survivor."
    run_readd_max_tag_holder(ipv6=True)


# ---------------------------------------------------------------------------
# Test 10: tag recalculated when tag-owning nexthop changes distance
# ---------------------------------------------------------------------------


def run_tag_recalc_on_distance_move(ipv6=False):
    """
    When the max-tag-holder nexthop changes its administrative distance,
    the remaining ECMP nexthop on the old path must receive the correct
    recalculated tag in the route-UPDATE sent to zebra.

    Setup:
      NH2/tag=50 and NH1/tag=100 share AD=10; pn->tag = max(50, 100) = 100.

    Steps:
      1. Install NH2 at AD=10 with tag=50.
      2. Install NH1 at AD=10 with tag=100; max-wins gives pn->tag=100.
      3. Verify RIB: both NHs as ECMP at AD=10 with tag=100.
      4. Change NH1's distance to 20 (distance_modify fires, NH1 moves).
      5. Verify old path (AD=10, NH2 only) now has tag=50 (recalculated);
         new path (AD=20, NH1) has tag=100.
      6. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: NH2 with tag=50
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} 10 tag 50\n")

    # Step 2: NH1 with tag=100 → max(50, 100) = 100
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 100\n")

    # Step 3: both NHs ECMP at AD=10 with tag=100 (max-wins)
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 100), (nh2, 100)}, ipv6)
    assert result is None, (
        f"Tag recalc on dist move [3]: expected ECMP {{(NH1,100),(NH2,100)}}; got {result}"
    )

    # Step 4: change NH1's distance to 20; distance_modify fires and moves NH1
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 20 tag 100\n")

    # Step 5: old path (AD=10) retains NH2 whose tag must be recalculated to 50.
    # New path (AD=20) has NH1 with tag=100.
    result = _expect_nexthop_tags(r1, prefix, {(nh2, 50), (nh1, 100)}, ipv6)
    assert result is None, (
        f"Tag recalc on dist move [5]: expected {{(NH2,50),(NH1,100)}}; got {result}"
    )
    result = _expect_rib_tags(r1, prefix, {10: 50, 20: 100}, ipv6)
    assert result is None, (
        f"Tag recalc on dist move [5]: expected {{10:50, 20:100}}; got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh2} 10 tag 50\n"
        f"no ip{ip_ver} route {prefix} {nh1} 20 tag 100\n"
    )
    result = _expect_nexthop_tags(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Tag recalc on dist move [cleanup]: RIB not empty; got {result}"
    )


def test_tag_recalc_on_distance_move_ipv4():
    "IPv4: remaining ECMP peer gets correct recalculated tag when max-tag holder changes distance."
    run_tag_recalc_on_distance_move(ipv6=False)


def test_tag_recalc_on_distance_move_ipv6():
    "IPv6: remaining ECMP peer gets correct recalculated tag when max-tag holder changes distance."
    run_tag_recalc_on_distance_move(ipv6=True)


# ---------------------------------------------------------------------------
# Test 11: tag recalculated when max-tag-holder nexthop changes metric
# ---------------------------------------------------------------------------


def run_tag_recalc_on_metric_move(ipv6=False):
    """
    When the max-tag-holder nexthop changes its metric, the remaining ECMP
    nexthop on the old path must receive the correct recalculated tag in
    the route-UPDATE sent to zebra.

    Setup:
      NH2/tag=50 and NH1/tag=100 share (AD=10, metric=100);
      pn->tag = max(50, 100) = 100.

    Steps:
      1. Install NH2 at AD=10, metric=100, tag=50.
      2. Install NH1 at AD=10, metric=100, tag=100; max-wins gives pn->tag=100.
      3. Verify RIB: both NHs ECMP at (AD=10, metric=100) with tag=100.
      4. Change NH1's metric to 200 (metric_modify fires, NH1 moves).
      5. Verify old path (metric=100, NH2 only) now has tag=50 (recalculated);
         new path (metric=200, NH1) has tag=100.
      6. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: NH2 at (AD=10, metric=100, tag=50)
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh2} 10 metric 100 tag 50\n"
    )

    # Step 2: NH1 at (AD=10, metric=100, tag=100) → max(50, 100) = 100
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100 tag 100\n"
    )

    # Step 3: both NHs ECMP at (AD=10, metric=100) with tag=100 (max-wins)
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 100), (nh2, 100)}, ipv6)
    assert result is None, (
        f"Tag recalc on metric move [3]: expected ECMP {{(NH1,100),(NH2,100)}}; "
        f"got {result}"
    )

    # Step 4: change NH1's metric to 200; metric_modify fires and moves NH1
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 200 tag 100\n"
    )

    # Step 5: old path (metric=100) retains NH2; tag must be recalculated to 50.
    # New path (metric=200) has NH1 with tag=100.
    result = _expect_nexthop_tags(r1, prefix, {(nh2, 50), (nh1, 100)}, ipv6)
    assert result is None, (
        f"Tag recalc on metric move [5]: expected {{(NH2,50),(NH1,100)}}; got {result}"
    )
    result = _expect_rib_tags_by_dist_metric(r1, prefix, {(10, 100): 50, (10, 200): 100}, ipv6)
    assert result is None, (
        f"Tag recalc on metric move [5]: expected {{(10,100):50,(10,200):100}}; "
        f"got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh2} 10 metric 100 tag 50\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10 metric 200 tag 100\n"
    )
    result = _expect_nexthop_tags(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Tag recalc on metric move [cleanup]: RIB not empty; got {result}"
    )


def test_tag_recalc_on_metric_move_ipv4():
    "IPv4: remaining ECMP peer gets correct recalculated tag when max-tag holder changes metric."
    run_tag_recalc_on_metric_move(ipv6=False)


def test_tag_recalc_on_metric_move_ipv6():
    "IPv6: remaining ECMP peer gets correct recalculated tag when max-tag holder changes metric."
    run_tag_recalc_on_metric_move(ipv6=True)


# ---------------------------------------------------------------------------
# Test 12: tag preserved when non-max nexthop changes distance
# ---------------------------------------------------------------------------


def run_tag_preserved_when_non_max_moves(ipv6=False):
    """
    When a non-max nexthop changes its distance, the remaining max-tag
    holder on the old path must retain its tag unchanged.  The
    if (old_pn->tag == nh->tag) branch is false, so no recalculation fires.

    Setup:
      NH2/tag=50 and NH1/tag=100 share AD=10; pn->tag = max(50, 100) = 100
      and NH1 carries the max.

    Steps:
      1. Install NH2 at AD=10 with tag=50.
      2. Install NH1 at AD=10 with tag=100; max-wins gives pn->tag=100.
      3. Verify RIB: both NHs ECMP at AD=10 with tag=100.
      4. Change NH2's distance to 20 (non-max moves; no recalc on old path).
      5. Verify old path (AD=10, NH1 only) retains tag=100 (unchanged);
         new path (AD=20, NH2) has tag=50.
      6. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: NH2 with tag=50
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} 10 tag 50\n")

    # Step 2: NH1 with tag=100 → max(50, 100) = 100
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 100\n")

    # Step 3: both NHs ECMP at AD=10 with tag=100 (max-wins)
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 100), (nh2, 100)}, ipv6)
    assert result is None, (
        f"Tag preserved nonmax move [3]: expected ECMP {{(NH1,100),(NH2,100)}}; "
        f"got {result}"
    )

    # Step 4: change NH2's distance to 20; NH2 is non-max so no recalc on old path
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} 20 tag 50\n")

    # Step 5: old path (AD=10) retains NH1 with tag=100 (no recalc fired);
    # new path (AD=20) has NH2 with tag=50.
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 100), (nh2, 50)}, ipv6)
    assert result is None, (
        f"Tag preserved nonmax move [5]: expected {{(NH1,100),(NH2,50)}}; got {result}"
    )
    result = _expect_rib_tags(r1, prefix, {10: 100, 20: 50}, ipv6)
    assert result is None, (
        f"Tag preserved nonmax move [5]: expected {{10:100, 20:50}}; got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"no ip{ip_ver} route {prefix} {nh2} 20 tag 50\n"
    )
    result = _expect_nexthop_tags(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Tag preserved nonmax move [cleanup]: RIB not empty; got {result}"
    )


def test_tag_preserved_when_non_max_moves_ipv4():
    "IPv4: max-tag holder's tag on old path unchanged when a non-max nexthop changes distance."
    run_tag_preserved_when_non_max_moves(ipv6=False)


def test_tag_preserved_when_non_max_moves_ipv6():
    "IPv6: max-tag holder's tag on old path unchanged when a non-max nexthop changes distance."
    run_tag_preserved_when_non_max_moves(ipv6=True)


# ---------------------------------------------------------------------------
# Test 13: tag recalculated when nexthop moves onto an existing tagged path
# ---------------------------------------------------------------------------


def run_tag_recalc_on_move_to_existing_path(ipv6=False):
    """
    When a nexthop moves onto a path that already has a tagged nexthop,
    static_path_recalc_tag(new_pn) must apply max-wins across the
    pre-existing and arriving nexthops.

    Setup:
      NH1 at AD=10, tag=50; NH2 at AD=20, tag=100.

    Steps:
      1. Install NH1 at AD=10 with tag=50.
      2. Install NH2 at AD=20 with tag=100.
      3. Verify: AD=10 has tag=50 (NH1 sole); AD=20 has tag=100 (NH2 sole).
      4. Change NH2's distance to 10: NH2 joins NH1's existing path.
         static_path_recalc_tag(new_pn) sets pn->tag = max(50, 100) = 100.
      5. Verify: AD=10 path (NH1+NH2) has tag=100 (max-wins);
         AD=20 is gone (NH2 was its sole nexthop → deleted).
      6. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: NH1 at AD=10, tag=50
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 50\n")

    # Step 2: NH2 at AD=20, tag=100
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} 20 tag 100\n")

    # Step 3: each path carries its own tag
    result = _expect_rib_tags(r1, prefix, {10: 50, 20: 100}, ipv6)
    assert result is None, (
        f"Tag recalc move to existing [3]: expected {{10:50, 20:100}}; got {result}"
    )

    # Step 4: NH2 changes distance from 20 to 10; NH2 joins NH1's existing
    # path; static_path_recalc_tag(new_pn) sets pn->tag = max(50, 100) = 100.
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} 10 tag 100\n")

    # Step 5: AD=10 path (NH1+NH2) now has tag=100 (max-wins); AD=20 gone.
    result = _expect_rib_tags(r1, prefix, {10: 100}, ipv6)
    assert result is None, (
        f"Tag recalc move to existing [5]: expected {{10:100}}; got {result}"
    )
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 100), (nh2, 100)}, ipv6)
    assert result is None, (
        f"Tag recalc move to existing [5]: expected {{(NH1,100),(NH2,100)}}; "
        f"got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10 tag 50\n"
        f"no ip{ip_ver} route {prefix} {nh2} 10 tag 100\n"
    )
    result = _expect_nexthop_tags(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Tag recalc move to existing [cleanup]: RIB not empty; got {result}"
    )


def test_tag_recalc_on_move_to_existing_path_ipv4():
    "IPv4: max-wins tag recalc when nexthop joins an existing tagged path."
    run_tag_recalc_on_move_to_existing_path(ipv6=False)


def test_tag_recalc_on_move_to_existing_path_ipv6():
    "IPv6: max-wins tag recalc when nexthop joins an existing tagged path."
    run_tag_recalc_on_move_to_existing_path(ipv6=True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
