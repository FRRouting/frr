#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test per-path tag for static routes.

Design: tag lives in static_path alongside distance.  The path-list key is
(table-id, distance); tag is a modifiable leaf.  Each path groups ECMP
nexthops that share the same table and distance; the tag is shared by all
nexthops in a path.

Note: zebra keys routes by (prefix, protocol, table, distance) and ignores
tag, so tag is advisory metadata only.  Nexthops at the same AD always share
one zebra slot regardless of tag.

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

  5. Same AD, different tag: NH1@AD10+tag=100 and NH2@AD10+tag=200.  Since
     both nexthops share the same path-list (keyed by distance only), the
     path tag is the last-configured value (200).  Both nexthops form ECMP
     under one path.  Removing NH1 leaves NH2 in the RIB intact.
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
    Two nexthops at the same AD go into one path-list (keyed by distance only).
    The path tag is the last-configured value; both nexthops form an ECMP group.
    Removing one nexthop does not affect the other.

    Steps:
      1. Install NH1 at AD 10 with tag 100, then NH2 at AD 10 with tag 200.
         Both land in path-list[distance=10].  Tag becomes 200 (last command).
      2. Verify running-config shows both NHs with tag 200.
      3. Verify RIB has both NHs as ECMP, each with tag 200.
      4. Remove NH1; verify NH2 survives in config and RIB with tag 200.
      5. Clean up NH2; verify RIB and running-config are empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    nh2 = NH2_V6 if ipv6 else NH2_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: two nexthops at same AD, different tags; last tag (200) wins
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 tag 200\n"
    )

    # Step 2: running-config shows both NHs under one path with tag 200
    result = _expect_running(
        r1, prefix,
        [
            f"ip{ip_ver} route {prefix} {nh1} tag 200 10",
            f"ip{ip_ver} route {prefix} {nh2} tag 200 10",
        ],
        ipv6,
    )
    assert result is None, (
        f"Same-AD diff-tag [2]: running-config mismatch; got {result}"
    )

    # Step 3: RIB shows both NHs as ECMP with tag 200
    result = _expect_nexthop_tags(r1, prefix, {(nh1, 200), (nh2, 200)}, ipv6)
    assert result is None, (
        f"Same-AD diff-tag [3]: expected ECMP {{(NH1,200),(NH2,200)}}; got {result}"
    )

    # Step 4: remove NH1; NH2 config and RIB entry survive with tag 200
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n"
    )
    result = _expect_running(
        r1, prefix,
        [f"ip{ip_ver} route {prefix} {nh2} tag 200 10"],
        ipv6,
    )
    assert result is None, (
        f"Same-AD diff-tag [4]: NH2 config gone after removing NH1; got {result}"
    )
    result = _expect_nexthop_tags(r1, prefix, {(nh2, 200)}, ipv6)
    assert result is None, (
        f"Same-AD diff-tag [4]: NH2 not in RIB after removing NH1; got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh2} 10\n"
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
    "IPv4: two nexthops at same AD share one path-list; removing one leaves the other intact."
    run_same_ad_different_tag(ipv6=False)


def test_same_ad_different_tag_ipv6():
    "IPv6: two nexthops at same AD share one path-list; removing one leaves the other intact."
    run_same_ad_different_tag(ipv6=True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
