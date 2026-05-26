#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test that apply_finish correctly batches NB per-leaf callbacks.

The YANG path-list is keyed by nexthop identity (nh-type, vrf, gateway,
interface); distance, metric, and tag are non-key leaf attributes.  The NB
framework fires individual per-leaf callbacks (tag_modify, distance_modify,
metric_modify) followed by apply_finish on the same path-list node once all
leaf callbacks complete.

apply_finish is the single installation point.  Per-leaf callbacks update
in-memory state and set nh->state = STATIC_START when a reinstall is needed;
apply_finish then calls static_install_nexthop() once per nexthop.

Test cases:

  1. Tag + metric combined: changing tag and metric in one command fires
     tag_modify and metric_modify followed by a single apply_finish.  The
     route must end up at the new (metric, tag) with the old metric entry
     gone from the RIB.

  2. Distance + metric combined: changing distance and metric together fires
     distance_modify and metric_modify followed by one apply_finish.  The
     route must move to the new (distance, metric) with no stale entry.

  3. Tag + distance + metric combined: all three attributes change in one
     command.  apply_finish fires once.  The route must reflect all three
     new values with no stale entry.

  4. Tag no-op + apply_finish: when tag_modify fires but the effective path
     tag (pn->tag) does not change after static_path_recalc_tag(), the
     no-op guard breaks early without setting nh->state = STATIC_START.
     apply_finish still fires.  The route must remain correctly installed.
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
NH1_V6 = "2001:db8:0:1::2"
NH2_V6 = "2001:db8:0:2::2"

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
    """Return list of route-entry dicts from 'show ip route json'."""
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd(f"show ip{ip_ver} route {prefix} json")
    json_data = json.loads(output)
    return json_data.get(prefix, [])


def _route_attr_set(router, prefix, ipv6=False):
    """Return set of (distance, metric, tag) tuples for all RIB entries."""
    return {
        (e.get("distance", 0), e.get("metric", 0), e.get("tag", 0))
        for e in _route_entries(router, prefix, ipv6)
    }


def _route_tag(router, prefix, ipv6=False):
    """Return the tag of the first RIB entry for prefix, or None if absent."""
    entries = _route_entries(router, prefix, ipv6)
    return entries[0].get("tag", 0) if entries else None


def _active_nexthop_ips(router, prefix, ipv6=False):
    """Return set of nexthop IPs from all RIB entries for prefix."""
    result = set()
    for entry in _route_entries(router, prefix, ipv6):
        for nh in entry.get("nexthops", []):
            ip = nh.get("ip", "")
            if ip:
                result.add(ip)
    return result


def _running_config_routes(router, prefix, ipv6=False):
    """Return static-route lines for prefix from 'show running-config'."""
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd("show running-config")
    keyword = f"ip{ip_ver} route {prefix}"
    return [line.strip() for line in output.splitlines() if keyword in line]


def _check_attrs(router, prefix, expected, ipv6=False):
    actual = _route_attr_set(router, prefix, ipv6)
    return None if actual == expected else actual


def _check_tag(router, prefix, expected, ipv6=False):
    actual = _route_tag(router, prefix, ipv6)
    return None if actual == expected else actual


def _check_nhs(router, prefix, expected, ipv6=False):
    actual = _active_nexthop_ips(router, prefix, ipv6)
    return None if actual == expected else actual


def _check_running(router, prefix, expected_lines, ipv6=False):
    actual = set(_running_config_routes(router, prefix, ipv6))
    return None if actual == set(expected_lines) else actual


def _expect_attrs(router, prefix, expected, ipv6=False):
    fn = functools.partial(_check_attrs, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(fn, None, count=15, wait=1)
    return result


def _expect_tag(router, prefix, expected, ipv6=False):
    fn = functools.partial(_check_tag, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(fn, None, count=15, wait=1)
    return result


def _expect_nhs(router, prefix, expected, ipv6=False):
    fn = functools.partial(_check_nhs, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(fn, None, count=15, wait=1)
    return result


def _expect_running(router, prefix, expected_lines, ipv6=False):
    fn = functools.partial(_check_running, router, prefix, expected_lines, ipv6)
    _, result = topotest.run_and_expect(fn, None, count=15, wait=1)
    return result


# ---------------------------------------------------------------------------
# Test 1: tag + metric combined change
# ---------------------------------------------------------------------------


def run_tag_metric_combined(ipv6=False):
    """
    Changing tag and metric in one command fires tag_modify and metric_modify
    followed by a single apply_finish.

    Steps:
      1. Install NH1 at distance 10, metric 100, tag 100.
      2. Verify RIB has (dist=10, metric=100, tag=100).
      3. Reconfigure NH1 with metric 200 and tag 200 (one command).
      4. Verify RIB has (dist=10, metric=200, tag=200); old metric=100 is gone.
      5. Verify running-config shows the updated entry.
      6. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100 tag 100\n"
    )

    # Step 2
    result = _expect_attrs(r1, prefix, {(10, 100, 100)}, ipv6)
    assert result is None, (
        f"tag+metric combined [2]: expected {{(10,100,100)}}, got {result}"
    )

    # Step 3: change both tag and metric in one command
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 200 tag 200\n"
    )

    # Step 4: new attrs present, old metric=100 entry gone
    result = _expect_attrs(r1, prefix, {(10, 200, 200)}, ipv6)
    assert result is None, (
        f"tag+metric combined [4]: expected {{(10,200,200)}}, got {result}"
    )

    # Step 5: running-config
    expected_line = f"ip{ip_ver} route {prefix} {nh1} tag 200 10 metric 200"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"tag+metric combined [5]: running-config mismatch; got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 10 metric 200 tag 200\n"
    )
    result = _expect_attrs(r1, prefix, set(), ipv6)
    assert result is None, (
        f"tag+metric combined [cleanup]: RIB not empty; got {result}"
    )


def test_tag_metric_combined_ipv4():
    "IPv4: tag and metric change together; tag_modify+metric_modify then one apply_finish."
    run_tag_metric_combined(ipv6=False)


def test_tag_metric_combined_ipv6():
    "IPv6: tag and metric change together; tag_modify+metric_modify then one apply_finish."
    run_tag_metric_combined(ipv6=True)


# ---------------------------------------------------------------------------
# Test 2: distance + metric combined change
# ---------------------------------------------------------------------------


def run_distance_metric_combined(ipv6=False):
    """
    Changing distance and metric in one command fires distance_modify and
    metric_modify followed by a single apply_finish.

    Steps:
      1. Install NH1 at distance 10, metric 100.
      2. Verify RIB has (dist=10, metric=100, tag=0).
      3. Reconfigure NH1 at distance 20, metric 200 (one command).
      4. Verify RIB has only (dist=20, metric=200, tag=0); old entry is gone.
      5. Verify running-config shows the updated entry.
      6. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100\n")

    # Step 2
    result = _expect_attrs(r1, prefix, {(10, 100, 0)}, ipv6)
    assert result is None, (
        f"dist+metric combined [2]: expected {{(10,100,0)}}, got {result}"
    )

    # Step 3: change distance and metric together
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 20 metric 200\n")

    # Step 4: new attrs present, old (dist=10, metric=100) entry gone
    result = _expect_attrs(r1, prefix, {(20, 200, 0)}, ipv6)
    assert result is None, (
        f"dist+metric combined [4]: expected {{(20,200,0)}}, got {result}"
    )

    # Step 5: running-config
    expected_line = f"ip{ip_ver} route {prefix} {nh1} 20 metric 200"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"dist+metric combined [5]: running-config mismatch; got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 20 metric 200\n")
    result = _expect_attrs(r1, prefix, set(), ipv6)
    assert result is None, (
        f"dist+metric combined [cleanup]: RIB not empty; got {result}"
    )


def test_distance_metric_combined_ipv4():
    "IPv4: distance and metric change together; distance_modify+metric_modify then one apply_finish."
    run_distance_metric_combined(ipv6=False)


def test_distance_metric_combined_ipv6():
    "IPv6: distance and metric change together; distance_modify+metric_modify then one apply_finish."
    run_distance_metric_combined(ipv6=True)


# ---------------------------------------------------------------------------
# Test 3: tag + distance + metric combined change
# ---------------------------------------------------------------------------


def run_tag_distance_metric_combined(ipv6=False):
    """
    Changing tag, distance, and metric in one command fires all three per-leaf
    callbacks followed by a single apply_finish.

    Steps:
      1. Install NH1 at distance 10, metric 100, tag 100.
      2. Verify RIB has (dist=10, metric=100, tag=100).
      3. Reconfigure NH1 at distance 20, metric 200, tag 200 (one command).
      4. Verify RIB has only (dist=20, metric=200, tag=200); old entry is gone.
      5. Verify running-config shows the updated entry.
      6. Clean up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100 tag 100\n"
    )

    # Step 2
    result = _expect_attrs(r1, prefix, {(10, 100, 100)}, ipv6)
    assert result is None, (
        f"tag+dist+metric [2]: expected {{(10,100,100)}}, got {result}"
    )

    # Step 3: change all three in one command
    r1.vtysh_multicmd(
        f"configure\nip{ip_ver} route {prefix} {nh1} 20 metric 200 tag 200\n"
    )

    # Step 4: new attrs present, old (dist=10, metric=100, tag=100) entry gone
    result = _expect_attrs(r1, prefix, {(20, 200, 200)}, ipv6)
    assert result is None, (
        f"tag+dist+metric [4]: expected {{(20,200,200)}}, got {result}"
    )

    # Step 5: running-config
    expected_line = f"ip{ip_ver} route {prefix} {nh1} tag 200 20 metric 200"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"tag+dist+metric [5]: running-config mismatch; got {result}"
    )

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\nno ip{ip_ver} route {prefix} {nh1} 20 metric 200 tag 200\n"
    )
    result = _expect_attrs(r1, prefix, set(), ipv6)
    assert result is None, (
        f"tag+dist+metric [cleanup]: RIB not empty; got {result}"
    )


def test_tag_distance_metric_combined_ipv4():
    "IPv4: tag, distance, and metric all change in one command; apply_finish fires once."
    run_tag_distance_metric_combined(ipv6=False)


def test_tag_distance_metric_combined_ipv6():
    "IPv6: tag, distance, and metric all change in one command; apply_finish fires once."
    run_tag_distance_metric_combined(ipv6=True)


# ---------------------------------------------------------------------------
# Test 4: tag no-op + apply_finish
# ---------------------------------------------------------------------------


def run_tag_noop_apply_finish(ipv6=False):
    """
    When tag_modify fires but pn->tag is unchanged after static_path_recalc_tag(),
    the no-op guard breaks early without setting nh->state = STATIC_START.
    apply_finish still fires and must leave the route correctly installed.

    Setup: NH1 and NH2 share the same (distance, metric) ECMP path.
    pn->tag is the maximum nh->tag across the group (max-wins).

    Steps:
      1. Install NH1 with tag 50 at distance 10.
      2. Install NH2 with tag 100 at distance 10.
         pn->tag = max(50, 100) = 100.
      3. Verify both NH1 and NH2 are active ECMP nexthops with tag 100.
      4. Reconfigure NH1 with tag 100 (matches the current pn->tag).
         tag_modify fires for NH1: nh->tag updates 50 → 100; recalc gives
         max(100, 100) = 100 (unchanged) → no-op guard breaks without
         setting nh->state = STATIC_START.  apply_finish fires for NH1's
         path-list entry.
      5. Verify both NH1 and NH2 are still active with tag 100.
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

    # Step 1: NH1 at distance 10 with tag 50
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 50\n")

    # Step 2: NH2 at distance 10 with tag 100; max-wins → pn->tag = 100
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} 10 tag 100\n")

    # Step 3: both NH1 and NH2 active; path tag = 100
    result = _expect_nhs(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, (
        f"tag no-op [3]: expected both nexthops active, got {result}"
    )
    result = _expect_tag(r1, prefix, 100, ipv6)
    assert result is None, f"tag no-op [3]: expected tag 100, got {result}"

    # Step 4: raise NH1's tag to 100 (matches current max → no-op in tag_modify)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 tag 100\n")

    # Step 5: both NH1 and NH2 still active with tag 100
    result = _expect_nhs(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, (
        f"tag no-op [5]: expected both nexthops active after no-op, got {result}"
    )
    result = _expect_tag(r1, prefix, 100, ipv6)
    assert result is None, f"tag no-op [5]: expected tag 100 after no-op, got {result}"

    # Step 6: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10 tag 100\n"
        f"no ip{ip_ver} route {prefix} {nh2} 10 tag 100\n"
    )
    result = _expect_attrs(r1, prefix, set(), ipv6)
    assert result is None, f"tag no-op [cleanup]: RIB not empty; got {result}"


def test_tag_noop_apply_finish_ipv4():
    "IPv4: tag no-op (pn->tag unchanged) leaves apply_finish handling the nexthop correctly."
    run_tag_noop_apply_finish(ipv6=False)


def test_tag_noop_apply_finish_ipv6():
    "IPv6: tag no-op (pn->tag unchanged) leaves apply_finish handling the nexthop correctly."
    run_tag_noop_apply_finish(ipv6=True)
