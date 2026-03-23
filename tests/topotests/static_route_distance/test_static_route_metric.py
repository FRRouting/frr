#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test per-path metric for static routes.

Design: metric is a YANG path-list key alongside table-id and distance.
Nexthops sharing the same (table-id, distance, metric) tuple form one ECMP
group.  Zebra keeps separate route_entry objects for routes with the same
(type, instance, distance) but different metrics because rib_compare_routes()
treats static routes with different metrics as non-equal, and the
process_subq_early_route_delete() loop skips entries whose metric does not
match the delete request.  Zebra selects the lower-metric entry as best —
enabling metric-based floating routes within the same administrative distance.

Topology: r1 with three Ethernet interfaces, each connected to a switch
(s1/s2/s3), providing three independent nexthop addresses (NH1, NH2, NH3).
All tests run for both IPv4 and IPv6.

Test cases:

  1. Metric replacement: reconfiguring the same nexthop with a new metric
     must update the existing RIB entry (including the active metric value
     reported by zebra) and remove the stale old-metric entry — not
     duplicate it.

  2. ECMP at same (distance, metric): two nexthops with matching distance
     and metric are both active in the FIB.  Removing one leaves the other
     active at the same (distance, metric).

  3. Metric-based floating within same distance: NH1@(AD=10, metric=100)
     and NH2@(AD=10, metric=200) are kept as separate RIB entries; the lower
     metric wins in zebra.  Removing NH1 promotes NH2.

  4. Metric change (promote/demote): a nexthop moves in and out of the
     ECMP group by having its metric changed — covering both promotion
     (standby joins ECMP group) and demotion (ECMP member becomes standby),
     and re-promotion back into the group.

  5. Metric-aware deletion: 'no ip route X/M via Y DIST metric M' finds
     the exact entry; 'no ip route X/M via Y DIST' without metric defaults
     to metric=0 and will NOT match a route installed at a non-zero metric;
     'no ip route X/M via Y' without any key does a lazy search that finds
     the route regardless of distance and metric.  A two-metric scenario
     verifies that zebra's delete-lookup loop removes only the matching
     metric entry, leaving the other intact.

  6. Running-config format: metric appears after distance in the
     'show running-config' output; distance=default is omitted; metric=0
     is omitted.
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
    """Return list of route-entry dicts from 'show ip route json'."""
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd(f"show ip{ip_ver} route {prefix} json")
    json_data = json.loads(output)
    return json_data.get(prefix, [])


def _route_keys(router, prefix, ipv6=False):
    """Return set of (distance, metric) tuples present in the RIB for prefix."""
    return {
        (e.get("distance", 0), e.get("metric", 0))
        for e in _route_entries(router, prefix, ipv6)
    }


def _active_nexthops(router, prefix, ipv6=False):
    """Return set of nexthop IPs from the selected (best-path) route entry."""
    active = set()
    for entry in _route_entries(router, prefix, ipv6):
        if not entry.get("selected"):
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("active"):
                active.add(nh.get("ip", nh.get("interfaceName", "")))
    return active


def _active_metric(router, prefix, ipv6=False):
    """Return the metric of the selected (best-path) RIB entry, or None if absent."""
    for entry in _route_entries(router, prefix, ipv6):
        if entry.get("selected"):
            return entry.get("metric", 0)
    return None


def _running_config_routes(router, prefix, ipv6=False):
    """Return static-route lines for prefix from 'show running-config'."""
    ip_ver = "v6" if ipv6 else ""
    output = router.vtysh_cmd("show running-config")
    keyword = f"ip{ip_ver} route {prefix}"
    return [l.strip() for l in output.splitlines() if keyword in l]


def _check_keys(router, prefix, expected, ipv6=False):
    actual = _route_keys(router, prefix, ipv6)
    return None if actual == expected else actual


def _check_nexthops(router, prefix, expected, ipv6=False):
    actual = _active_nexthops(router, prefix, ipv6)
    return None if actual == expected else actual


def _check_metric(router, prefix, expected, ipv6=False):
    actual = _active_metric(router, prefix, ipv6)
    return None if actual == expected else actual


def _check_running(router, prefix, expected_lines, ipv6=False):
    actual = set(_running_config_routes(router, prefix, ipv6))
    return None if actual == set(expected_lines) else actual


def _expect_keys(router, prefix, expected, ipv6=False):
    test_func = functools.partial(_check_keys, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


def _expect_nexthops(router, prefix, expected, ipv6=False):
    test_func = functools.partial(_check_nexthops, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


def _expect_metric(router, prefix, expected, ipv6=False):
    test_func = functools.partial(_check_metric, router, prefix, expected, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


def _expect_running(router, prefix, expected_lines, ipv6=False):
    test_func = functools.partial(_check_running, router, prefix, expected_lines, ipv6)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    return result


# ---------------------------------------------------------------------------
# Test 1: Metric replacement
# ---------------------------------------------------------------------------


def run_metric_replacement(ipv6=False):
    """
    Same nexthop reconfigured with a new metric must replace the old RIB
    entry and leave running-config with exactly one entry at the new metric.

    Steps:
      1. Install NH1 at (AD=10, metric=100).
      2. Reconfigure NH1 at (AD=10, metric=200) — must replace, not duplicate.
      3. Verify only (10, 200) is in RIB; (10, 100) entry is gone.
      4. Verify running-config shows '... NH1 10 metric 200', not 'metric 100'.
      5. Clean up; verify RIB and running-config are empty.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Step 1: install at (AD=10, metric=100)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_keys(r1, prefix, {(10, 100)}, ipv6)
    assert result is None, f"Metric replacement [1]: expected {{(10,100)}}, got {result}"

    # Step 2: same nexthop, new metric — must replace, not duplicate
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 200\n")
    result = _expect_keys(r1, prefix, {(10, 200)}, ipv6)
    assert result is None, (
        f"Metric replacement [2]: stale metric 100 present or metric 200 missing; got {result}"
    )

    # Verify zebra reports the updated metric value
    result = _expect_metric(r1, prefix, 200, ipv6)
    assert result is None, (
        f"Metric replacement [2]: active metric should be 200 in RIB; got {result}"
    )

    # Step 3: running-config shows exactly one entry at metric 200
    expected_line = f"ip{ip_ver} route {prefix} {nh1} 10 metric 200"
    result = _expect_running(r1, prefix, [expected_line], ipv6)
    assert result is None, (
        f"Metric replacement [3]: running-config mismatch; got {result}"
    )

    # Step 4: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10 metric 200\n")
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, f"Metric replacement [cleanup]: route not removed; got {result}"
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Metric replacement [cleanup]: stale running-config entry; got {result}"
    )


def test_metric_replacement_ipv4():
    "IPv4: same nexthop reconfigured with new metric replaces old RIB entry."
    run_metric_replacement(ipv6=False)


def test_metric_replacement_ipv6():
    "IPv6: same nexthop reconfigured with new metric replaces old RIB entry."
    run_metric_replacement(ipv6=True)


# ---------------------------------------------------------------------------
# Test 2: ECMP at same (distance, metric)
# ---------------------------------------------------------------------------


def run_ecmp_same_metric(ipv6=False):
    """
    Two nexthops at the same (distance, metric) are both active in the FIB.
    Removing one ECMP member leaves the other active at the same key.

    Steps:
      1. Install NH1 and NH2 both at (AD=10, metric=100).
      2. Verify both are active (ECMP); only one (10, 100) entry in RIB.
      3. Remove NH1; verify NH2 remains active at (10, 100).
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

    # Step 1: two nexthops at same (AD, metric)
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 metric 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 metric 100\n"
    )
    result = _expect_keys(r1, prefix, {(10, 100)}, ipv6)
    assert result is None, f"ECMP same metric [1]: expected {{(10,100)}}, got {result}"

    # Step 2: both nexthops active (ECMP)
    result = _expect_nexthops(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, (
        f"ECMP same metric [2]: expected both {nh1},{nh2} active, got {result}"
    )

    # Step 3: remove one ECMP member
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_nexthops(r1, prefix, {nh2}, ipv6)
    assert result is None, (
        f"ECMP same metric [3]: expected only {nh2} active after {nh1} removed, got {result}"
    )
    result = _expect_keys(r1, prefix, {(10, 100)}, ipv6)
    assert result is None, (
        f"ECMP same metric [3]: RIB key should still be {{(10,100)}}, got {result}"
    )

    # Step 4: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh2} 10 metric 100\n")
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, f"ECMP same metric [cleanup]: route not removed; got {result}"


def test_ecmp_same_metric_ipv4():
    "IPv4 ECMP: two nexthops at same (distance, metric) both active; removing one leaves the other."
    run_ecmp_same_metric(ipv6=False)


def test_ecmp_same_metric_ipv6():
    "IPv6 ECMP: two nexthops at same (distance, metric) both active; removing one leaves the other."
    run_ecmp_same_metric(ipv6=True)


# ---------------------------------------------------------------------------
# Test 3: Metric-based floating within same distance
# ---------------------------------------------------------------------------


def run_metric_floating(ipv6=False):
    """
    Two nexthops at the same distance but different metrics are kept as
    separate RIB entries (ZEBRA_FLAG_RR_USE_METRIC).  Zebra selects the
    lower-metric path as best; the higher-metric path is standby.
    Removing the primary promotes the standby.

    Steps:
      1. Install NH1 at (AD=10, metric=100) and NH2 at (AD=10, metric=200).
      2. Verify RIB has both keys; NH1 is active (lower metric wins).
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

    # Step 1: primary (lower metric) + standby (higher metric), same distance
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 metric 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 metric 200\n"
    )
    result = _expect_keys(r1, prefix, {(10, 100), (10, 200)}, ipv6)
    assert result is None, (
        f"Metric floating [1]: expected {{(10,100),(10,200)}}, got {result}"
    )

    # Step 2: lower-metric nexthop is active
    result = _expect_nexthops(r1, prefix, {nh1}, ipv6)
    assert result is None, (
        f"Metric floating [2]: expected {nh1} active (lower metric), got {result}"
    )
    result = _expect_metric(r1, prefix, 100, ipv6)
    assert result is None, (
        f"Metric floating [2]: expected active metric=100, got {result}"
    )

    # Step 3: remove primary → standby promoted
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_nexthops(r1, prefix, {nh2}, ipv6)
    assert result is None, (
        f"Metric floating [3]: expected {nh2} promoted after {nh1} removed, got {result}"
    )
    result = _expect_metric(r1, prefix, 200, ipv6)
    assert result is None, (
        f"Metric floating [3]: expected active metric=200 after promotion, got {result}"
    )

    # Step 4: clean up
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh2} 10 metric 200\n")
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, f"Metric floating [cleanup]: route not removed; got {result}"


def test_metric_floating_ipv4():
    "IPv4: NH at lower metric active; higher-metric NH is standby and promoted on primary removal."
    run_metric_floating(ipv6=False)


def test_metric_floating_ipv6():
    "IPv6: NH at lower metric active; higher-metric NH is standby and promoted on primary removal."
    run_metric_floating(ipv6=True)


# ---------------------------------------------------------------------------
# Test 4: Metric change (promote/demote)
# ---------------------------------------------------------------------------


def run_metric_change(ipv6=False):
    """
    A nexthop moves in and out of the ECMP group by having its metric changed.

    Steps:
      1. NH1 at (AD=10, metric=100) sole primary; NH2 at (AD=10, metric=200) standby.
         Verify NH1 active, NH2 not.
      2. Change NH2 metric=200 → 100: NH2 joins the ECMP group.
         Verify both NH1 and NH2 active; only (10,100) in RIB (old (10,200) gone).
      3. Change NH1 metric=100 → 200: NH1 demoted to standby.
         Verify NH2 sole primary at (10,100); NH1 standby at (10,200).
      4. Change NH1 metric=200 → 100: NH1 rejoins ECMP group.
         Verify both NH1 and NH2 active at (10,100).
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

    # Step 1: NH1 primary at metric=100, NH2 standby at metric=200
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 metric 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 metric 200\n"
    )
    result = _expect_nexthops(r1, prefix, {nh1}, ipv6)
    assert result is None, (
        f"Metric change [1]: expected only {nh1} active, got {result}"
    )
    result = _expect_keys(r1, prefix, {(10, 100), (10, 200)}, ipv6)
    assert result is None, (
        f"Metric change [1]: expected {{(10,100),(10,200)}} in RIB, got {result}"
    )

    # Step 2: promote NH2 into ECMP group (metric=200 → 100)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} 10 metric 100\n")
    result = _expect_nexthops(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, (
        f"Metric change [2]: expected both {nh1},{nh2} active after NH2 promoted, got {result}"
    )
    result = _expect_keys(r1, prefix, {(10, 100)}, ipv6)
    assert result is None, (
        f"Metric change [2]: stale (10,200) still present after NH2 promoted, got {result}"
    )
    result = _expect_running(
        r1, prefix,
        [
            f"ip{ip_ver} route {prefix} {nh1} 10 metric 100",
            f"ip{ip_ver} route {prefix} {nh2} 10 metric 100",
        ],
        ipv6,
    )
    assert result is None, (
        f"Metric change [2]: running-config mismatch after NH2 promoted; got {result}"
    )

    # Step 3: demote NH1 to standby (metric=100 → 200)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 200\n")
    result = _expect_nexthops(r1, prefix, {nh2}, ipv6)
    assert result is None, (
        f"Metric change [3]: expected only {nh2} active after NH1 demoted, got {result}"
    )
    result = _expect_keys(r1, prefix, {(10, 100), (10, 200)}, ipv6)
    assert result is None, (
        f"Metric change [3]: expected {{(10,100),(10,200)}} in RIB after NH1 demoted, got {result}"
    )
    result = _expect_running(
        r1, prefix,
        [
            f"ip{ip_ver} route {prefix} {nh2} 10 metric 100",
            f"ip{ip_ver} route {prefix} {nh1} 10 metric 200",
        ],
        ipv6,
    )
    assert result is None, (
        f"Metric change [3]: running-config mismatch after NH1 demoted; got {result}"
    )

    # Step 4: NH1 rejoins ECMP group (metric=200 → 100)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_nexthops(r1, prefix, {nh1, nh2}, ipv6)
    assert result is None, (
        f"Metric change [4]: expected both {nh1},{nh2} active after NH1 rejoined, got {result}"
    )
    result = _expect_keys(r1, prefix, {(10, 100)}, ipv6)
    assert result is None, (
        f"Metric change [4]: stale (10,200) still present after NH1 rejoined, got {result}"
    )

    # Step 5: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10 metric 100\n"
        f"no ip{ip_ver} route {prefix} {nh2} 10 metric 100\n"
    )
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, f"Metric change [cleanup]: route not removed; got {result}"
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Metric change [cleanup]: stale running-config entry; got {result}"
    )


def test_metric_change_ipv4():
    "IPv4: nexthop moves in and out of ECMP group by changing its metric."
    run_metric_change(ipv6=False)


def test_metric_change_ipv6():
    "IPv6: nexthop moves in and out of ECMP group by changing its metric."
    run_metric_change(ipv6=True)


# ---------------------------------------------------------------------------
# Test 5: Metric-aware deletion
# ---------------------------------------------------------------------------


def run_metric_aware_deletion(ipv6=False):
    """
    Verify deletion behaviour for all combinations of distance/metric on 'no ip route':

      a. Both distance and metric specified — exact match; removes the route.
      b. Distance only (no metric) — defaults to metric=0; does NOT match a
         route installed at a non-zero metric; route stays.
      c. Neither distance nor metric — lazy search; removes the route regardless
         of distance and metric.
      d. Two routes at different metrics; exact-key delete of one leaves the
         other intact — directly exercises zebra's delete-lookup loop metric
         check (rib_compare_routes / process_subq_early_route_delete).
      e. Metric only (no distance) — exact match on (distance=default=1, metric);
         removes the route when metric matches; does NOT match a different metric.

    Steps (case a):
      1. Install NH1 at (AD=10, metric=100).
      2. Delete with exact key: 'no ip route ... NH1 10 metric 100'.
      3. Verify route is gone.

    Steps (case b → c):
      4. Install NH1 at (AD=10, metric=100).
      5. Delete without metric: 'no ip route ... NH1 10'.
         This looks for (AD=10, metric=0) — NOT FOUND.
      6. Verify route still present.
      7. Delete without any key: 'no ip route ... NH1'.
         This does lazy search and finds the route.
      8. Verify route is gone.

    Steps (case d):
      9.  Install NH1 at (AD=10, metric=100) and NH2 at (AD=10, metric=200).
      10. Verify both {(10,100),(10,200)} are in the RIB.
      11. Delete NH1 at (AD=10, metric=100) with exact key.
      12. Verify only {(10,200)} remains.
      13. Cleanup: delete NH2 at (AD=10, metric=200).

    Steps (case e):
      14. Install NH1 at (AD=1 default, metric=100).
      15. Delete with wrong metric: 'no ip route ... NH1 metric 200'.
          This looks for (AD=1, metric=200) — NOT FOUND; route stays.
      16. Verify route still present.
      17. Delete with correct metric: 'no ip route ... NH1 metric 100'.
          This looks for (AD=1, metric=100) — exact match; route removed.
      18. Verify route is gone.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    ip_ver = "v6" if ipv6 else ""
    nh1 = NH1_V6 if ipv6 else NH1_V4
    prefix = PREFIX_V6 if ipv6 else PREFIX_V4

    # Case (a): exact-key delete removes the route
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_keys(r1, prefix, {(10, 100)}, ipv6)
    assert result is None, f"Metric deletion (a) [1]: expected {{(10,100)}}, got {result}"

    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Metric deletion (a) [2]: exact-key delete failed; got {result}"
    )

    # Case (b): delete with distance but no metric → looks for metric=0, not found
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_keys(r1, prefix, {(10, 100)}, ipv6)
    assert result is None, f"Metric deletion (b) [4]: expected {{(10,100)}}, got {result}"

    # Delete without metric (defaults to metric=0) — route at metric=100 must survive
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10\n")
    result = _expect_keys(r1, prefix, {(10, 100)}, ipv6)
    assert result is None, (
        f"Metric deletion (b) [5]: route at metric=100 should survive 'no' without metric; got {result}"
    )

    # Case (c): lazy delete (no distance, no metric) finds and removes the route
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1}\n")
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Metric deletion (c) [7]: lazy delete should remove route at any metric; got {result}"
    )
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Metric deletion (c) [8]: stale running-config after lazy delete; got {result}"
    )

    # Case (d): two routes at different metrics; delete one; the other must survive.
    # NH1 and NH2 are used so both path-lists co-exist (nexthop uniqueness only
    # enforces one path-list per nexthop address, not per prefix).
    # This directly exercises zebra's delete-lookup loop: the loop must skip the
    # metric=200 entry and remove only metric=100.
    nh2 = NH2_V6 if ipv6 else NH2_V4
    r1.vtysh_multicmd(
        f"configure\n"
        f"ip{ip_ver} route {prefix} {nh1} 10 metric 100\n"
        f"ip{ip_ver} route {prefix} {nh2} 10 metric 200\n"
    )
    result = _expect_keys(r1, prefix, {(10, 100), (10, 200)}, ipv6)
    assert result is None, (
        f"Metric deletion (d) [9]: expected {{(10,100),(10,200)}}; got {result}"
    )

    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_keys(r1, prefix, {(10, 200)}, ipv6)
    assert result is None, (
        f"Metric deletion (d) [11]: metric=200 entry should survive deletion of "
        f"metric=100; got {result}"
    )

    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh2} 10 metric 200\n")
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, f"Metric deletion (d) [cleanup]: got {result}"

    # Case (e): metric-only delete (no distance) — exact match on (distance=1, metric)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} metric 100\n")
    result = _expect_keys(r1, prefix, {(1, 100)}, ipv6)
    assert result is None, f"Metric deletion (e) [14]: expected {{(1,100)}}; got {result}"

    # Wrong metric — route must survive
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} metric 200\n")
    result = _expect_keys(r1, prefix, {(1, 100)}, ipv6)
    assert result is None, (
        f"Metric deletion (e) [15]: route at metric=100 should survive 'no' with metric=200; got {result}"
    )

    # Correct metric — route must be removed
    r1.vtysh_multicmd(f"configure\nno ip{ip_ver} route {prefix} {nh1} metric 100\n")
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Metric deletion (e) [17]: metric-only exact delete should remove route; got {result}"
    )


def test_metric_aware_deletion_ipv4():
    "IPv4: exact-key, wrong-metric, lazy, two-metric, and metric-only deletion all behave correctly."
    run_metric_aware_deletion(ipv6=False)


def test_metric_aware_deletion_ipv6():
    "IPv6: exact-key, wrong-metric, lazy, two-metric, and metric-only deletion all behave correctly."
    run_metric_aware_deletion(ipv6=True)


# ---------------------------------------------------------------------------
# Test 6: Running-config format
# ---------------------------------------------------------------------------


def run_running_config_format(ipv6=False):
    """
    Verify that metric appears after distance in 'show running-config' output,
    that a zero metric is omitted, and that the default distance (1) is omitted.

    Steps:
      1. Install NH1 at (AD=10, metric=100): expect '... NH1 10 metric 100'.
      2. Install NH2 at (AD=1 default, metric=50): expect '... NH2 metric 50'
         (distance 1 is default → omitted).
      3. Install NH3 at (AD=20, metric=0 default): expect '... NH3 20'
         (metric 0 is default → omitted).
      4. Clean up all three.
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

    # Step 1: non-default AD, non-zero metric
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh1} 10 metric 100\n")
    result = _expect_running(
        r1, prefix, [f"ip{ip_ver} route {prefix} {nh1} 10 metric 100"], ipv6
    )
    assert result is None, (
        f"Running-config format [1]: expected '... NH1 10 metric 100'; got {result}"
    )

    # Step 2: default AD (omitted), non-zero metric
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh2} metric 50\n")
    result = _expect_running(
        r1, prefix,
        [
            f"ip{ip_ver} route {prefix} {nh1} 10 metric 100",
            f"ip{ip_ver} route {prefix} {nh2} metric 50",
        ],
        ipv6,
    )
    assert result is None, (
        f"Running-config format [2]: expected '... NH2 metric 50' (no distance); got {result}"
    )

    # Step 3: non-default AD, zero metric (omitted)
    r1.vtysh_multicmd(f"configure\nip{ip_ver} route {prefix} {nh3} 20\n")
    result = _expect_running(
        r1, prefix,
        [
            f"ip{ip_ver} route {prefix} {nh1} 10 metric 100",
            f"ip{ip_ver} route {prefix} {nh2} metric 50",
            f"ip{ip_ver} route {prefix} {nh3} 20",
        ],
        ipv6,
    )
    assert result is None, (
        f"Running-config format [3]: expected '... NH3 20' (no metric); got {result}"
    )

    # Step 4: clean up
    r1.vtysh_multicmd(
        f"configure\n"
        f"no ip{ip_ver} route {prefix} {nh1} 10 metric 100\n"
        f"no ip{ip_ver} route {prefix} {nh2}\n"
        f"no ip{ip_ver} route {prefix} {nh3} 20\n"
    )
    result = _expect_keys(r1, prefix, set(), ipv6)
    assert result is None, (
        f"Running-config format [cleanup]: route not fully removed; got {result}"
    )
    result = _expect_running(r1, prefix, [], ipv6)
    assert result is None, (
        f"Running-config format [cleanup]: stale running-config; got {result}"
    )


def test_running_config_format_ipv4():
    "IPv4: metric appears after distance in running-config; defaults (dist=1, metric=0) omitted."
    run_running_config_format(ipv6=False)


def test_running_config_format_ipv6():
    "IPv6: metric appears after distance in running-config; defaults (dist=1, metric=0) omitted."
    run_running_config_format(ipv6=True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
