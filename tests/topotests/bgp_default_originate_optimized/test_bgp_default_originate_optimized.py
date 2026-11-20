#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>

"""
Test BGP default-originate with the optimized prefix-list-driven algorithm
(bgp default-originate optimized).

Topology:
  R1 (AS 65000) ---- R2 (AS 65001)

R1 configuration:
  - bgp default-originate optimized
  - IPv4 sentinel routes: 10.0.0.1/32 (comm 100:100) and 10.0.0.2/32 (comm 200:200)
  - IPv6 sentinel routes: 2001:db8::1/128 (comm 100:100) and 2001:db8::2/128 (comm 200:200)
  - default-originate route-maps (IPv4: default-orig, IPv6: default-orig-v6):
      seq 10: match sentinels + match comm-high  =>  set community 10:10
      seq 20: match sentinels + match comm-low   =>  set community 20:20

The optimized algorithm selects the (prefix, path) pair that the route-map
permits at the lowest sequence number; that sequence's set clauses govern
the synthesized default route's attributes.

Tests:
   1. Best-pref selection: both sentinels present; seq 10 wins (community 10:10).
   2. Sentinel removal: remove seq-10 sentinel; seq 20 now wins (community 20:20).
   3. All sentinels removed: no default route advertised.
   4. Sentinel restored: default route re-advertised (community 20:20).
   5. ge/le entries skipped: a ge-qualified prefix-list entry is ignored by the
      optimized path; only exact entries are used as lookup keys.
   6. Catch-all DENY sequence: a bare deny sequence (no match clauses) stops
      the outer loop and withholds the default.
   7. on-match goto over catch-all DENY: a goto in an earlier sequence can jump
      past a catch-all deny to reach a later permit sequence with the prefix-list.
   8. Unconfigured prefix-list: a missing prefix-list withholds the default;
      creating it mid-session restores origination.
   9. Multiple paths per prefix: the path matching at the lowest sequence number
      wins; its set clauses govern the default route's attributes.
  10. Set-only route-map without set-only-unconditional: the optimized path is
      bypassed; default is originated only when the BGP table is non-empty.
  11. Set-only route-map with set-only-unconditional: default is originated
      unconditionally even with an empty BGP table.
  12. Dynamic prefix-list change: adding or removing prefix-list entries
      triggers re-evaluation without changing the BGP routing table.
  13. IPv6 best-pref selection: same best-pref logic via "match ipv6 address
      prefix-list"; R2 receives ::/0 with community 10:10.
  14. IPv6 sentinel removal and restore: ::/0 community changes and withdrawal
      follow the same rules as the IPv4 path.
  15. Sentinel community change: the sentinel stays in the BGP table but its
      community changes, causing it to match a different route-map sequence
      and changing the default's attributes without any route add/remove.
  16. Multiple prefix-lists across sequences: each route-map sequence
      references a distinct prefix-list; the optimized path collects
      candidates from all sequences and selects the globally lowest-pref
      match.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _check_default_community(r2, expected_community):
    """Return None when r2's default route has the expected community."""
    try:
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
    except Exception:
        return "Failed to parse JSON"

    paths = output.get("paths", [])
    if not paths:
        return "No default route at r2"

    community = paths[0].get("community", {}).get("string", "")
    if expected_community not in community:
        return "Expected community '{}' not in '{}'".format(
            expected_community, community
        )
    return None


def _check_no_default_route(r1):
    """Return None when r1 is not originating the default route."""
    try:
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.255.2 advertised-routes json"
            )
        )
    except Exception:
        return "Failed to parse JSON"

    if output.get("bgpOriginatingDefaultNetwork") == "0.0.0.0/0":
        return "Default route is still being originated"
    return None


def _check_v6_default_community(r2, expected_community):
    """Return None when r2's IPv6 default route has the expected community."""
    try:
        output = json.loads(r2.vtysh_cmd("show bgp ipv6 unicast ::/0 json"))
    except Exception:
        return "Failed to parse JSON"

    paths = output.get("paths", [])
    if not paths:
        return "No IPv6 default route at r2"

    community = paths[0].get("community", {}).get("string", "")
    if expected_community not in community:
        return "Expected community '{}' not in '{}'".format(expected_community, community)
    return None


def _check_no_v6_default_route(r1):
    """Return None when r1 is not originating the IPv6 default route."""
    try:
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv6 unicast neighbors 2001:db8:ffff::2 advertised-routes json"
            )
        )
    except Exception:
        return "Failed to parse JSON"

    if output.get("bgpOriginatingDefaultNetwork") == "::/0":
        return "IPv6 default route is still being originated"
    return None


def test_optimized_best_pref_selection():
    """
    Both sentinels present.  10.0.0.1/32 (community 100:100) matches route-map
    seq 10; 10.0.0.2/32 (community 200:200) matches seq 20.  Seq 10 has the
    lower sequence number so its set clause (community 10:10) governs the
    synthesized default route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Wait for BGP session and default route with community 10:10")

    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected default route with community 10:10 at r2: {}".format(result)
    )


def test_sentinel_removal_attribute_change():
    """
    Remove the seq-10 sentinel (10.0.0.1/32) from the BGP table.  Only the
    seq-20 sentinel (10.0.0.2/32) remains, so the default route must now carry
    community 20:20.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Remove 10.0.0.1/32 from BGP table")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      no network 10.0.0.1/32 route-map set-high
"""
    )

    step("Verify default route community changes to 20:20")
    test_func = functools.partial(_check_default_community, r2, "20:20")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected default route with community 20:20 after removing seq-10 sentinel: {}".format(
            result
        )
    )


def test_all_sentinels_removed():
    """
    Remove the remaining sentinel (10.0.0.2/32).  With no sentinel in the BGP
    table, the default route must be withdrawn.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Remove 10.0.0.2/32 from BGP table")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      no network 10.0.0.2/32 route-map set-low
"""
    )

    step("Verify default route is withdrawn")
    test_func = functools.partial(_check_no_default_route, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected no default-originate after removing all sentinels: {}".format(result)
    )


def test_sentinel_restored():
    """
    Restore 10.0.0.2/32.  The default route must be re-advertised with
    community 20:20 (seq 20 is the only matching sequence).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Restore 10.0.0.2/32 to BGP table")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      network 10.0.0.2/32 route-map set-low
"""
    )

    step("Verify default route re-advertised with community 20:20")
    test_func = functools.partial(_check_default_community, r2, "20:20")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected default route with community 20:20 after restoring sentinel: {}".format(
            result
        )
    )


def test_ge_le_entries_skipped():
    """
    Replace the exact prefix-list entry for 10.0.0.1/32 with a ge-qualified
    entry and restore 10.0.0.1/32 to the BGP table.

    The optimized path skips ge/le entries, so 10.0.0.1/32 is NOT used as a
    lookup key even though it is present in the BGP table.  Only the exact
    entry for 10.0.0.2/32 (seq 10 of the prefix-list) is considered.
    10.0.0.2/32 matches route-map seq 20 (community 200:200) → community 20:20.
    If ge/le entries were NOT skipped, 10.0.0.1/32 would be found and would
    match route-map seq 10 → community 10:10.  Seeing 20:20 confirms the skip.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Replace exact 10.0.0.1/32 entry with ge-qualified entry in prefix-list")
    r1.vtysh_cmd(
        """
configure
  no ip prefix-list sentinels seq 5 permit 10.0.0.1/32
  ip prefix-list sentinels seq 5 permit 10.0.0.0/8 ge 32
"""
    )

    step("Restore 10.0.0.1/32 to BGP table (community 100:100)")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      network 10.0.0.1/32 route-map set-high
"""
    )

    step("Verify default route community remains 20:20 (ge entry skipped)")
    test_func = functools.partial(_check_default_community, r2, "20:20")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 20:20 (ge/le entry skipped); got: {}".format(result)
    )

    step("Restore exact entry for 10.0.0.1/32")
    r1.vtysh_cmd(
        """
configure
  no ip prefix-list sentinels seq 5 permit 10.0.0.0/8 ge 32
  ip prefix-list sentinels seq 5 permit 10.0.0.1/32
"""
    )

    step("Verify default route community reverts to 10:10 (exact entry restored)")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 after restoring exact entry: {}".format(result)
    )


def test_catch_all_deny_sequence():
    """
    Insert a bare DENY sequence (no match clauses) before the PERMIT sequences.
    The optimized path stops the outer loop on a catch-all deny, so no sentinel
    can produce a match and the default route must be withdrawn.
    Removing the deny sequence must restore origination.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Insert catch-all DENY sequence 5 in route-map default-orig")
    r1.vtysh_cmd(
        """
configure
  route-map default-orig deny 5
"""
    )

    step("Verify default route is withdrawn")
    test_func = functools.partial(_check_no_default_route, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected no default-originate after catch-all deny: {}".format(result)
    )

    step("Remove catch-all DENY sequence")
    r1.vtysh_cmd(
        """
configure
  no route-map default-orig deny 5
"""
    )

    step("Verify default route is re-advertised with community 10:10")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected default route with community 10:10 after removing deny: {}".format(
            result
        )
    )


def test_on_match_goto_over_catch_all_deny():
    """
    Verify that an on-match goto jumping over a catch-all DENY sequence does
    not suppress prefix-list discovery.

    Route-map layout:
      seq 5  PERMIT: match community comm-high, on-match goto 30
      seq 10 DENY:   (no match clauses — catch-all deny)
      seq 20 PERMIT: match sentinels + match comm-low  -> set community 20:20
      seq 30 PERMIT: match sentinels + match comm-high -> set community 10:10

    For 10.0.0.1/32 (community 100:100 = comm-high):
      route_map_apply_ext hits seq 5 (community matches) -> goto 30 ->
      seq 30 (sentinel + community matches) -> RMAP_PERMITMATCH, pref=30.
      Seq 10 (the catch-all deny) is never evaluated for this route.

    If the outer sequence loop stopped at the catch-all deny (seq 10) it
    would never discover seq 20's or seq 30's prefix-list entries and would
    incorrectly withdraw the default.  The default must still be advertised
    with community 10:10.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Rebuild route-map with on-match goto jumping over a catch-all deny")
    r1.vtysh_cmd(
        """
configure
  no route-map default-orig permit 10
  no route-map default-orig permit 20
  route-map default-orig permit 5
    match community comm-high
    on-match goto 30
  !
  route-map default-orig deny 10
  !
  route-map default-orig permit 20
    match ip address prefix-list sentinels
    match community comm-low
    set community 20:20
  !
  route-map default-orig permit 30
    match ip address prefix-list sentinels
    match community comm-high
    set community 10:10
  !
"""
    )

    step("Verify default route is advertised with community 10:10 (goto 30 wins)")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 via on-match goto over catch-all deny: {}".format(
            result
        )
    )

    step("Restore original route-map (seq 10 permit + seq 20 permit)")
    r1.vtysh_cmd(
        """
configure
  no route-map default-orig permit 5
  no route-map default-orig deny 10
  no route-map default-orig permit 20
  no route-map default-orig permit 30
  route-map default-orig permit 10
    match ip address prefix-list sentinels
    match community comm-high
    set community 10:10
  !
  route-map default-orig permit 20
    match ip address prefix-list sentinels
    match community comm-low
    set community 20:20
  !
"""
    )

    step("Verify default route reverts to community 10:10")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 after restoring original route-map: {}".format(result)
    )


def test_unconfigured_prefix_list():
    """
    Reference a prefix-list that does not exist yet in the route-map.

    bgp_check_prefix_in_prefix_list() returns RMAP_DENYMATCH when
    prefix_list_lookup() returns NULL.  The default must be withheld.
    Creating the prefix-list mid-session triggers re-evaluation and the
    default must then be advertised.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Replace route-map to reference a non-existent prefix-list MISSING")
    r1.vtysh_cmd(
        """
configure
  no route-map default-orig permit 10
  no route-map default-orig permit 20
  route-map default-orig permit 10
    match ip address prefix-list MISSING
    match community comm-high
    set community 10:10
  !
"""
    )

    step("Verify default route is withheld (prefix-list MISSING not configured)")
    test_func = functools.partial(_check_no_default_route, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected no default-originate when prefix-list not configured: {}".format(result)
    )

    step("Create prefix-list MISSING pointing to 10.0.0.1/32")
    r1.vtysh_cmd(
        """
configure
  ip prefix-list MISSING seq 5 permit 10.0.0.1/32
"""
    )

    step("Verify default route is now advertised with community 10:10")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected default route with community 10:10 after adding prefix-list: {}".format(
            result
        )
    )

    step("Restore original route-map and remove MISSING prefix-list")
    r1.vtysh_cmd(
        """
configure
  no ip prefix-list MISSING
  no route-map default-orig permit 10
  route-map default-orig permit 10
    match ip address prefix-list sentinels
    match community comm-high
    set community 10:10
  !
  route-map default-orig permit 20
    match ip address prefix-list sentinels
    match community comm-low
    set community 20:20
  !
"""
    )


def test_multiple_paths_per_prefix():
    """
    Two BGP paths exist for the same sentinel prefix, matching the route-map
    at different sequence numbers.  The optimized path must select the path
    with the lower (higher-priority) sequence number and use its set clauses.

    Setup:
      - r1 networks 10.0.0.1/32 with community 200:200 (comm-low, matches seq 20)
      - r2 also announces 10.0.0.1/32 with community 100:100 (comm-high, matches seq 10)
      - r1 therefore has two paths for 10.0.0.1/32: its own (pref=20) and r2's (pref=10)

    Expected: default route at r2 carries community 10:10 (r2's path wins, pref=10 < 20).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Re-originate 10.0.0.1/32 on r1 with community 200:200 (comm-low, seq 20)")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      no network 10.0.0.1/32 route-map set-high
      network 10.0.0.1/32 route-map set-low
"""
    )

    step("Add 10.0.0.1/32 on r2's loopback and announce it with community 100:100 (comm-high, seq 10)")
    r2.vtysh_cmd(
        """
configure
  interface lo
    ip address 10.0.0.1/32
  !
  route-map r2-comm-high permit 10
    set community 100:100
  !
  router bgp 65001
    address-family ipv4 unicast
      network 10.0.0.1/32 route-map r2-comm-high
"""
    )

    step("Verify r1's default carries community 10:10 (r2's path at seq 10 wins)")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 from lower-pref path (r2's path at seq 10): {}".format(
            result
        )
    )

    step("Withdraw r2's path and restore r1's 10.0.0.1/32 to comm-high")
    r2.vtysh_cmd(
        """
configure
  router bgp 65001
    address-family ipv4 unicast
      no network 10.0.0.1/32 route-map r2-comm-high
  no route-map r2-comm-high
  interface lo
    no ip address 10.0.0.1/32
"""
    )
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      no network 10.0.0.1/32 route-map set-low
      network 10.0.0.1/32 route-map set-high
"""
    )

    step("Verify default reverts to community 10:10 (single path, seq 10)")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 after removing r2's path: {}".format(result)
    )


def test_setonly_rmap_without_unconditional_flag():
    """
    Set-only route-map (no match clauses) with 'bgp default-originate optimized'
    enabled but WITHOUT 'bgp default-originate set-only-unconditional'.

    The optimized prefix-list path is NOT taken (match_rules == 0); the code
    falls through to the full RIB walk.  In backward-compatible mode the RIB
    walk requires at least one route in the BGP table before originating the
    default.

    Steps:
      1. Replace the conditional route-map with a set-only one (set community 30:30).
      2. With a sentinel route present  → default originated, community 30:30.
      3. Remove the sentinel route      → default withdrawn (empty table, no flag).
      4. Restore the sentinel route     → default re-originated, community 30:30.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Install set-only route-map (no match clauses, set community 30:30)")
    r1.vtysh_cmd(
        """
configure
  no route-map default-orig permit 10
  no route-map default-orig permit 20
  route-map default-orig permit 10
    set community 30:30
  !
"""
    )

    step("Verify default route originated with community 30:30 (sentinel in table)")
    test_func = functools.partial(_check_default_community, r2, "30:30")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected default route with community 30:30 (set-only, with sentinel): {}".format(
            result
        )
    )

    step("Remove all sentinels from BGP table")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    no bgp default-originate set-only-unconditional
    address-family ipv4 unicast
      no network 10.0.0.1/32 route-map set-high
      no network 10.0.0.2/32 route-map set-low
"""
    )

    step("Verify default route is withdrawn (empty table, no set-only-unconditional)")
    test_func = functools.partial(_check_no_default_route, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected no default-originate with empty table and no unconditional flag: {}".format(
            result
        )
    )

    step("Restore sentinel 10.0.0.2/32")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      network 10.0.0.2/32 route-map set-low
"""
    )

    step("Verify default route re-originated with community 30:30")
    test_func = functools.partial(_check_default_community, r2, "30:30")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected default route with community 30:30 after restoring sentinel: {}".format(
            result
        )
    )


def test_setonly_rmap_with_unconditional_flag():
    """
    Set-only route-map with both 'bgp default-originate optimized' AND
    'bgp default-originate set-only-unconditional' enabled.

    The optimized path is still NOT taken (match_rules == 0); the code falls
    through to bgp_route_map_setting_only(), which applies the set clauses
    unconditionally without requiring a table route.

    Steps:
      1. Enable 'bgp default-originate set-only-unconditional'.
      2. Remove the sentinel so the BGP table is empty.
         → default must still be originated with community 30:30.
      3. Disable 'bgp default-originate set-only-unconditional'.
         → default must be withdrawn (empty table, backward-compat mode).
      4. Restore the sentinel and the conditional route-map for cleanup.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Enable bgp default-originate set-only-unconditional")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    bgp default-originate set-only-unconditional
"""
    )

    step("Remove remaining sentinel so BGP table is empty")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      no network 10.0.0.2/32 route-map set-low
"""
    )

    step("Verify default originated with community 30:30 despite empty table")
    test_func = functools.partial(_check_default_community, r2, "30:30")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected default route with community 30:30 with set-only-unconditional "
        "and empty table: {}".format(result)
    )

    step("Disable bgp default-originate set-only-unconditional")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    no bgp default-originate set-only-unconditional
"""
    )

    step("Verify default is withdrawn (empty table, backward-compat mode restored)")
    test_func = functools.partial(_check_no_default_route, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected no default-originate after disabling set-only-unconditional: {}".format(
            result
        )
    )

    step("Restore sentinels and conditional route-map for clean state")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      network 10.0.0.1/32 route-map set-high
      network 10.0.0.2/32 route-map set-low
  no route-map default-orig permit 10
  route-map default-orig permit 10
    match ip address prefix-list sentinels
    match community comm-high
    set community 10:10
  !
  route-map default-orig permit 20
    match ip address prefix-list sentinels
    match community comm-low
    set community 20:20
  !
"""
    )


def test_dynamic_prefix_list_change():
    """
    Modify the prefix-list entries mid-session and verify that
    default-originate re-evaluates correctly each time.

    The existing tests add/remove BGP network statements (the sentinel routes
    themselves).  This test instead modifies the prefix-list that the
    route-map references, leaving the sentinel routes in the BGP table
    throughout.  This verifies that prefix_list_lookup() changes are picked
    up at the next re-evaluation.

    Steps:
      A. Remove 10.0.0.1/32 from the prefix-list (keep it in BGP table).
         Only 10.0.0.2/32 remains as a lookup key.
         -> default community changes to 20:20 (seq 20, comm-low).

      B. Add 10.0.0.1/32 back to the prefix-list.
         -> default community reverts to 10:10 (seq 10, comm-high).

      C. Remove 10.0.0.2/32 from the prefix-list (10.0.0.1/32 is now the only entry).
         -> default community stays 10:10 (10.0.0.1/32 matches seq 10, comm-high).

      D. Remove 10.0.0.1/32 from the prefix-list (prefix-list completely empty).
         -> default withdrawn (empty prefix-list, no candidates).

      E. Restore both entries.
         -> default re-advertised with community 10:10.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("A: Remove 10.0.0.1/32 from prefix-list sentinels (sentinel stays in BGP)")
    r1.vtysh_cmd(
        """
configure
  no ip prefix-list sentinels seq 5 permit 10.0.0.1/32
"""
    )

    step("A: Verify default community changes to 20:20 (only 10.0.0.2/32 in prefix-list)")
    test_func = functools.partial(_check_default_community, r2, "20:20")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 20:20 after removing 10.0.0.1/32 from prefix-list: {}".format(
            result
        )
    )

    step("B: Add 10.0.0.1/32 back to prefix-list sentinels")
    r1.vtysh_cmd(
        """
configure
  ip prefix-list sentinels seq 5 permit 10.0.0.1/32
"""
    )

    step("B: Verify default community reverts to 10:10")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 after restoring 10.0.0.1/32 to prefix-list: {}".format(
            result
        )
    )

    step("C: Remove 10.0.0.2/32 from prefix-list (only 10.0.0.1/32 remains)")
    r1.vtysh_cmd(
        """
configure
  no ip prefix-list sentinels seq 10 permit 10.0.0.2/32
"""
    )

    step("C: Verify default community stays 10:10 (10.0.0.1/32 still in list)")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 with only 10.0.0.1/32 in prefix-list: {}".format(result)
    )

    step("D: Remove 10.0.0.1/32 from prefix-list (prefix-list now completely empty)")
    r1.vtysh_cmd(
        """
configure
  no ip prefix-list sentinels seq 5 permit 10.0.0.1/32
"""
    )

    step("D: Verify default is withdrawn (empty prefix-list, no candidates)")
    test_func = functools.partial(_check_no_default_route, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected no default-originate with completely empty prefix-list: {}".format(result)
    )

    step("E: Restore both entries to prefix-list sentinels")
    r1.vtysh_cmd(
        """
configure
  ip prefix-list sentinels seq 5 permit 10.0.0.1/32
  ip prefix-list sentinels seq 10 permit 10.0.0.2/32
"""
    )

    step("E: Verify default re-advertised with community 10:10")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 after restoring both prefix-list entries: {}".format(
            result
        )
    )


def test_sentinel_community_change():
    """
    The sentinel route stays in the BGP table throughout but its community
    changes, causing it to match a different route-map sequence.  The
    optimized path re-evaluates on the next trigger and the default route's
    attributes must reflect the new winning sequence.

    Steps:
      1. Change 10.0.0.1/32 from community 100:100 (comm-high, seq 10) to
         200:200 (comm-low, seq 20).  Both sentinels now match seq 20.
         -> default community changes to 20:20.
      2. Restore 10.0.0.1/32 to community 100:100 (comm-high).
         -> default community reverts to 10:10 (seq 10 wins again).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Change 10.0.0.1/32 community from 100:100 to 200:200 (comm-low)")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    bgp default-originate optimized
    address-family ipv4 unicast
      no network 10.0.0.1/32 route-map set-high
      network 10.0.0.1/32 route-map set-low
"""
    )

    step("Verify default community changes to 20:20 (both sentinels now match seq 20)")
    test_func = functools.partial(_check_default_community, r2, "20:20")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 20:20 after community change on sentinel: {}".format(result)
    )

    step("Restore 10.0.0.1/32 to community 100:100 (comm-high)")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      no network 10.0.0.1/32 route-map set-low
      network 10.0.0.1/32 route-map set-high
"""
    )

    step("Verify default community reverts to 10:10")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 after restoring sentinel community: {}".format(result)
    )


def test_multiple_prefix_lists_across_sequences():
    """
    Each route-map sequence references a different prefix-list.  The optimized
    path must discover and evaluate prefix-lists from all sequences, not just
    the first one that contains a match.

    Setup:
      - Create route-map default-orig-split with two sequences:
          seq 10: match plist-a (10.0.0.3/32) + match comm-high -> set community 10:10
          seq 20: match plist-b (10.0.0.2/32) + match comm-low  -> set community 20:20
      - 10.0.0.3/32 is a new sentinel on r1's loopback, community 100:100.
      - 10.0.0.2/32 is the existing sentinel, community 200:200.

    Steps:
      1. With 10.0.0.3/32 present (matches seq 10 via plist-a):
         -> default community is 10:10.
      2. Remove 10.0.0.3/32 from BGP.  Only 10.0.0.2/32 remains (matches seq 20
         via plist-b).
         -> default community changes to 20:20.
      3. Cleanup: remove split route-map and restore original.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Add 10.0.0.3/32 to r1's loopback and BGP table with comm-high")
    r1.vtysh_cmd(
        """
configure
  interface lo
    ip address 10.0.0.3/32
  !
  router bgp 65000
    address-family ipv4 unicast
      network 10.0.0.3/32 route-map set-high
"""
    )

    step("Create split route-map referencing separate prefix-lists per sequence")
    r1.vtysh_cmd(
        """
configure
  ip prefix-list plist-a seq 5 permit 10.0.0.3/32
  ip prefix-list plist-b seq 5 permit 10.0.0.2/32
  !
  route-map default-orig-split permit 10
    match ip address prefix-list plist-a
    match community comm-high
    set community 10:10
  !
  route-map default-orig-split permit 20
    match ip address prefix-list plist-b
    match community comm-low
    set community 20:20
  !
  router bgp 65000
    bgp default-originate optimized
    address-family ipv4 unicast
      neighbor 192.168.255.2 default-originate route-map default-orig-split
"""
    )

    step("Verify default community is 10:10 (plist-a sentinel at seq 10 wins)")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 with plist-a sentinel present: {}".format(result)
    )

    step("Remove 10.0.0.3/32 from BGP (plist-a sentinel gone)")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      no network 10.0.0.3/32 route-map set-high
"""
    )

    step("Verify default community changes to 20:20 (plist-b sentinel at seq 20 wins)")
    test_func = functools.partial(_check_default_community, r2, "20:20")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 20:20 with only plist-b sentinel present: {}".format(result)
    )

    step("Cleanup: restore original route-map and remove split config")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv4 unicast
      neighbor 192.168.255.2 default-originate route-map default-orig
  no route-map default-orig-split
  no ip prefix-list plist-a
  no ip prefix-list plist-b
  interface lo
    no ip address 10.0.0.3/32
"""
    )

    step("Verify default community reverts to 10:10")
    test_func = functools.partial(_check_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected community 10:10 after restoring original route-map: {}".format(result)
    )


def test_ipv6_optimized_best_pref_selection():
    """
    IPv6 equivalent of test_optimized_best_pref_selection.

    R1 advertises two IPv6 sentinel prefixes:
      2001:db8::1/128  community 100:100 (comm-high, matches route-map seq 10)
      2001:db8::2/128  community 200:200 (comm-low,  matches route-map seq 20)

    The optimized path uses "match ipv6 address prefix-list sentinels-v6" to
    discover candidates.  With both sentinels present, seq 10 wins and R2
    should receive ::/0 with community 10:10.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    step("Wait for IPv6 BGP session and ::/0 with community 10:10")

    test_func = functools.partial(_check_v6_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected ::/0 with community 10:10 at r2: {}".format(result)
    )


def test_ipv6_sentinel_removal_and_restore():
    """
    IPv6 equivalent of sentinel removal tests.

    Steps:
      1. Remove 2001:db8::1/128 (seq-10 sentinel) from BGP.
         -> ::/0 community changes to 20:20 (seq 20 now wins).
      2. Remove 2001:db8::2/128 (last sentinel).
         -> ::/0 is withdrawn.
      3. Restore 2001:db8::2/128.
         -> ::/0 re-advertised with community 20:20.
      4. Restore 2001:db8::1/128.
         -> ::/0 community reverts to 10:10.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Remove IPv6 sentinel 2001:db8::1/128 from BGP")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv6 unicast
      no network 2001:db8::1/128 route-map set-high
"""
    )

    step("Verify ::/0 community changes to 20:20")
    test_func = functools.partial(_check_v6_default_community, r2, "20:20")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected ::/0 with community 20:20 after removing seq-10 sentinel: {}".format(
            result
        )
    )

    step("Remove last IPv6 sentinel 2001:db8::2/128 from BGP")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv6 unicast
      no network 2001:db8::2/128 route-map set-low
"""
    )

    step("Verify ::/0 is withdrawn")
    test_func = functools.partial(_check_no_v6_default_route, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected no ::/0 after removing all IPv6 sentinels: {}".format(result)
    )

    step("Restore 2001:db8::2/128")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv6 unicast
      network 2001:db8::2/128 route-map set-low
"""
    )

    step("Verify ::/0 re-advertised with community 20:20")
    test_func = functools.partial(_check_v6_default_community, r2, "20:20")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected ::/0 with community 20:20 after restoring one sentinel: {}".format(
            result
        )
    )

    step("Restore 2001:db8::1/128")
    r1.vtysh_cmd(
        """
configure
  router bgp 65000
    address-family ipv6 unicast
      network 2001:db8::1/128 route-map set-high
"""
    )

    step("Verify ::/0 community reverts to 10:10")
    test_func = functools.partial(_check_v6_default_community, r2, "10:10")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "Expected ::/0 with community 10:10 after restoring both sentinels: {}".format(
            result
        )
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
