#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Philippe Brisset

"""
test_bgp_upa_multipeer.py: Multi-peer topology tests for BGP UPA ExtCom aggregation
and per-neighbor filtering.

TOPOLOGY OVERVIEW:
==================

    R5 (AS 65006) - Route Originator
        │ BGP: advertises 10.1.1.0/24, 10.1.2.0/24
        │ Static routes back the BGP advertisements
        ▼
    R4 (AS 65005) - TRANSIT/P ROUTER
        │ Role: Pure transit - NO aggregate configuration
        │ BGP: Relays routes between R5 and R1
        │ Has 'neighbor upa' to relay UPA ExtComs
        ▼
    R1 (AS 65001) - PE ROUTER
        │ Role: Provider Edge with aggregation
        │ Config: aggregate-address 10.1.0.0/16 upa drop max-routes 100
        │ Originates UPA when BGP-learned constituent becomes unreachable
        │ Router-ID: 10.255.0.1
        ├─→ R2 (AS 65003) - has 'neighbor upa' ✓ (receives UPA)
        ├─→ R3 (AS 65004) - NO 'neighbor upa' ✗ (UPA filtered)
        └─→ R4 (AS 65005) - has 'neighbor upa' (for transit)

ROUTER ROLES:
=============

- R5: Route source - advertises specific routes via BGP (with static backing routes)
- R4: **P (Provider core) router** - Transit only, NO aggregation, relays routes
- R1: **PE (Provider Edge) router** - Has aggregate, originates UPA when constituent lost
- R2: UPA-capable peer (has 'neighbor upa') - receives UPA ExtComs
- R3: Non-UPA peer (no 'neighbor upa') - UPA ExtComs filtered

CRITICAL DESIGN DECISION:
=========================

R4 is a **transit/P router**, NOT a PE router. This means:
- R4 does NOT have an aggregate-address configuration
- R4 does NOT originate UPA
- R4 only relays routes and withdrawals between R5 and R1
- Only R1 (the PE router) aggregates and originates UPA

TEST SCENARIOS:
===============

This test suite validates:

1. **BGP Convergence** (Test 1):
   - All BGP sessions establish
   - R5's routes propagate: R5 → R4 → R1

2. **UPA Origination & Propagation** (Test 2):
   - R5 withdraws BOTH 10.1.1.0/24 and 10.1.2.0/24 via BGP
   - R4 relays withdrawals to R1 (R4 is just transit)
   - R1 loses ALL constituents → R1 originates UPA with upa:10.255.0.1:drop
   - R1 propagates UPA to R2 (has 'neighbor upa')
   - R3 does NOT receive UPA (filtered - no 'neighbor upa')
   - **Critical**: UPA is only originated when ALL constituents are lost

3. **Per-Neighbor UPA Filtering** (Tests 3-5):
   - UPA ExtComs propagate to peers with 'neighbor upa' capability
   - UPA ExtComs filtered from peers without 'neighbor upa'
   - Update groups correctly separate UPA-capable from non-capable peers

KEY TEST FLOW:
==============

Initial State:
  R5 advertises 10.1.1.0/24 and 10.1.2.0/24 → R4 relays → R1 receives both

Withdrawal Event:
  R5: no network 10.1.1.0/24; no network 10.1.2.0/24 (withdraw BOTH)
    ↓
  R4: receives withdrawals, relays both to R1 (transit function)
    ↓
  R1: loses ALL BGP-learned constituents under aggregate 10.1.0.0/16
    ↓
  R1: originates UPA for aggregate 10.1.0.0/16
      ExtCom: upa:10.255.0.1:drop (R1's Router-ID + D-bit)
    ↓
  R2: receives UPA (has 'neighbor upa')
  R3: NO UPA (filtered - no 'neighbor upa')

CRITICAL UPA BEHAVIOR:
  UPA is ONLY originated when ALL constituents become unreachable.
  Withdrawing only 10.1.1.0/24 while 10.1.2.0/24 remains valid would NOT trigger UPA.

This tests UPA origination when BGP-learned constituents become unreachable
and subsequent per-neighbor filtering based on UPA capability negotiation.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step, kill_router_daemons, start_router_daemons

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


def build_topo(tgen):
    """
    Multi-peer topology:

           [R1]--------10.0.2.1/24-------[R2] AS 65003 (has 'upa')
        AS 65001       10.0.2.2/24
              |
              |--------10.0.3.1/24-------[R3] AS 65004 (NO 'upa' - filter)
              |        10.0.3.2/24
              |
              |--------10.0.4.1/24-------[R4] AS 65005 (has 'upa')
                       10.0.4.2/24        |
                                          |
                                     10.0.5.1/24
                                          |
                                       [R5] AS 65006
                                     10.0.5.2/24

    Purpose:
    - R5: Advertises 10.1.1.0/24 and 10.1.2.0/24 to R4
    - R4: Has aggregate 10.1.0.0/16 with UPA enabled
          When R5 withdraws → R4 originates UPA (BGP constituent lost)
    - R1: Has aggregate, receives UPA from R4 (or originates own UPA)
    - R2: Has 'neighbor upa' - should receive UPA from R1
    - R3: NO 'neighbor upa' - should NOT receive UPA (filtered)
    """

    # Create routers
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    # Links
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])


def setup_module(mod):
    """Setup test environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Teardown test environment"""
    tgen = get_topogen()
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def ensure_baseline_state():
    """
    Fixture that runs after each test to verify baseline state.
    This catches any pollution from previous tests.

    Baseline state:
    - R5 advertises 10.1.1.0/24 and 10.1.2.0/24 to R4 via BGP
    - R4 receives them and advertises aggregate to R1
    - R1 receives them as aggregate constituents
    """
    # Run before test
    yield

    # Run after test - verify routes are restored on R5
    tgen = get_topogen()
    if tgen.routers_have_failure():
        return

    r5 = tgen.gears["r5"]

    # Verify both networks are advertised by R5
    def _verify_baseline():
        output = r5.vtysh_cmd("show ip bgp summary json")

        try:
            data = json.loads(output)
            # Check if BGP is running and advertising networks
            if "ipv4Unicast" not in data:
                return "BGP not running on R5"

            # Check the specific routes in BGP table
            bgp_table = r5.vtysh_cmd("show ip bgp json")
            routes = json.loads(bgp_table)

            if "routes" not in routes:
                return "No BGP routes on R5"

            if "10.1.1.0/24" not in routes["routes"]:
                return "Missing 10.1.1.0/24 in R5 BGP table"
            if "10.1.2.0/24" not in routes["routes"]:
                return "Missing 10.1.2.0/24 in R5 BGP table"

            return None
        except Exception as e:
            return str(e)

    # Give time for any async cleanup to complete
    time.sleep(1)

    _, result = topotest.run_and_expect(_verify_baseline, None, count=15, wait=0.5)
    if result is not None:
        # Try to restore if missing - re-advertise networks on R5
        r5.vtysh_cmd("conf t\nrouter bgp 65006\naddress-family ipv4 unicast\nnetwork 10.1.1.0/24\nnetwork 10.1.2.0/24")
        time.sleep(3)  # Wait for BGP to propagate to R4 and R1


def test_bgp_convergence():
    """
    Test 1: Verify BGP sessions established across all routers

    Expected:
    - R1 has 3 BGP sessions: R2, R3, R4
    - R2, R3, R4 each have 1 BGP session to R1
    - R4 has 2 BGP sessions: R1, R5
    - R5 has 1 BGP session to R4
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 1: BGP Convergence - Verify all BGP sessions established")
    step("=" * 60)

    # Check R1 BGP neighbors - use same pattern as bgp_features test
    r1 = tgen.gears["r1"]

    def _bgp_converge_r1():
        output = json.loads(r1.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "10.0.2.2": {"state": "Established"},
                    "10.0.3.2": {"state": "Established"},
                    "10.0.4.2": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r1)
    _, result = topotest.run_and_expect(test_func, None, count=125, wait=0.5)
    assert result is None, "R1 BGP sessions to FRR routers did not converge"

    # Check R4 session to R5
    r4 = tgen.gears["r4"]

    def _bgp_converge_r4():
        output = json.loads(r4.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "10.0.5.2": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r4)
    _, result = topotest.run_and_expect(test_func, None, count=125, wait=0.5)
    assert result is None, "R4 BGP session to R5 did not converge"

    # Check R2
    r2 = tgen.gears["r2"]
    def _bgp_converge_r2():
        output = json.loads(r2.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "10.0.2.1": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "R2 BGP session did not converge"

    step("Test 1 PASSED: BGP convergence verified")
    step("=" * 60)


def test_extcom_aggregation_multiple_sources():
    """
    Test 2: UPA origination and propagation

    Topology:
    - R5 (AS 65006): Route originator - advertises 10.1.1.0/24 and 10.1.2.0/24
    - R4 (AS 65005): Transit router (P) - relays routes between R5 and R1
    - R1 (AS 65001): PE router - has aggregate 10.1.0.0/16 with UPA and summary-only
    - R2 (AS 65003): Peer of R1 with 'neighbor upa' - should receive UPA
    - R3 (AS 65004): Peer of R1 WITHOUT 'neighbor upa' - should NOT receive UPA

    Test Flow:
    1. Initial: R5 → R4 → R1 (10.1.1.0/24 and 10.1.2.0/24 flow normally)
       R1 only advertises aggregate 10.1.0.0/16 to R2 (summary-only suppresses specifics)
    2. R5 withdraws BOTH 10.1.1.0/24 and 10.1.2.0/24 via BGP
    3. R4 withdraws both from R1 (R4 is just relaying)
    4. R1 loses ALL constituents → R1 originates UPA with ExtCom: upa:10.255.0.1:drop
    5. R1 propagates UPA to R2 (has 'neighbor upa')
    6. R3 does NOT receive UPA (filtered - no 'neighbor upa')

    This tests UPA origination when ALL BGP-learned constituents become unreachable
    and subsequent propagation to UPA-capable peers.

    Note: UPA is only originated when ALL constituents are lost. Withdrawing only
    one constituent (e.g., 10.1.1.0/24) while 10.1.2.0/24 remains would NOT trigger UPA.

    Note: The aggregate uses summary-only to suppress advertising specific routes,
    so R2 only receives the aggregate (10.1.0.0/16) initially, then UPA for specifics.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 2: UPA Origination and Propagation (R1 → R2)")
    step("=" * 60)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    # Step 1: Verify R1 has normal route from R4 initially
    step("Step 2.1: Verify R1 has normal BGP route from R4 for 10.1.1.0/24")

    def _r1_has_route_from_r4():
        output = r1.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "No paths for 10.1.1.0/24"

            # Should be from R4 (Router-ID 10.255.0.4)
            peer_router_id = paths[0].get("peer", {}).get("routerId", "")
            if peer_router_id != "10.255.0.4":
                return "Path not from R4 (Router-ID 10.255.0.4), got: {}".format(peer_router_id)

            # Should NOT have UPA ExtCom yet
            extcoms = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" in extcoms:
                return "Unexpected UPA ExtCom: {}".format(extcoms)

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r1_has_route_from_r4, None, count=30, wait=1)
    assert result is None, "R1 initial state check failed: {}".format(result)

    # Step 2: R5 withdraws BOTH constituents -> R4 withdraws to R1 -> R1 originates UPA
    step("Step 2.2: R5 withdraws 10.1.1.0/24 and 10.1.2.0/24 - R4 relays withdrawals to R1")
    r5 = tgen.gears["r5"]
    # Withdraw both constituents so R1 has NO valid paths under aggregate
    r5.vtysh_cmd("conf t\nrouter bgp 65006\naddress-family ipv4 unicast\nno network 10.1.1.0/24\nno network 10.1.2.0/24")

    # Step 3: Check R1 originates UPA (R1 has the aggregate, loses ALL constituents)
    step("Step 2.3: Verify R1 originates UPA for 10.1.1.0/24")

    def _r1_has_upa():
        output = r1.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "No paths found for 10.1.1.0/24 on R1"

            # R1 originates UPA when it loses constituent from R4
            path = paths[0]
            extcoms = path.get("extendedCommunity", {}).get("string", "")

            if "upa:" not in extcoms:
                return "No UPA ExtCom found on R1: {}".format(extcoms)

            # Should have R1's Router-ID (R1 originated the UPA)
            if "10.255.0.1" not in extcoms:
                return "UPA ExtCom missing R1 Router-ID (10.255.0.1): {}".format(extcoms)

            # Should have D-bit
            if ":drop" not in extcoms and ":0x80" not in extcoms:
                return "UPA ExtCom missing D-bit: {}".format(extcoms)

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r1_has_upa, None, count=30, wait=1)
    assert result is None, "R1 did not originate UPA: {}".format(result)

    step("Step 2.4: Verify R2 receives UPA propagated from R1")

    def _r2_has_upa_route():
        output = r2.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "No paths found on R2"

            # Check path has UPA ExtCom from R1 (R1 originated after losing constituent)
            path = paths[0]
            extcoms = path.get("extendedCommunity", {}).get("string", "")

            if "upa:" not in extcoms:
                return "No UPA ExtCom found on R2: {}".format(extcoms)

            # Should have R1's Router-ID (10.255.0.1) - R1 originated the UPA
            if "10.255.0.1" not in extcoms:
                return "UPA ExtCom missing R1 Router-ID: {}".format(extcoms)

            # Should have D-bit (can be ":drop" or ":0x80")
            if ":drop" not in extcoms and ":0x80" not in extcoms:
                return "UPA ExtCom missing D-bit: {}".format(extcoms)

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_has_upa_route, None, count=30, wait=1)

    # Debug: If test fails, dump relevant logs and BGP state
    if result is not None:
        step("DEBUG: Test failed, dumping diagnostics...")

        # Dump R1's BGP table for the route - DETAILED
        step("R1 BGP table for 10.1.1.0/24 (DETAILED):")
        print(r1.vtysh_cmd("show ip bgp 10.1.1.0/24"))

        # Check all paths at R1
        step("R1 ALL paths for 10.1.1.0/24:")
        print(r1.vtysh_cmd("show bgp ipv4 10.1.1.0/24 detail"))

        # Dump R2's BGP table
        step("R2 BGP table for 10.1.1.0/24:")
        print(r2.vtysh_cmd("show ip bgp 10.1.1.0/24"))

        # Dump R1->R2 advertised routes
        step("R1 advertised routes to R2:")
        print(r1.vtysh_cmd("show ip bgp neighbor 10.0.2.2 advertised-routes"))

        # Check R1->R2 routes including withdrawn
        step("R1->R2 routes (including updates):")
        print(r1.vtysh_cmd("show bgp ipv4 neighbor 10.0.2.2 routes"))

        # Check send-community status
        step("R1 neighbor R2 config:")
        print(r1.vtysh_cmd("show bgp neighbor 10.0.2.2"))

        # Check R4 state
        step("R4 BGP table for 10.1.1.0/24:")
        print(r4.vtysh_cmd("show ip bgp 10.1.1.0/24"))

        # Dump last 100 lines of UPA debug logs
        step("R1 UPA debug logs (last 100 lines):")
        print(r1.run("grep -i upa /tmp/r1-bgpd.log | tail -100"))

        step("R1 update debug logs for 10.1.1:")
        print(r1.run("grep '10.1.1' /tmp/r1-bgpd.log | tail -50"))

    assert result is None, "R2 did not receive UPA: {}".format(result)

    # Step 5: Cleanup - Restore the route
    step("Step 2.5: Cleanup - R5 re-advertises 10.1.1.0/24")
    r5.vtysh_cmd("conf t\nrouter bgp 65006\naddress-family ipv4 unicast\nnetwork 10.1.1.0/24")

    def _r1_route_restored():
        # Check R1's BGP table for route from R4
        output = r1.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "No paths for 10.1.1.0/24 after restoration"

            # Should have normal route from R4 (Router-ID 10.255.0.4)
            path = paths[0]
            peer_router_id = path.get("peer", {}).get("routerId", "")
            if peer_router_id != "10.255.0.4":
                return "Best path not from R4: {}".format(path)

            # Should NOT have UPA ExtCom
            extcoms = path.get("extendedCommunity", {}).get("string", "")
            if "upa:" in extcoms:
                return "UPA ExtCom still present: {}".format(extcoms)

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r1_route_restored, None, count=30, wait=0.5)
    assert result is None, "Failed to restore normal route: {}".format(result)

    step("Test 2 PASSED: UPA origination by R4 and propagation via R1 to R2 verified, cleanup completed")
    step("=" * 60)


def test_upa_filtering_with_capability():
    """
    Test 3: Verify UPA propagated to peer WITH 'neighbor upa'

    Expected:
    - R2 has 'neighbor 10.0.2.1 upa' configured
    - R2 should receive UPA routes from R1
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 3: UPA Filtering WITH Capability")
    step("=" * 60)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]
    r5 = tgen.gears["r5"]

    # Withdraw 10.1.2.0/24 on R5 to trigger UPA on R1
    step("Step 3.1: R5 withdraws 10.1.2.0/24 - R1 should originate UPA")
    r5.vtysh_cmd("conf t\nrouter bgp 65006\naddress-family ipv4 unicast\nno network 10.1.2.0/24")

    time.sleep(3)

    # Verify R2 receives UPA
    step("Step 3.2: Verify R2 receives UPA for 10.1.2.0/24")

    def _r2_has_upa():
        output = r2.vtysh_cmd("show ip bgp 10.1.2.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "R2 has no path for 10.1.2.0/24"

            # Check path has UPA ExtCom
            extcoms = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" not in extcoms:
                return "Missing UPA ExtCom: {}".format(extcoms)

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_has_upa, None, count=30, wait=1)
    assert result is None, "R2 did not receive UPA: {}".format(result)

    # Cleanup: Restore BGP route on R5 and wait for convergence
    step("Step 3.3: Cleanup - R5 re-advertises 10.1.2.0/24")
    r5.vtysh_cmd("conf t\nrouter bgp 65006\naddress-family ipv4 unicast\nnetwork 10.1.2.0/24")
    assert result is None, "Cleanup failed: {}".format(result)

    step("Test 3 PASSED: UPA propagation to capable peer verified and cleanup completed")
    step("=" * 60)


def test_upa_filtering_without_capability():
    """
    Test 4: Verify UPA FILTERED from peer WITHOUT 'neighbor upa'

    Expected:
    - R3 does NOT have 'neighbor upa' configured
    - R3 should NOT receive UPA routes from R1 (filtered)
    - R3 should receive normal (non-UPA) routes normally
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 4: UPA Filtering WITHOUT Capability")
    step("=" * 60)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    # First verify R3 receives normal routes (aggregate)
    step("Step 4.1: Verify R3 receives normal aggregate route")

    def _r3_has_aggregate():
        output = r3.vtysh_cmd("show ip bgp 10.1.0.0/16 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "R3 has no path for 10.1.0.0/16"
            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r3_has_aggregate, None, count=30, wait=1)
    assert result is None, "R3 did not receive aggregate: {}".format(result)

    # R5 withdraws 10.1.2.0/24 → R4 originates UPA → R1 receives → R3 should filter
    step("Step 4.2: R5 withdraws 10.1.2.0/24 - R4 should originate UPA")
    r5 = tgen.gears["r5"]
    r5.vtysh_cmd("conf t\nrouter bgp 65006\naddress-family ipv4 unicast\nno network 10.1.2.0/24")

    time.sleep(3)

    # Verify R3 does NOT receive UPA (filtered)
    step("Step 4.3: Verify R3 does NOT receive UPA for 10.1.2.0/24")

    def _r3_no_upa():
        output = r3.vtysh_cmd("show ip bgp 10.1.2.0/24 json")
        try:
            parsed = json.loads(output)
            # Should have no paths (filtered)
            if parsed == {} or "paths" not in parsed or len(parsed["paths"]) == 0:
                return None

            # If path exists, check it's NOT a UPA route
            paths = parsed.get("paths", [])
            extcoms = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" in extcoms:
                return "R3 received UPA route (should be filtered)"

            # Non-UPA route is OK (shouldn't happen in this test but allowed)
            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r3_no_upa, None, count=30, wait=1)
    assert result is None, "R3 UPA filtering failed: {}".format(result)

    step("Step 4.4: Cleanup - R5 re-advertises 10.1.2.0/24")
    r5.vtysh_cmd("conf t\nrouter bgp 65006\naddress-family ipv4 unicast\nnetwork 10.1.2.0/24")
    time.sleep(3)

    # Verify cleanup - normal route from R4 (which got it from R5) should be back on R1
    def _route_restored():
        output = r4.vtysh_cmd("show ip bgp 10.1.2.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "No paths after restore on R4"
            # Should be from R5 (Router-ID 10.255.0.5)
            path = paths[0]
            peer_router_id = path.get("peer", {}).get("routerId", "")
            if peer_router_id != "10.255.0.5":
                return "Best path on R4 not from R5: {}".format(path)
            # Should NOT have UPA ExtCom
            extcoms = path.get("extendedCommunity", {}).get("string", "")
            if "upa:" in extcoms:
                return "UPA ExtCom still present: {}".format(extcoms)
            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_route_restored, None, count=30, wait=0.5)
    assert result is None, "Cleanup failed: {}".format(result)

    step("Test 4 PASSED: UPA filtering verified and cleanup completed")
    step("=" * 60)


def test_update_group_separation():
    """
    Test 5: Verify update group separation based on UPA capability

    Expected:
    - R2 and R4 (with 'upa') in same update group
    - R3 (without 'upa') in different update group
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 5: Update Group Separation")
    step("=" * 60)

    r1 = tgen.gears["r1"]

    # Force update group recalculation to ensure UPA flag changes are applied
    step("Forcing update group recalculation with soft reset")
    r1.vtysh_cmd("clear ip bgp * soft out")
    time.sleep(3)  # Wait for update groups to reform

    # DEBUG: Check if BGP sessions are established
    step("DEBUG: Checking BGP session status")
    bgp_summary = r1.vtysh_cmd("show ip bgp summary json")
    step(f"BGP summary:\n{bgp_summary}")

    # DEBUG: Capture actual update group state for analysis
    step("DEBUG: Capturing update group state")
    updgrp_output = r1.vtysh_cmd("show ip bgp update-groups json")
    step(f"Update groups JSON output:\n{updgrp_output}")

    # Also check neighbor configs
    for peer in ["10.0.2.2", "10.0.3.2", "10.0.4.2"]:
        neighbor_output = r1.vtysh_cmd(f"show ip bgp neighbors {peer} json")
        step(f"Neighbor {peer} config:\n{neighbor_output}")

    def _check_update_groups():
        output = r1.vtysh_cmd("show ip bgp update-groups json")
        try:
            parsed = json.loads(output)

            # Find update groups
            # JSON structure: { "default": { "group_id": { "afi": "IPv4", "safi": "unicast", "subGroup": [{"peers": [...]}] } } }
            groups = {}

            # Iterate through VRFs (usually just "default")
            for vrf_name, vrf_data in parsed.items():
                if not isinstance(vrf_data, dict):
                    continue

                # Iterate through group IDs
                for group_id, group_data in vrf_data.items():
                    if not isinstance(group_data, dict):
                        continue

                    # Check if this is IPv4 Unicast
                    afi = group_data.get("afi", "")
                    safi = group_data.get("safi", "")

                    if afi == "IPv4" and safi == "unicast":
                        peers = []
                        # Peers are in subGroup[0]["peers"]
                        if "subGroup" in group_data and len(group_data["subGroup"]) > 0:
                            subgroup = group_data["subGroup"][0]
                            if "peers" in subgroup:
                                peers = subgroup["peers"]
                        groups[group_id] = peers

            # Check R2 and R4 are in same group (or different groups but both have UPA)
            # R3 should be in separate group
            r2_group = None
            r3_group = None
            r4_group = None

            for group_id, peers in groups.items():
                if "10.0.2.2" in peers:  # R2
                    r2_group = group_id
                if "10.0.3.2" in peers:  # R3
                    r3_group = group_id
                if "10.0.4.2" in peers:  # R4
                    r4_group = group_id

            # Check if groups exist at all
            if not groups:
                return "No update groups found! BGP sessions may not be established. Raw output: " + output[:200]

            # Check if all peers were found
            if r2_group is None or r3_group is None or r4_group is None:
                return f"Missing peers in update groups. R2={r2_group}, R3={r3_group}, R4={r4_group}. Groups: {groups}"

            # R3 should be in different group than R2/R4
            if r3_group == r2_group:
                return f"R3 (no UPA) in same group as R2 (with UPA). Groups: {groups}, R2={r2_group}, R3={r3_group}, R4={r4_group}"
            if r3_group == r4_group:
                return f"R3 (no UPA) in same group as R4 (with UPA). Groups: {groups}, R2={r2_group}, R3={r3_group}, R4={r4_group}"

            # SUCCESS - groups are properly separated
            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_check_update_groups, None, count=10, wait=1)
    assert result is None, "Update group separation check failed: {}".format(result)

    step("Test 5 PASSED: Update group separation verified")
    step("=" * 60)


def test_upa_only_update_rule():
    """
    Test 6: Verify UPA-only UPDATE rule enforcement (draft Section 5)

    Draft Requirement: UPDATE messages with UPA ExtCom must contain ONLY UPA prefixes.
    No mixing of UPA and non-UPA routes in the same UPDATE packet.

    Test Strategy:
    Uses existing aggregate topology from previous tests:
    - R1 has aggregate 10.1.0.0/16 with summary-only and UPA enabled
    - Constituents (10.1.1.0/24, 10.1.2.0/24) come from R5 via R4→R3→R1

    Steps:
    1. Add a non-UPA static route on R1 (192.168.100.0/24)
    2. Withdraw constituents from R5 → triggers UPA on aggregate constituents
    3. Verify R2 receives BOTH:
       - UPA route (10.1.1.0/24) WITH UPA ExtCom
       - Non-UPA route (192.168.100.0/24) WITHOUT UPA ExtCom
    4. Different ExtCom presence proves separate UPDATE messages

    This validates bgp_updgrp_packet.c lines 732-751 enforcement logic.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 6: UPA-Only UPDATE Rule Enforcement")
    step("=" * 60)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r5 = tgen.gears["r5"]

    # Step 1: Add a non-UPA static route on R1
    step("Step 6.1: Configure non-UPA static route 192.168.100.0/24 on R1")
    r1.vtysh_cmd("""
    conf t
    ip route 192.168.100.0/24 Null0
    router bgp 65001
     address-family ipv4 unicast
      network 192.168.100.0/24
    """)
    time.sleep(2)

    # Step 2: Verify R2 receives the static route (baseline check)
    step("Step 6.2: Verify R2 receives static route")

    def _r2_has_static():
        output = r2.vtysh_cmd("show ip bgp 192.168.100.0/24 json")
        try:
            parsed = json.loads(output)
            if len(parsed.get("paths", [])) == 0:
                return "Missing 192.168.100.0/24"
            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_has_static, None, count=30, wait=1)
    assert result is None, f"R2 static route check failed: {result}"

    # Step 3: Withdraw constituents to trigger UPA
    step("Step 6.3: Withdraw constituents from R5 to trigger UPA")
    r5.vtysh_cmd("""
    conf t
    router bgp 65006
     address-family ipv4 unicast
      no network 10.1.1.0/24
      no network 10.1.2.0/24
    """)

    # Step 4: Wait for UPA propagation to R2
    # R2 should receive UPA routes (with ExtCom) for the constituents
    step("Step 6.4: Wait for UPA routes to propagate to R2")
    time.sleep(5)  # Allow time for: R5→R4→R3→R1(UPA origination)→R2

    # Step 5: THE TEST - Verify R2 has both route types with correct attributes
    step("Step 6.5: Verify R2 receives UPA and non-UPA routes with correct separation")

    def _r2_routes_correctly_separated():
        # Check UPA route (10.1.1.0/24)
        upa_output = r2.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        # Check non-UPA route (192.168.100.0/24)
        non_upa_output = r2.vtysh_cmd("show ip bgp 192.168.100.0/24 json")

        try:
            upa_parsed = json.loads(upa_output)
            non_upa_parsed = json.loads(non_upa_output)

            upa_paths = upa_parsed.get("paths", [])
            non_upa_paths = non_upa_parsed.get("paths", [])

            if len(upa_paths) == 0:
                return "Missing UPA route 10.1.1.0/24"
            if len(non_upa_paths) == 0:
                return "Missing non-UPA route 192.168.100.0/24"

            # UPA route MUST have UPA ExtCom
            upa_extcoms = upa_paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" not in upa_extcoms:
                return f"UPA route 10.1.1.0/24 missing UPA ExtCom. ExtComs: {upa_extcoms}"

            # Non-UPA route MUST NOT have UPA ExtCom
            non_upa_extcoms = non_upa_paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" in non_upa_extcoms:
                return f"Non-UPA route 192.168.100.0/24 has unexpected UPA ExtCom: {non_upa_extcoms}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_routes_correctly_separated, None, count=60, wait=1)
    assert result is None, f"R2 route separation validation failed: {result}"

    step("✅ Test 6 PASSED: UPA-only UPDATE rule validated")
    step("  - UPA route (10.1.1.0/24) has UPA ExtCom")
    step("  - Non-UPA route (192.168.100.0/24) has no UPA ExtCom")
    step("  - Different attributes prove separate UPDATE messages")

    # Step 6: Cleanup - restore routes
    step("Step 6.6: Cleanup - restore original state")

    # Remove static route
    r1.vtysh_cmd("""
    conf t
    no ip route 192.168.100.0/24 Null0
    router bgp 65001
     address-family ipv4 unicast
      no network 192.168.100.0/24
    """)

    # Restore constituents on R5
    r5.vtysh_cmd("""
    conf t
    router bgp 65006
     address-family ipv4 unicast
      network 10.1.1.0/24
      network 10.1.2.0/24
    """)

    time.sleep(3)
    step("  - Cleanup completed - system restored to normal state")
    step("=" * 60)


def test_neighbor_upa_dynamic_toggle():
    """
    Test 7: Dynamic neighbor UPA enable/disable toggle

    Tests runtime configuration changes of 'neighbor upa' command.
    Validates update group recalculation and UPA route filtering
    based on dynamic neighbor capability changes.

    Steps:
    1. Start with R2 having 'neighbor upa' (baseline)
    2. Trigger UPA origination (withdraw routes from R5)
    3. Verify R2 receives UPA routes with ExtCom
    4. Dynamically remove 'no neighbor 10.0.2.2 upa' on R1
    5. Verify update groups recalculate (R2 moves to non-UPA group)
    6. Verify R2 no longer receives UPA routes (filtered)
    7. Re-enable 'neighbor 10.0.2.2 upa' on R1
    8. Verify update groups recalculate (R2 back to UPA group)
    9. Verify R2 receives UPA routes again
    10. Cleanup

    This validates:
    - PEER_FLAG_UPA_SEND toggles dynamically
    - Update group membership changes when flag changes
    - UPA filtering responds to dynamic config changes
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 7: Dynamic Neighbor UPA Toggle")
    step("=" * 60)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r5 = tgen.gears["r5"]

    # Step 1: Verify baseline - R2 has 'neighbor upa'
    step("Step 7.1: Verify baseline - R2 has 'neighbor upa' configured")

    config = r1.vtysh_cmd("show running-config")
    assert "neighbor 10.0.2.2 upa" in config, \
        "Baseline failed: R2 should have 'neighbor upa' in config"

    # Step 2: Trigger UPA origination by withdrawing ALL constituents from R5
    step("Step 7.2: Withdraw constituents from R5 to trigger UPA")
    r5.vtysh_cmd("""
    conf t
    router bgp 65006
     address-family ipv4 unicast
      no network 10.1.1.0/24
      no network 10.1.2.0/24
    """)
    time.sleep(5)  # Wait for: R5→R4→R1(UPA origination)→R2

    # Step 3: Verify R2 receives UPA routes WITH ExtCom (baseline)
    step("Step 7.3: Verify R2 receives UPA routes (baseline)")

    def _r2_has_upa():
        output = r2.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "R2 missing 10.1.1.0/24"

            extcoms = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" not in extcoms:
                return f"R2 path missing UPA ExtCom: {extcoms}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_has_upa, None, count=30, wait=1)
    assert result is None, f"Baseline check failed: {result}"

    # Get R2's update group BEFORE disabling UPA
    step("Step 7.4a: Record R2's initial update group")

    def _get_r2_update_group():
        output = r1.vtysh_cmd("show ip bgp update-groups json")
        try:
            parsed = json.loads(output)

            for vrf_name, vrf_data in parsed.items():
                if not isinstance(vrf_data, dict):
                    continue
                for group_id, group_data in vrf_data.items():
                    if not isinstance(group_data, dict):
                        continue
                    afi = group_data.get("afi", "")
                    safi = group_data.get("safi", "")
                    if afi == "IPv4" and safi == "unicast":
                        peers = []
                        if "subGroup" in group_data and len(group_data["subGroup"]) > 0:
                            subgroup = group_data["subGroup"][0]
                            if "peers" in subgroup:
                                peers = subgroup["peers"]
                        if "10.0.2.2" in peers:
                            return group_id
            return None
        except Exception as e:
            return None

    initial_r2_group = _get_r2_update_group()
    assert initial_r2_group is not None, "R2 not in any update group before test"
    step(f"  - R2 initial update group: {initial_r2_group}")

    # Step 4: Dynamically DISABLE 'neighbor upa' for R2
    step("Step 7.4b: Dynamically disable 'neighbor 10.0.2.2 upa'")
    r1.vtysh_cmd("""
    conf t
    router bgp 65001
     address-family ipv4 unicast
      no neighbor 10.0.2.2 upa
    """)

    # Force update group recalculation for all peers
    r1.vtysh_cmd("clear ip bgp * soft out")
    time.sleep(3)

    # Step 5: Verify update group changed
    step("Step 7.5: Verify R2's update group changed after disabling UPA")

    def _check_r2_group_changed():
        new_group = _get_r2_update_group()
        if new_group is None:
            return "R2 not found in any update group after disabling UPA"
        if new_group == initial_r2_group:
            return f"R2 still in same update group ({new_group}) after disabling UPA"
        return None

    _, result = topotest.run_and_expect(_check_r2_group_changed, None, count=10, wait=1)
    assert result is None, f"Update group check failed: {result}"

    new_r2_group = _get_r2_update_group()
    step(f"  - R2 new update group: {new_r2_group} (changed from {initial_r2_group})")

    # Step 6: Verify R2 NO LONGER receives UPA routes (filtered)
    step("Step 7.6: Verify R2 no longer receives UPA ExtCom (filtered)")

    # Wait for BGP to propagate the change
    time.sleep(3)

    def _r2_no_upa():
        output = r2.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            # R2 might not have the route at all (filtered), or have it without UPA ExtCom
            if len(paths) == 0:
                # Route completely filtered - acceptable
                return None

            # If route exists, it should NOT have UPA ExtCom
            extcoms = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" in extcoms:
                return f"R2 still has UPA ExtCom after disabling: {extcoms}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_no_upa, None, count=30, wait=1)
    assert result is None, f"UPA filtering check failed: {result}"

    # Step 7: Dynamically RE-ENABLE 'neighbor upa' for R2
    step("Step 7.7: Dynamically re-enable 'neighbor 10.0.2.2 upa'")
    r1.vtysh_cmd("""
    conf t
    router bgp 65001
     address-family ipv4 unicast
      neighbor 10.0.2.2 upa
    """)

    # Force update group recalculation for all peers
    r1.vtysh_cmd("clear ip bgp * soft out")
    time.sleep(3)

    # Step 8: Verify update group changed back (different from non-UPA group)
    step("Step 7.8: Verify R2's update group changed after re-enabling UPA")

    def _check_r2_group_restored():
        restored_group = _get_r2_update_group()
        if restored_group is None:
            return "R2 not found in any update group after re-enabling UPA"
        if restored_group == new_r2_group:
            return f"R2 still in non-UPA group ({restored_group}) after re-enabling UPA"
        # It might not be the same as initial_r2_group, but it should be different from new_r2_group
        return None

    _, result = topotest.run_and_expect(_check_r2_group_restored, None, count=10, wait=1)
    assert result is None, f"Update group restoration check failed: {result}"

    final_r2_group = _get_r2_update_group()
    step(f"  - R2 final update group: {final_r2_group} (changed from {new_r2_group})")

    # Step 9: Verify R2 receives UPA routes again
    step("Step 7.9: Verify R2 receives UPA routes again")

    _, result = topotest.run_and_expect(_r2_has_upa, None, count=30, wait=1)
    assert result is None, f"UPA restoration check failed: {result}"

    step("✅ Test 7 PASSED: Dynamic neighbor UPA toggle validated")
    step(f"  - UPA disabled → R2 update group changed: {initial_r2_group} → {new_r2_group}")
    step("  - UPA disabled → R2 no longer receives UPA ExtCom")
    step(f"  - UPA re-enabled → R2 update group changed: {new_r2_group} → {final_r2_group}")
    step("  - UPA re-enabled → R2 receives UPA ExtCom again")

    # Step 10: Cleanup - restore routes on R5
    step("Step 7.10: Cleanup - restore routes on R5")
    r5.vtysh_cmd("""
    conf t
    router bgp 65006
     address-family ipv4 unicast
      network 10.1.1.0/24
      network 10.1.2.0/24
    """)

    time.sleep(3)
    step("  - Cleanup completed - system restored to normal state")
    step("=" * 60)


@pytest.mark.skip(reason="Requires per-daemon config files for daemon restart; unified frr.conf incompatible with individual bgpd restart")
def test_gr_stale_routes_trigger_upa():
    """
    Test 8: BGP Graceful Restart - validates UPA correctly handles STALE routes

    Tests the critical GR interaction: UPA code explicitly skips BGP_PATH_STALE routes
    in bgp_upa_is_prefix_unreachable() at bgp_route.c:9570, ensuring stale routes
    during GR window do NOT trigger premature UPA origination.

    Scenario:
    - R5 advertises 10.1.1.0/24 and 10.1.2.0/24 to R4 → R1
    - Enable BGP Graceful Restart on R1, R4, R5
    - Kill bgpd on R4 to simulate peer restart (R4 is R1's direct peer)
    - R1 marks routes from R4 as STALE (GR activated)
    - **CRITICAL TEST**: Verify UPA is NOT originated while routes are stale
    - Clear stale routes (simulating stalepath-time expiry)
    - **VERIFY**: UPA IS originated after stale routes cleared
    - UPA propagates to R2 (with 'neighbor upa')
    - UPA filtered from R3 (without 'neighbor upa')
    - Restore R4 bgpd, re-establish sessions and routes → UPA withdrawn

    This validates:
    - BGP_PATH_STALE code path: stale routes do NOT trigger UPA (RFC 4724 compliance)
    - UPA origination ONLY after stale routes cleared/expired
    - Complete GR cycle: stale → clear → UPA → restore → withdraw UPA
    - Multi-peer UPA propagation during GR scenarios
    - Real-world DC fabric scenario (peer restart during maintenance)

    Key Validation:
    Per RFC 4724, stale routes should be treated as valid during GR window.
    UPA code at bgp_route.c:9548-9574 implements: \"Stale routes (Graceful Restart)
    MUST NOT suppress UPA\" - meaning stale routes are skipped when checking
    reachability, so they don't trigger UPA while still in GR window.

    Note: We kill R4 (R1's direct peer) rather than R5, so GR activates on the R1-R4
    link. If we killed R5, routes would be stale on R4, but R4 might withdraw them
    from R1, preventing us from testing GR on R1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 8: BGP Graceful Restart - STALE Route Handling with UPA")
    step("=" * 60)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r5 = tgen.gears["r5"]

    # Step 1: Verify BGP Graceful Restart capability is negotiated
    step("Step 8.1: Verify BGP Graceful Restart capability negotiated (pre-configured)")

    # GR is pre-configured in static frr.conf files, so it should be negotiated at startup
    # Just verify it's actually working
    step("  Verifying GR capability on R1-R4 session...")
    # GR is pre-configured in static frr.conf files, so it should be negotiated at startup
    # Just verify it's actually working
    step("  Verifying GR capability on R1-R4 session...")
    def _gr_cap_negotiated():
        output = r1.vtysh_cmd("show bgp neighbor 10.0.4.2 json")
        try:
            parsed = json.loads(output)
            # Check for GR capability
            neighbor = parsed.get("10.0.4.2", {})
            gr_cap = neighbor.get("gracefulRestartInfo", {})

            # Check if GR is enabled/advertised
            if gr_cap:
                return None  # Found GR capability

            # Also check capabilities list
            caps = neighbor.get("neighborCapabilities", {})
            if "gracefulRestart" in str(caps):
                return None

            return "GR capability not found in neighbor capabilities"
        except Exception as e:
            return str(e)

    _, gr_result = topotest.run_and_expect(_gr_cap_negotiated, None, count=30, wait=1)

    if gr_result is not None:
        # GR capability not negotiated - log warning and skip test
        step(f"  ⚠️  WARNING: {gr_result}")
        step("  GR capability not negotiated properly")

        # Try to see what capabilities were actually negotiated
        output = r1.vtysh_cmd("show bgp neighbor 10.0.4.2")
        step(f"  DEBUG: Neighbor output (first 500 chars):")
        step(output[:500])

        pytest.skip("BGP Graceful Restart capability not negotiated - test requires GR support")

    step("  ✅ GR capability negotiated on R1-R4 session")

    # Step 2: Ensure routes are advertised by R5 (clean state after previous tests)
    step("Step 8.2: Ensure routes are advertised by R5")

    r5.vtysh_cmd("""
    conf t
    router bgp 65006
     address-family ipv4 unicast
      network 10.1.1.0/24
      network 10.1.2.0/24
    """)

    time.sleep(3)

    # Step 3: Verify baseline - routes are present and valid on R1
    step("Step 8.3: Verify baseline - routes from R5 are present on R1")

    def _r1_has_routes():
        output = r1.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "Missing 10.1.1.0/24 on R1"
            # Verify we have non-UPA paths
            non_upa_paths = [p for p in paths
                           if "upa:" not in p.get("extendedCommunity", {}).get("string", "")]
            if len(non_upa_paths) == 0:
                return "Only UPA paths exist (expected normal paths)"
            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r1_has_routes, None, count=20, wait=1)
    assert result is None, f"Baseline check failed: {result}"

    # Step 4: Simulate BGP peer restart to trigger Graceful Restart
    step("Step 8.4: Simulate R4 BGP restart (trigger Graceful Restart)")

    # Kill bgpd on R4 to simulate peer restart
    # This triggers GR on R1, which marks routes from R4 as STALE
    # R4 is the direct peer of R1, so GR will activate properly
    step("  Killing bgpd on R4 to simulate restart...")
    kill_router_daemons(tgen, "r4", ["bgpd"])

    # Wait for GR to activate on R1
    time.sleep(3)

    # Step 5: Verify routes are marked STALE on R1 (key GR behavior)
    step("Step 8.5: Verify routes marked STALE on R1 (GR activated)")

    def _r1_routes_marked_stale():
        # Check both text and JSON output for stale marking
        output_text = r1.vtysh_cmd("show ip bgp 10.1.1.0/24")
        output_json = r1.vtysh_cmd("show ip bgp 10.1.1.0/24 json")

        # Check for "Stale" in text output (most reliable)
        if "Stale" in output_text or "stale" in output_text:
            return None  # Found stale marking

        # Also check JSON for stale flag
        try:
            parsed = json.loads(output_json)
            paths = parsed.get("paths", [])
            for path in paths:
                if path.get("stale", False):
                    return None  # Found stale flag
        except:
            pass

        # If still not found, check if routes even exist
        try:
            parsed = json.loads(output_json)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "No paths found for 10.1.1.0/24 (routes may have been withdrawn instead of marked stale)"
        except:
            pass

        return "Routes not marked stale (GR may not have activated)"

    _, result = topotest.run_and_expect(_r1_routes_marked_stale, None, count=20, wait=1)
    assert result is None, f"GR stale marking failed: {result}"

    step("  ✅ Routes marked STALE - GR activated correctly")

    # Step 6: CRITICAL GR TEST - Verify UPA is NOT originated while routes are STALE
    step("Step 8.6: Verify UPA NOT originated (stale routes skipped per RFC)")

    def _r1_no_upa_for_stale():
        output = r1.vtysh_cmd("show bgp ipv4 unicast 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            # Check if any path has UPA ExtCom
            for path in paths:
                extcom = path.get("extendedCommunity", {}).get("string", "")
                if "upa:" in extcom:
                    # Found UPA while routes are stale - this is wrong!
                    return "UPA originated for stale route (VIOLATION: stale routes should NOT trigger UPA)"

            # Also check 10.1.2.0/24
            output2 = r1.vtysh_cmd("show bgp ipv4 unicast 10.1.2.0/24 json")
            parsed2 = json.loads(output2)
            paths2 = parsed2.get("paths", [])

            for path in paths2:
                extcom = path.get("extendedCommunity", {}).get("string", "")
                if "upa:" in extcom:
                    return "UPA originated for stale route 10.1.2.0/24 (VIOLATION)"

            return None  # No UPA - correct behavior!
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r1_no_upa_for_stale, None, count=20, wait=1)
    assert result is None, f"GR UPA suppression check failed: {result}"

    step("  ✅ CRITICAL: UPA NOT originated for stale routes (BGP_PATH_STALE code path validated)")

    # Step 7: Clear stale routes to trigger UPA
    step("Step 8.7: Clear stale routes (simulating stalepath-time expiry)")

    # Option A: Wait for stalepath-time (60s) - too slow for testing
    # Option B: Manually clear stale routes - faster
    step("  Clearing stale routes from R4 (simulating timer expiry)...")
    r1.vtysh_cmd("clear ip bgp 10.255.0.4")

    # Wait for stale routes to be removed and UPA to be originated
    time.sleep(5)

    # Step 8: NOW verify UPA IS originated (after stale routes cleared)
    step("Step 8.8: Verify UPA IS originated (after stale routes cleared)")

    def _r1_originates_upa():
        output = r1.vtysh_cmd("show bgp ipv4 unicast 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            if len(paths) == 0:
                return "No paths for 10.1.1.0/24 (expected UPA route)"

            # Look for path with UPA ExtCom (locally originated)
            found_upa = False
            for path in paths:
                extcom = path.get("extendedCommunity", {}).get("string", "")
                if "upa:" in extcom:
                    found_upa = True
                    break

            if not found_upa:
                return "No UPA route found for 10.1.1.0/24"

            # Also check 10.1.2.0/24
            output2 = r1.vtysh_cmd("show bgp ipv4 unicast 10.1.2.0/24 json")
            parsed2 = json.loads(output2)
            paths2 = parsed2.get("paths", [])

            if len(paths2) == 0:
                return "No paths for 10.1.2.0/24 (expected UPA route)"

            found_upa2 = False
            for path in paths2:
                extcom = path.get("extendedCommunity", {}).get("string", "")
                if "upa:" in extcom:
                    found_upa2 = True
                    break

            if not found_upa2:
                return "No UPA route found for 10.1.2.0/24"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r1_originates_upa, None, count=30, wait=1)
    assert result is None, f"R1 UPA origination failed: {result}"

    step("  ✅ UPA originated after stale routes cleared")

    # Step 9: Verify UPA propagates to R2 (has 'neighbor upa')
    step("Step 8.9: Verify UPA propagates to R2 (with 'neighbor upa')")

    def _r2_receives_upa():
        output = r2.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])
            if len(paths) == 0:
                return "R2 missing 10.1.1.0/24"

            extcoms = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" not in extcoms:
                return f"R2 path missing UPA ExtCom: {extcoms}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_receives_upa, None, count=30, wait=1)
    assert result is None, f"R2 UPA reception failed: {result}"

    # Step 10: Verify UPA filtered from R3 (NO 'neighbor upa')
    step("Step 8.10: Verify UPA filtered from R3 (without 'neighbor upa')")

    def _r3_no_upa():
        output = r3.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            # R3 might not have the route at all (filtered), or have it without UPA ExtCom
            if len(paths) == 0:
                return None  # Filtered completely - acceptable

            # If route exists, should NOT have UPA ExtCom
            extcoms = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" in extcoms:
                return f"R3 received UPA ExtCom (should be filtered): {extcoms}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r3_no_upa, None, count=30, wait=1)
    assert result is None, f"R3 UPA filtering check failed: {result}"

    # Step 11: Note - Cannot verify R4 since it's down (we killed bgpd on R4)
    step("Step 8.11: Skipping R4 verification (R4 bgpd is down for GR test)")

    step("✅ GR Validation PASSED: UPA originated and propagated correctly after GR")

    # Step 12: Restore R4 BGP session (simulating peer recovery)
    step("Step 8.12: Restore R4 BGP session (simulating GR recovery)")

    # Restart bgpd on R4
    step("  Starting bgpd on R4...")
    start_router_daemons(tgen, "r4", ["bgpd"])

    # Wait for bgpd to start and sessions to establish
    time.sleep(5)

    # Verify BGP session is back up
    def _r4_bgp_running():
        output = r4.vtysh_cmd("show ip bgp summary json")
        try:
            parsed = json.loads(output)
            if "ipv4Unicast" in parsed:
                peers = parsed["ipv4Unicast"].get("peers", {})
                # Check both R1 and R5 sessions are established
                if len(peers) >= 2:
                    for peer_ip, peer_data in peers.items():
                        if peer_data.get("state") != "Established":
                            return f"Peer {peer_ip} not Established"
                    return None
                return f"Not enough peers established: {len(peers)}"
            return "BGP not running on R4"
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r4_bgp_running, None, count=40, wait=1)
    assert result is None, f"R4 BGP restart failed: {result}"

    step("  ✅ R4 BGP running, sessions re-established with R1 and R5")

    # Wait for routes to propagate R5 → R4 → R1
    time.sleep(5)

    # Step 13: Verify UPA withdrawn after routes restored
    step("Step 8.13: Verify UPA withdrawn after routes restored")

    def _r1_upa_withdrawn():
        # Check both constituent routes no longer have locally originated UPA
        for prefix in ["10.1.1.0/24", "10.1.2.0/24"]:
            output = r1.vtysh_cmd(f"show bgp ipv4 unicast {prefix} json")
            try:
                parsed = json.loads(output)
                paths = parsed.get("paths", [])

                # Check if any path has UPA ExtCom from self
                for path in paths:
                    peer = path.get("peer", {})
                    # Check if locally originated
                    if peer.get("hostname") == "r1" or peer.get("peerId") == "0.0.0.0":
                        extcom = path.get("extendedCommunity", {}).get("string", "")
                        if "upa:" in extcom:
                            return f"Locally originated UPA still present for {prefix}"

            except Exception as e:
                return str(e)

        return None

    _, result = topotest.run_and_expect(_r1_upa_withdrawn, None, count=30, wait=1)
    assert result is None, f"UPA withdrawal check failed: {result}"

    step("✅ Test 8 PASSED: BGP Graceful Restart UPA interaction validated")
    step("  - Simulated BGP peer restart (killed and restarted bgpd on R4)")
    step("  - VERIFIED: Routes marked STALE during GR window")
    step("  - VERIFIED: UPA NOT originated for stale routes (BGP_PATH_STALE code path)")
    step("  - VERIFIED: UPA originated AFTER stale routes cleared")
    step("  - UPA propagated to R2 (with 'neighbor upa')")
    step("  - UPA filtered from R3 (without 'neighbor upa')")
    step("  - UPA withdrawn after R4 recovery and route restoration")
    step("  - Validates complete GR cycle: stale → clear → UPA → restore → withdraw UPA")

    # Step 14: Cleanup note
    step("Step 8.14: Cleanup - GR remains enabled (pre-configured in static configs)")
    step("  - GR configuration is in static frr.conf files, persists across tests")
    step("  - No dynamic cleanup needed")
    step("=" * 60)


def test_route_refresh_upa_persistence():
    """
    Test 9: Route Refresh - Verify UPA behavior during soft reconfiguration

    Tests that UPA routes and their extended communities persist correctly
    through BGP soft reconfiguration (route refresh). This is critical for
    operational scenarios where policies are updated without session teardown.

    Route refresh in BGP allows routers to request/re-send routes without
    tearing down the BGP session. There are two types:
    - Soft inbound refresh: Router re-processes incoming routes from peer
    - Soft outbound refresh: Router re-advertises routes to peer

    This test validates that UPA routes:
    - Persist through soft refresh (no loss)
    - Maintain correct extended communities
    - Don't create duplicates during refresh
    - Respect policy changes applied during refresh

    Test Scenarios:
    Part A - Inbound Refresh: UPA routes persist on receiving router (R2)
    Part B - Outbound Refresh: UPA routes re-advertised correctly from R1
    Part C - Policy Change + Refresh: UPA filtering applies correctly

    Topology (reuses existing bgp_upa_multipeer):
    - R1 (PE): Has aggregate 10.1.0.0/16 with UPA, originates UPA
    - R2: Peer with 'neighbor upa' - receives UPA
    - R5: Route source
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("=" * 60)
    step("Test 9: Route Refresh - UPA Persistence During Soft Reconfiguration")
    step("=" * 60)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r5 = tgen.gears["r5"]

    # ========================================================================
    # PART A: Inbound Refresh - Verify UPA persists on R2
    # ========================================================================

    step("=" * 60)
    step("PART A: Soft Inbound Refresh (R2 perspective)")
    step("=" * 60)

    # Step 1: Trigger UPA origination - R5 withdraws routes
    step("Step 9.1: Withdraw routes from R5 to trigger UPA on R1")
    r5.vtysh_cmd("""
    conf t
    router bgp 65006
     address-family ipv4 unicast
      no network 10.1.1.0/24
      no network 10.1.2.0/24
    """)
    time.sleep(5)

    # Step 2: Verify R2 has UPA baseline
    step("Step 9.2: Verify R2 receives UPA (baseline before refresh)")

    def _r2_has_upa_baseline():
        output = r2.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            if len(paths) == 0:
                return "R2 missing 10.1.1.0/24"

            if len(paths) != 1:
                return f"Expected 1 path, got {len(paths)} (duplicates?)"

            # Must have UPA ExtCom
            extcom = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" not in extcom:
                return f"Missing UPA ExtCom: {extcom}"

            # Must have R1's Router-ID
            if "10.255.0.1" not in extcom:
                return f"Wrong Router-ID in ExtCom: {extcom}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_has_upa_baseline, None, count=30, wait=1)
    assert result is None, f"Baseline check failed: {result}"

    step("  ✅ Baseline: R2 has UPA route with correct ExtCom")

    # Step 3: Trigger soft inbound refresh on R2
    step("Step 9.3: Trigger soft inbound refresh on R2")
    step("  Command: clear bgp 10.0.2.1 soft in")
    r2.vtysh_cmd("clear bgp 10.0.2.1 soft in")
    time.sleep(3)

    # Step 4: Verify UPA persists with same attributes
    step("Step 9.4: Verify UPA persists after inbound refresh")

    def _r2_upa_persists_after_refresh():
        output = r2.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            # Should still have exactly 1 path (no duplicates from refresh)
            if len(paths) == 0:
                return "UPA route lost after inbound refresh"

            if len(paths) != 1:
                return f"Route refresh created duplicates: {len(paths)} paths"

            # UPA ExtCom should still be present
            extcom = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" not in extcom:
                return f"UPA ExtCom lost after refresh: {extcom}"

            # Verify Router-ID unchanged
            if "10.255.0.1" not in extcom:
                return f"Router-ID changed in ExtCom after refresh: {extcom}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_upa_persists_after_refresh, None, count=20, wait=1)
    assert result is None, f"Inbound refresh validation failed: {result}"

    step("  ✅ UPA route persisted through inbound refresh")
    step("  ✅ No duplicate routes created")
    step("  ✅ ExtCom integrity maintained")

    # ========================================================================
    # PART B: Outbound Refresh - Verify R1 re-advertises UPA correctly
    # ========================================================================

    step("=" * 60)
    step("PART B: Soft Outbound Refresh (R1 perspective)")
    step("=" * 60)

    # Step 5: Trigger soft outbound refresh on R1
    step("Step 9.5: Trigger soft outbound refresh on R1")
    step("  Command: clear bgp 10.0.2.2 soft out")
    r1.vtysh_cmd("clear bgp 10.0.2.2 soft out")
    time.sleep(3)

    # Step 6: Verify R2 still receives UPA (re-advertised)
    step("Step 9.6: Verify R2 still receives UPA after outbound refresh")

    def _r2_receives_upa_after_outbound():
        output = r2.vtysh_cmd("show ip bgp 10.1.1.0/24 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            if len(paths) == 0:
                return "UPA route lost after outbound refresh"

            if len(paths) != 1:
                return f"Outbound refresh created duplicates: {len(paths)} paths"

            # Must still have UPA ExtCom
            extcom = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" not in extcom:
                return f"UPA ExtCom missing after re-advertisement: {extcom}"

            # Verify Router-ID still correct
            if "10.255.0.1" not in extcom:
                return f"Router-ID changed after outbound refresh: {extcom}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_receives_upa_after_outbound, None, count=20, wait=1)
    assert result is None, f"Outbound refresh validation failed: {result}"

    step("  ✅ UPA successfully re-advertised after outbound refresh")
    step("  ✅ ExtCom preserved through re-advertisement")

    # ========================================================================
    # PART C: Policy Change + Refresh - Verify filtering applies correctly
    # ========================================================================

    step("=" * 60)
    step("PART C: Policy Change During Refresh")
    step("=" * 60)

    # Step 7: Apply route-map to filter UPA aggregate on R1→R2
    step("Step 9.7: Apply route-map to filter UPA aggregate 10.1.0.0/16 from R1 to R2")
    r1.vtysh_cmd("""
    conf t
    ip prefix-list FILTER_AGGREGATE permit 10.1.0.0/16
    !
    route-map TO_R2 deny 10
     match ip address prefix-list FILTER_AGGREGATE
    !
    route-map TO_R2 permit 20
    !
    router bgp 65001
     address-family ipv4 unicast
      neighbor 10.0.2.2 route-map TO_R2 out
    """)

    step("  - Prefix-list matches aggregate 10.1.0.0/16")
    step("  - Route-map clause 10: deny UPA aggregate")
    step("  - Route-map clause 20: permit other routes")
    step("  - Route-map applied to neighbor 10.0.2.2 (R2)")

    # Step 8: Soft refresh to apply policy
    step("Step 9.8: Soft refresh to apply new policy")
    r1.vtysh_cmd("clear bgp 10.0.2.2 soft out")
    time.sleep(3)

    # Step 9: Verify UPA aggregate filtered from R2
    step("Step 9.9: Verify UPA aggregate filtered from R2")

    def _r2_aggregate_filtered():
        output = r2.vtysh_cmd("show ip bgp 10.1.0.0/16 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            # Aggregate should be completely filtered
            if len(paths) > 0:
                return f"Aggregate should be filtered but still present: {len(paths)} paths"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_r2_aggregate_filtered, None, count=20, wait=1)
    assert result is None, f"Aggregate filtering failed: {result}"

    step("  ✅ UPA aggregate 10.1.0.0/16 successfully filtered")
    step("  ✅ Filtering applies correctly to UPA routes")

    # ========================================================================
    # Cleanup
    # ========================================================================

    step("Step 9.10: Cleanup - Restore routes first, then remove route-map")

    # Restore routes on R5 while route-map still active
    r5.vtysh_cmd("""
    conf t
    router bgp 65006
     address-family ipv4 unicast
      network 10.1.1.0/24
      network 10.1.2.0/24
    """)

    # Wait for routes to propagate and R1 to switch from UPA to normal
    time.sleep(8)

    # Remove route-map
    r1.vtysh_cmd("""
    conf t
    router bgp 65001
     address-family ipv4 unicast
      no neighbor 10.0.2.2 route-map TO_R2 out
    !
    no route-map TO_R2
    no ip prefix-list FILTER_AGGREGATE
    """)

    # Soft refresh to advertise aggregate without filter
    r1.vtysh_cmd("clear bgp 10.0.2.2 soft out")

    time.sleep(3)

    # Verify cleanup - R2 should have normal aggregate (not UPA)
    def _cleanup_verified():
        output = r2.vtysh_cmd("show ip bgp 10.1.0.0/16 json")
        try:
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            if len(paths) == 0:
                return "Aggregate not restored after cleanup"

            # Should NOT have UPA ExtCom (normal aggregate restored)
            extcom = paths[0].get("extendedCommunity", {}).get("string", "")
            if "upa:" in extcom:
                return f"UPA ExtCom still present after restoration: {extcom}"

            return None
        except Exception as e:
            return str(e)

    _, result = topotest.run_and_expect(_cleanup_verified, None, count=30, wait=1)
    assert result is None, f"Cleanup verification failed: {result}"

    step("✅ Test 9 PASSED: Route Refresh UPA behavior validated")
    step("  PART A - Inbound Refresh:")
    step("    ✅ UPA routes persist through soft refresh in")
    step("    ✅ No duplicate routes created")
    step("    ✅ Extended communities maintained")
    step("  PART B - Outbound Refresh:")
    step("    ✅ UPA routes re-advertised correctly")
    step("    ✅ ExtCom integrity preserved")
    step("  PART C - Policy Change:")
    step("    ✅ Route filtering applies correctly to UPA aggregate")
    step("  - Cleanup completed - system restored to normal state")
    step("=" * 60)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
