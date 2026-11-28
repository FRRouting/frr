#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Verify default-originate attribute visibility, precedence, and duplicate
suppression behavior.

The topology is a simple two-router setup with both IPv4 and IPv6 EBGP sessions:

    r1 (AS 65001) --- EBGP (IPv4 + IPv6) --- r2 (AS 65002)

r1 sends 0.0.0.0/0 via the IPv4 session and ::/0 via the IPv6 session, both
using default-originate with route-map SET_COMMUNITY (sets community 65001:100).

Note: "no bgp default ipv4-unicast" is configured to ensure each neighbor only
receives routes for its activated address family.

Tests:
  1. r2 receives 0.0.0.0/0/::/0 with AS-path "65001" and community "65001:100".
  2. r1 advertised-routes shows 0.0.0.0/0/::/0 with the correct attributes,
     including community in JSON.  IPv6 text-mode output is also verified
     to guard against a NULL-dest crash in route_vty_out_route().
  3. Switching to 'network 0.0.0.0/0' - r2 still receives 0.0.0.0/0.
  4. When both default-originate and 'network 0.0.0.0/0' are active,
     default-originate takes precedence and its attributes are visible.
  5. No duplicate UPDATE for 0.0.0.0/0 is sent on re-evaluation when
     attributes are unchanged — tested for both a set-only route-map and
     a conditional route-map (one with match clauses).
  6. When default-originate condition is not met (route-map doesn't match),
     the default route is withdrawn and advertised-routes shows nothing
     for 0.0.0.0/0 even if a table entry exists.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

# Neighbor addresses
R1_IPV4 = "192.168.12.1"
R2_IPV4 = "192.168.12.2"
R1_IPV6 = "fd00::1"
R2_IPV6 = "fd00::2"

# Expected attributes for the default route
COMMUNITY = "65001:100"
ASPATH = "65001"
METRIC = 1000


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


def test_bgp_default_originate_attr():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # -------------------------------------------------------------------------
    # Helper: check BGP session established
    # -------------------------------------------------------------------------
    def _bgp_neighbor_established(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
        )
        expected = {neighbor: {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    # -------------------------------------------------------------------------
    # Helper: check receiver has 0.0.0.0/0 with correct path and community
    # -------------------------------------------------------------------------
    def _r2_has_ipv4_default(router):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json")
        )
        expected = {
            "paths": [
                {
                    "aspath": {"string": ASPATH},
                    "community": {"string": COMMUNITY},
                    "metric": METRIC,
                    "nexthops": [{"ip": R1_IPV4}],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _r2_has_ipv6_default(router):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv6 unicast ::/0 json")
        )
        expected = {
            "paths": [
                {
                    "aspath": {"string": ASPATH},
                    "community": {"string": COMMUNITY},
                    "metric": METRIC,
                    # Check the global nexthop; link-local is interface-specific.
                    "nexthops": [{"ip": R1_IPV6, "scope": "global"}],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    # -------------------------------------------------------------------------
    # Helper: check sender's advertised-routes shows 0.0.0.0/0
    # -------------------------------------------------------------------------
    def _r1_adv_routes_ipv4_default(router):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbor {} advertised-routes json".format(
                    R2_IPV4
                )
            )
        )
        # Check path, community, and metric first.
        result = topotest.json_cmp(
            output,
            {
                "advertisedRoutes": {
                    "0.0.0.0/0": {
                        "path": ASPATH,
                        "community": {"string": COMMUNITY},
                        "metric": METRIC,
                    }
                }
            },
        )
        if result:
            return result
        # Check nexthop: currently shows 0.0.0.0 for default-originate.
        # TODO: update to check for real nexthop once that patch is added.
        route = output.get("advertisedRoutes", {}).get("0.0.0.0/0", {})
        nexthop = route.get("nextHop") or route.get("nextHopGlobal", "")
        if nexthop != "0.0.0.0":
            return "0.0.0.0/0 nexthop: expected 0.0.0.0, got {}".format(nexthop)
        return None

    def _r1_adv_routes_ipv6_default(router):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv6 unicast neighbor {} advertised-routes json".format(
                    R2_IPV6
                )
            )
        )
        # Note: nexthop currently shows "::" for default-originate.
        # TODO: update to check for real nexthop once that patch is added.
        expected = {
            "advertisedRoutes": {
                "::/0": {
                    "nextHopGlobal": "::",
                    "path": ASPATH,
                    "community": {"string": COMMUNITY},
                    "metric": METRIC,
                }
            }
        }
        return topotest.json_cmp(output, expected)

    # -------------------------------------------------------------------------
    # Helper: check advertised-routes text output for ::/0 (non-JSON).
    # This exercises the text-mode code path in route_vty_out_tmp() that was
    # crashing for IPv6 when dest is NULL.
    # -------------------------------------------------------------------------
    def _r1_adv_routes_ipv6_default_text(router):
        output = router.vtysh_cmd(
            "show bgp ipv6 unicast neighbor {} advertised-routes".format(R2_IPV6)
        )
        if "::/0" not in output:
            return "advertised-routes text output missing ::/0"
        return None

    # -------------------------------------------------------------------------
    # Helper: check advertised-routes with prefix specified (0.0.0.0/0)
    # -------------------------------------------------------------------------
    def _r1_adv_routes_ipv4_default_prefix(router):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbor {} advertised-routes 0.0.0.0/0 json".format(
                    R2_IPV4
                )
            )
        )
        result = topotest.json_cmp(
            output,
            {
                "advertisedRoutes": {
                    "0.0.0.0/0": {
                        "path": ASPATH,
                        "community": {"string": COMMUNITY},
                        "metric": METRIC,
                    }
                }
            },
        )
        return result

    # -------------------------------------------------------------------------
    # Run the checks
    # -------------------------------------------------------------------------

    step("Wait for BGP sessions to establish")
    test_func = functools.partial(_bgp_neighbor_established, r1, R2_IPV4)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP IPv4 session r1->r2 not established"

    test_func = functools.partial(_bgp_neighbor_established, r1, R2_IPV6)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP IPv6 session r1->r2 not established"

    step("r2: verify 0.0.0.0/0 received with correct AS-path and community")
    test_func = functools.partial(_r2_has_ipv4_default, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r2 did not receive 0.0.0.0/0 with path='{}' community='{}'".format(
            ASPATH, COMMUNITY
        )
    )

    step("r2: verify ::/0 received with correct AS-path and community")
    test_func = functools.partial(_r2_has_ipv6_default, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r2 did not receive ::/0 with path='{}' community='{}'".format(ASPATH, COMMUNITY)
    )

    step("r1: verify advertised-routes (IPv4) shows 0.0.0.0/0 with correct attributes")
    test_func = functools.partial(_r1_adv_routes_ipv4_default, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r1 advertised-routes does not show 0.0.0.0/0 with expected attributes"
    )

    step("r1: verify advertised-routes (IPv6) shows ::/0 with correct attributes")
    test_func = functools.partial(_r1_adv_routes_ipv6_default, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r1 advertised-routes does not show ::/0 with expected attributes"
    )

    step("r1: verify advertised-routes (IPv6) text mode shows ::/0 (crash guard)")
    test_func = functools.partial(_r1_adv_routes_ipv6_default_text, r1)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, (
        "r1 advertised-routes text output missing ::/0"
    )

    step("r1: verify advertised-routes with prefix 0.0.0.0/0 specified")
    test_func = functools.partial(_r1_adv_routes_ipv4_default_prefix, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r1 advertised-routes 0.0.0.0/0 does not show expected attributes"
    )


def test_bgp_network_default_attr():
    """
    Verify advertised-routes attributes for 0.0.0.0/0 originated via
    'network 0.0.0.0/0' (with 'no bgp network import-check') rather than
    default-originate.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("r1: remove default-originate, add 'no bgp network import-check' and 'network 0.0.0.0/0'")
    r1.vtysh_cmd(
        """
    configure terminal
      router bgp 65001
        no bgp network import-check
        address-family ipv4 unicast
          no neighbor {} default-originate route-map SET_COMMUNITY
          network 0.0.0.0/0
        exit-address-family
    """.format(R2_IPV4)
    )

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _r2_has_ipv4_default_network(router):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json")
        )
        expected = {
            "paths": [
                {
                    "aspath": {"string": ASPATH},
                    "nexthops": [{"ip": R1_IPV4}],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _r1_adv_routes_ipv4_default_network(router):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbor {} advertised-routes json".format(R2_IPV4)
            )
        )
        result = topotest.json_cmp(
            output,
            {
                "advertisedRoutes": {
                    "0.0.0.0/0": {
                        "path": ASPATH,
                    }
                }
            },
        )
        if result:
            return result
        # Note: nexthop currently shows 0.0.0.0 in advertised-routes.
        # TODO: update to check for real nexthop once that patch is added.
        route = output.get("advertisedRoutes", {}).get("0.0.0.0/0", {})
        nexthop = route.get("nextHop") or route.get("nextHopGlobal", "")
        if nexthop != "0.0.0.0":
            return "0.0.0.0/0 nexthop: expected 0.0.0.0, got {}".format(nexthop)
        return None

    # -------------------------------------------------------------------------
    # Run the checks
    # -------------------------------------------------------------------------

    step("r2: verify 0.0.0.0/0 received via 'network' statement with correct AS-path")
    test_func = functools.partial(_r2_has_ipv4_default_network, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r2 did not receive 0.0.0.0/0 (network statement) with path='{}'".format(ASPATH)
    )

    step("r1: verify advertised-routes shows 0.0.0.0/0 (network statement)")
    test_func = functools.partial(_r1_adv_routes_ipv4_default_network, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r1 advertised-routes does not show 0.0.0.0/0 (network statement) with expected attributes"
    )


def test_bgp_both_default_attr():
    """
    Verify behavior when both 'default-originate route-map SET_COMMUNITY' and
    'network 0.0.0.0/0' are configured simultaneously on r1.

    Expected: default-originate takes precedence - r2 receives 0.0.0.0/0 with
    the route-map community and metric.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("r1: add back default-originate route-map while 'network 0.0.0.0/0' is still active")
    r1.vtysh_cmd(
        """
    configure terminal
      router bgp 65001
        address-family ipv4 unicast
          neighbor {} default-originate route-map SET_COMMUNITY
        exit-address-family
    """.format(R2_IPV4)
    )

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _r2_has_ipv4_default_both(router):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json")
        )
        # default-originate takes precedence: r2 receives the synthesized
        # default with the route-map attributes (community, metric).
        expected = {
            "paths": [
                {
                    "aspath": {"string": ASPATH},
                    "community": {"string": COMMUNITY},
                    "metric": METRIC,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _r1_adv_routes_ipv4_default_both(router):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbor {} advertised-routes json".format(R2_IPV4)
            )
        )
        result = topotest.json_cmp(
            output,
            {
                "advertisedRoutes": {
                    "0.0.0.0/0": {
                        "path": ASPATH,
                    }
                }
            },
        )
        if result:
            return result
        # Note: nexthop currently shows 0.0.0.0 for default-originate.
        # TODO: update to check for real nexthop once that patch is added.
        route = output.get("advertisedRoutes", {}).get("0.0.0.0/0", {})
        nexthop = route.get("nextHop") or route.get("nextHopGlobal", "")
        if nexthop != "0.0.0.0":
            return "0.0.0.0/0 nexthop: expected 0.0.0.0, got {}".format(nexthop)
        return None

    def _r1_adv_routes_ipv4_default_both_prefix(router):
        """Query with prefix 0.0.0.0/0 specified - should show synthesized entry."""
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbor {} advertised-routes 0.0.0.0/0 json".format(
                    R2_IPV4
                )
            )
        )
        # Should show default-originate attributes (community, metric),
        # NOT the table entry from 'network 0.0.0.0/0'.
        return topotest.json_cmp(
            output,
            {
                "advertisedRoutes": {
                    "0.0.0.0/0": {
                        "path": ASPATH,
                        "community": {"string": COMMUNITY},
                        "metric": METRIC,
                    }
                }
            },
        )

    # -------------------------------------------------------------------------
    # Run the checks
    # -------------------------------------------------------------------------

    step("r2: verify 0.0.0.0/0 received with correct AS-path (both mechanisms active)")
    test_func = functools.partial(_r2_has_ipv4_default_both, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r2 did not receive 0.0.0.0/0 with path='{}' (both mechanisms)".format(ASPATH)
    )

    step("r1: verify advertised-routes shows 0.0.0.0/0 with default-originate attributes")
    test_func = functools.partial(_r1_adv_routes_ipv4_default_both, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r1 advertised-routes does not show 0.0.0.0/0 with expected attributes (both mechanisms)"
    )

    step("r1: verify advertised-routes 0.0.0.0/0 shows synthesized entry (not table entry)")
    test_func = functools.partial(_r1_adv_routes_ipv4_default_both_prefix, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "r1 advertised-routes 0.0.0.0/0 does not show synthesized entry with community/metric"
    )


def test_bgp_default_originate_no_dup():
    """
    Verify that when the 5-second default-originate re-evaluation timer fires
    (triggered by a BGP table change), no duplicate UPDATE for 0.0.0.0/0 is
    sent to the peer when the attributes have not changed.

    The duplicate suppression uses bgp_attr_intern() pointer equality:
    if the newly computed attr pointer equals the previously stored
    subgrp->default_originate_attr, the UPDATE is skipped.

    We detect duplicates via peer->pcount_dup[], exposed as
    "receivedPrefixDup" in "show bgp neighbor <x> json".

    State coming in: test_bgp_both_default_attr has both default-originate
    and 'network 0.0.0.0/0' active.  We remove the network statement first
    to return to a single-mechanism baseline, confirm pcount_dup is 0, then
    add an unrelated prefix (1.0.0.0/8) to trigger the 5-second timer and
    verify that no duplicate UPDATE is generated.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("r1: remove 'network 0.0.0.0/0', keep default-originate only")
    r1.vtysh_cmd(
        """
    configure terminal
      router bgp 65001
        address-family ipv4 unicast
          no network 0.0.0.0/0
        exit-address-family
    """
    )

    # -------------------------------------------------------------------------
    # Helper: read r2's received-duplicate counter for its session with r1
    # -------------------------------------------------------------------------
    def _r2_has_default(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
        return None if output.get("paths") else "0.0.0.0/0 not in r2 RIB"

    def _r2_dup_count(router):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(R1_IPV4))
        )
        try:
            return output[R1_IPV4]["addressFamilyInfo"]["ipv4Unicast"][
                "receivedPrefixDup"
            ]
        except KeyError:
            return None

    step("r2: record baseline receivedPrefixDup before triggering re-evaluation")
    baseline = _r2_dup_count(r2)
    assert baseline is not None, "could not read receivedPrefixDup from r2"

    def _r1_has_1_0_0_0(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast 1.0.0.0/8 json"))
        return None if output.get("paths") else "1.0.0.0/8 not in r1 BGP table"

    step("r1: add 'network 1.0.0.0/8' to trigger the 1-second default-originate re-evaluation timer")
    r1.vtysh_cmd(
        """
    configure terminal
      router bgp 65001
        address-family ipv4 unicast
          network 1.0.0.0/8
        exit-address-family
    """
    )

    step("Wait for 1.0.0.0/8 in r1's BGP table and 1-second re-evaluation timer to fire")
    test_func = functools.partial(_r1_has_1_0_0_0, r1)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "1.0.0.0/8 not installed in r1's BGP table"

    step("Confirm default is still active on r2 (re-evaluation completed)")
    test_func = functools.partial(_r2_has_default, r2)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, "default lost after re-evaluation"

    step("r2: verify receivedPrefixDup did not increase — no duplicate UPDATE was sent")
    after = _r2_dup_count(r2)
    assert after == baseline, (
        "r2 received {} new duplicate UPDATE(s) for 0.0.0.0/0 after "
        "default-originate re-evaluation (baseline={}, after={})".format(
            after - baseline, baseline, after
        )
    )


def test_bgp_default_originate_no_dup_conditional():
    """
    Verify that no duplicate UPDATE for 0.0.0.0/0 is sent when the 5-second
    default-originate re-evaluation timer fires under a *conditional* route-map
    (one with match clauses) and the condition and attributes remain unchanged.

    State coming in: test_bgp_default_originate_no_dup has default-originate
    with SET_COMMUNITY (set-only) active and 'network 1.0.0.0/8' in the BGP
    table.  Switch to a conditional route-map that matches 1.0.0.0/8 (present
    in the table), confirm the default is still advertised, then add an unrelated
    prefix to trigger re-evaluation and verify no duplicate UPDATE is sent.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("r1: configure COND_COMMUNITY conditional route-map")
    r1.vtysh_cmd(
        """
    configure terminal
      ip prefix-list MATCH_1_0_0_0 seq 5 permit 1.0.0.0/8
      route-map COND_COMMUNITY permit 10
        match ip address prefix-list MATCH_1_0_0_0
        set community 65001:100
        set metric 1000
      exit
      router bgp 65001
        address-family ipv4 unicast
          neighbor {} default-originate route-map COND_COMMUNITY
        exit-address-family
    """.format(R2_IPV4)
    )

    def _r2_has_ipv4_default(router):
        try:
            output = json.loads(
                router.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json")
            )
        except json.JSONDecodeError:
            return "could not parse JSON for 0.0.0.0/0"
        expected = {"paths": [{"aspath": {"string": ASPATH}}]}
        return topotest.json_cmp(output, expected)

    def _r2_dup_count(router):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(R1_IPV4))
        )
        try:
            return output[R1_IPV4]["addressFamilyInfo"]["ipv4Unicast"][
                "receivedPrefixDup"
            ]
        except KeyError:
            return 0

    step("r2: verify 0.0.0.0/0 still received (condition met: 1.0.0.0/8 in table)")
    test_func = functools.partial(_r2_has_ipv4_default, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not receive 0.0.0.0/0 with conditional route-map"

    step("r2: record baseline receivedPrefixDup")
    baseline = _r2_dup_count(r2)

    def _r1_has_2_0_0_0(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast 2.0.0.0/8 json"))
        return None if output.get("paths") else "2.0.0.0/8 not in r1 BGP table"

    step("r1: add 'network 2.0.0.0/8' to trigger the 1-second re-evaluation timer")
    r1.vtysh_cmd(
        """
    configure terminal
      router bgp 65001
        address-family ipv4 unicast
          network 2.0.0.0/8
        exit-address-family
    """
    )

    step("Wait for 2.0.0.0/8 in r1's BGP table and 1-second re-evaluation timer to fire")
    test_func = functools.partial(_r1_has_2_0_0_0, r1)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "2.0.0.0/8 not installed in r1's BGP table"

    step("Confirm default is still active on r2 (re-evaluation completed)")
    test_func = functools.partial(_r2_has_ipv4_default, r2)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, "default lost after re-evaluation"

    step("r2: verify receivedPrefixDup did not increase — no duplicate UPDATE was sent")
    after = _r2_dup_count(r2)
    assert after == baseline, (
        "r2 received {} new duplicate UPDATE(s) for 0.0.0.0/0 after "
        "conditional re-evaluation (baseline={}, after={})".format(
            after - baseline, baseline, after
        )
    )


def test_bgp_default_originate_denied_with_table_entry():
    """
    Verify that when default-originate is configured but denied (condition not met),
    advertised-routes shows nothing for 0.0.0.0/0 even if a table entry exists.

    When default-originate is configured, it governs entirely - the table entry
    is never shown as a separate route.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("r1: remove prefixes from previous tests and configure denied default-originate")
    r1.vtysh_cmd(
        """
    configure terminal
      ip prefix-list MATCH_NOTHING seq 5 permit 99.99.99.0/24
      route-map DENY_DEFAULT permit 10
        match ip address prefix-list MATCH_NOTHING
        set community 65001:999
      exit
      router bgp 65001
        address-family ipv4 unicast
          no network 1.0.0.0/8
          no network 2.0.0.0/8
          neighbor {} default-originate route-map DENY_DEFAULT
          network 0.0.0.0/0
        exit-address-family
    """.format(R2_IPV4)
    )

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _r2_no_ipv4_default(router):
        """Verify r2 does NOT have 0.0.0.0/0 (condition not met, no default sent)."""
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json")
        )
        # Should not have 'paths' key if route doesn't exist
        if "paths" in output:
            return "r2 should NOT have 0.0.0.0/0 but it does"
        return None

    def _r1_adv_routes_no_default(router):
        """Verify advertised-routes does NOT show 0.0.0.0/0."""
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbor {} advertised-routes json".format(
                    R2_IPV4
                )
            )
        )
        adv_routes = output.get("advertisedRoutes", {})
        if "0.0.0.0/0" in adv_routes:
            return "advertised-routes should NOT show 0.0.0.0/0 but it does"
        return None

    def _r1_adv_routes_prefix_no_default(router):
        """Verify advertised-routes 0.0.0.0/0 shows nothing."""
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbor {} advertised-routes 0.0.0.0/0 json".format(
                    R2_IPV4
                )
            )
        )
        adv_routes = output.get("advertisedRoutes", {})
        if "0.0.0.0/0" in adv_routes:
            return "advertised-routes 0.0.0.0/0 should show nothing but shows the route"
        return None

    # -------------------------------------------------------------------------
    # Run the checks
    # -------------------------------------------------------------------------

    step("r2: verify 0.0.0.0/0 is NOT received (condition not met)")
    test_func = functools.partial(_r2_no_ipv4_default, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    step("r1: verify advertised-routes does NOT show 0.0.0.0/0")
    test_func = functools.partial(_r1_adv_routes_no_default, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    step("r1: verify advertised-routes 0.0.0.0/0 shows nothing (not table entry)")
    test_func = functools.partial(_r1_adv_routes_prefix_no_default, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
