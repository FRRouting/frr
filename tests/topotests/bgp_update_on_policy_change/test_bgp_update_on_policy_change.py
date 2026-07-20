#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP update behavior on policy changes.

Topology: r1 (AS 65001) -- r2 (AS 65002)

r1 sources two prefixes (10.0.0.1/32, 10.0.0.11/32) and r2 sources two
prefixes (10.0.0.2/32, 10.0.0.22/32).

On r1:
  - outbound prefix-list (plist-out) permits only 10.0.0.1/32
  - inbound prefix-list (plist-in) permits only 10.0.0.2/32

Test cases:

TC1: "clear bgp * soft out" should force UPDATE re-send even if attrs
     are unchanged.  This is an explicit operator request.
     Verify: receivedPrefixDup increments on r2.

TC2: Change inbound prefix-list on r1, then "clear bgp * soft in" triggers
     ROUTE-REFRESH (RFC 2918) to r2.  Upon receiving ROUTE-REFRESH, r2
     must re-advertise the full table.
     Verify: receivedPrefixDup increments on r1 (for the existing prefix),
     and the new prefix (10.0.0.22/32) is now accepted.

TC3: Changing the outbound prefix-list should NOT cause duplicate UPDATEs
     for routes whose attributes are unchanged.  Only the newly permitted
     prefix should be sent.
     Verify: receivedPrefixDup does NOT increment on r2, and the new
     prefix is received.
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

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_check_neighbor_established(router, neighbor):
    output = json.loads(
        router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
    )
    expected = {
        neighbor: {
            "bgpState": "Established",
        }
    }
    return topotest.json_cmp(output, expected)


def _bgp_get_duplicate_count(router, neighbor):
    output = json.loads(
        router.vtysh_cmd("show bgp neighbors {} json".format(neighbor))
    )
    return output[neighbor]["addressFamilyInfo"]["ipv4Unicast"]["receivedPrefixDup"]


def _bgp_check_route_exists(router, prefix):
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    if output.get("paths"):
        return None
    return "Route {} not found".format(prefix)


def _bgp_check_route_not_exists(router, prefix):
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    if output.get("paths"):
        return "Route {} should not exist".format(prefix)
    return None


def test_bgp_converge():
    """Wait for BGP to converge and verify initial state."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Check BGP session is established")
    test_func = functools.partial(_bgp_check_neighbor_established, r1, "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP session not established"

    step("Verify r2 receives only 10.0.0.1/32 from r1 (filtered by plist-out)")
    test_func = functools.partial(_bgp_check_route_exists, r2, "10.0.0.1/32")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not receive 10.0.0.1/32"

    test_func = functools.partial(_bgp_check_route_not_exists, r2, "10.0.0.11/32")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "r2 should not receive 10.0.0.11/32"

    step("Verify r1 receives only 10.0.0.2/32 from r2 (filtered by plist-in)")
    test_func = functools.partial(_bgp_check_route_exists, r1, "10.0.0.2/32")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not receive 10.0.0.2/32"

    test_func = functools.partial(_bgp_check_route_not_exists, r1, "10.0.0.22/32")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "r1 should not receive 10.0.0.22/32"


def test_bgp_clear_soft_out():
    """
    TC1: 'clear bgp * soft out' should force UPDATE re-send.

    This is an explicit operator request to re-advertise all routes,
    so duplicate updates should be sent even if attributes are unchanged.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Get duplicate count before clear")
    dup_before = _bgp_get_duplicate_count(r2, "192.168.12.1")

    step("Perform 'clear bgp * soft out' on r1")
    r1.vtysh_cmd("clear bgp * soft out")

    step("Wait and check duplicate count increased")

    def _check_dup_increased():
        dup_after = _bgp_get_duplicate_count(r2, "192.168.12.1")
        if dup_after > dup_before:
            return None
        return "Duplicate count did not increase: before={}, after={}".format(
            dup_before, dup_after
        )

    _, result = topotest.run_and_expect(_check_dup_increased, None, count=30, wait=1)
    assert result is None, result


def test_bgp_inbound_policy_change_route_refresh():
    """
    TC2: ROUTE-REFRESH (RFC 2918) after inbound policy change.

    When r1 changes its inbound prefix-list and issues 'clear bgp soft in',
    it sends ROUTE-REFRESH to r2.  Upon receiving ROUTE-REFRESH, r2 must
    re-advertise the full table, including routes whose attributes are
    unchanged.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Get duplicate count on r1 before policy change")
    dup_before = _bgp_get_duplicate_count(r1, "192.168.12.2")

    step("Change inbound prefix-list on r1 to also allow 10.0.0.22/32")
    r1.vtysh_cmd(
        """
        configure terminal
         ip prefix-list plist-in seq 10 permit 10.0.0.22/32
        """
    )

    step("Perform 'clear bgp * soft in' on r1 to trigger ROUTE-REFRESH to r2")
    r1.vtysh_cmd("clear bgp * soft in")

    step("Verify r1 now accepts 10.0.0.22/32")
    test_func = functools.partial(_bgp_check_route_exists, r1, "10.0.0.22/32")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not receive 10.0.0.22/32 after policy change"

    step("Verify duplicate count increased on r1 (ROUTE-REFRESH caused re-advertisement)")

    def _check_dup_increased():
        dup_after = _bgp_get_duplicate_count(r1, "192.168.12.2")
        if dup_after > dup_before:
            return None
        return "Duplicate count did not increase: before={}, after={}".format(
            dup_before, dup_after
        )

    _, result = topotest.run_and_expect(_check_dup_increased, None, count=30, wait=1)
    assert result is None, result

    step("Verify r1 still has the original route")
    result = _bgp_check_route_exists(r1, "10.0.0.2/32")
    assert result is None, "r1 lost 10.0.0.2/32 after policy change"


def test_bgp_outbound_policy_change_no_dup():
    """
    TC3: Changing outbound prefix-list should NOT cause duplicate UPDATEs.

    When an outbound policy changes, the routes are re-evaluated, but if
    their attributes are unchanged, no duplicate UPDATE should be sent.
    Only the newly permitted prefix should be sent.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Get duplicate count on r2 before policy change")
    dup_before = _bgp_get_duplicate_count(r2, "192.168.12.1")

    step("Change outbound prefix-list on r1 to also allow 10.0.0.11/32")
    r1.vtysh_cmd(
        """
        configure terminal
         ip prefix-list plist-out seq 10 permit 10.0.0.11/32
        """
    )

    step("Verify r2 now receives 10.0.0.11/32")
    test_func = functools.partial(_bgp_check_route_exists, r2, "10.0.0.11/32")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not receive 10.0.0.11/32 after policy change"

    step("Verify duplicate count did NOT increase on r2")
    dup_after = _bgp_get_duplicate_count(r2, "192.168.12.1")
    assert dup_after == dup_before, (
        "Duplicate count should not change on outbound policy change: "
        "before={}, after={}".format(dup_before, dup_after)
    )

    step("Verify r2 still has the original route")
    result = _bgp_check_route_exists(r2, "10.0.0.1/32")
    assert result is None, "r2 lost 10.0.0.1/32 after policy change"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
