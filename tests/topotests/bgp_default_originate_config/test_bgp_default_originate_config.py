#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP default-originate config/re-evaluation separation.

This test suite verifies the behavior introduced by separating default-originate
config changes from ongoing re-evaluation:

  1. test_adjout_cache_clearing: When transitioning from "no default-originate"
     to "default-originate", stale adj-out entries for the table route are cleared.

  2. test_conditional_no_fallback: When conditional default-originate condition
     becomes unmet, the table route is NOT advertised as a fallback.

  3. test_deconfig_withdraw: 'no neighbor X default-originate' withdraws the
     synthesized default via subgroup_default_originate_unconfig().

  4. test_rmap_delete_withdraw: Deleting the route-map from the library while
     'default-originate route-map RMAP' is still configured withdraws the default.

  5. test_table_readvertise: After de-config, a real 0.0.0.0/0 in the BGP table
     is re-announced via subgroup_process_announce_selected().

  6. test_cond_withdraw_from_table: When conditional default-originate is
     configured with an unmet condition, a previously table-advertised 0.0.0.0/0
     is withdrawn.

  7. test_cond_never_sent: When the condition is never met, the synthesized
     default is never sent, even after the re-evaluation timer fires.

  8. test_peergroup_inheritance: When removing a neighbor-specific override,
     the neighbor inherits default-originate from its peer-group.

Topology:
    r1 (AS 65001) --- EBGP --- r2 (AS 65002)

Initial state: r1 has unconditional default-originate configured, plus a table
route 0.0.0.0/0 with community 65001:100 and a trigger prefix 10.10.10.10/32.
"""

import os
import sys
import json
import functools
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

R1_IPV4 = "192.168.1.1"
R2_IPV4 = "192.168.1.2"
COMMUNITY = "65001:100"


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


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _bgp_established(router, neighbor):
    output = json.loads(router.vtysh_cmd("show bgp neighbor {} json".format(neighbor)))
    expected = {neighbor: {"bgpState": "Established"}}
    return topotest.json_cmp(output, expected)


def _r2_has_default():
    """Return None when r2 has 0.0.0.0/0."""
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    try:
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
    except json.JSONDecodeError:
        return "could not parse JSON"
    if not output.get("paths"):
        return "r2 does not have 0.0.0.0/0"
    return None


def _r2_has_default_with_community():
    """Return None when r2 has 0.0.0.0/0 with community (table route)."""
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    try:
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
    except json.JSONDecodeError:
        return "could not parse JSON"
    if not output.get("paths"):
        return "r2 does not have 0.0.0.0/0"
    community = output["paths"][0].get("community", {}).get("string", "")
    if COMMUNITY not in community:
        return "missing community {} in '{}'".format(COMMUNITY, community)
    return None


def _r2_has_default_no_community():
    """Return None when r2 has 0.0.0.0/0 without community (synthesized)."""
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    try:
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
    except json.JSONDecodeError:
        return "could not parse JSON"
    if not output.get("paths"):
        return "r2 does not have 0.0.0.0/0"
    for path in output["paths"]:
        if path.get("community"):
            return "unexpected community: {}".format(path["community"])
    return None


def _r2_has_no_default():
    """Return None when r2 does NOT have 0.0.0.0/0."""
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    try:
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
    except json.JSONDecodeError:
        return "could not parse JSON"
    if output.get("paths"):
        return "r2 still has 0.0.0.0/0"
    return None


def _wait_for(test_func, timeout=30):
    _, result = topotest.run_and_expect(test_func, None, count=timeout, wait=1)
    return result


# ---------------------------------------------------------------------------
# Test 1: adj-out cache clearing on config transition
# ---------------------------------------------------------------------------

def test_adjout_cache_clearing():
    """
    Verify adj-out cache is cleared when default-originate is activated.

    When transitioning from "no default-originate" to "default-originate",
    stale adj-out entries for the table route should be cleared so that
    "show bgp advertised-routes" shows only the synthesized route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Wait for BGP session")
    assert _wait_for(functools.partial(_bgp_established, r1, R2_IPV4)) is None

    step("Remove default-originate so table route is advertised")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Wait for table route (with community) to be advertised")
    assert _wait_for(_r2_has_default_with_community) is None

    step("Re-add default-originate")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Verify adj-out shows only synthesized route")

    def _check_adjout():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv4 unicast neighbors {} advertised-routes json".format(R2_IPV4))
        )
        if output.get("bgpOriginatingDefaultNetwork") != "0.0.0.0/0":
            return "bgpOriginatingDefaultNetwork not set"
        if "0.0.0.0/0" in output.get("advertisedRoutes", {}):
            return "Stale 0.0.0.0/0 in advertisedRoutes"
        return None

    assert _wait_for(_check_adjout) is None

    step("Verify R2 receives synthesized route (no community)")
    assert _wait_for(_r2_has_default_no_community) is None


# ---------------------------------------------------------------------------
# Test 2: conditional default-originate does not fall back to table route
# ---------------------------------------------------------------------------

def test_conditional_no_fallback():
    """
    Verify conditional default-originate does not fall back to table route.

    When the route-map condition becomes unmet, the synthesized default should
    be withdrawn and the table route should NOT be advertised as a fallback.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure conditional default-originate")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                neighbor {} default-originate route-map CHECK_TRIGGER
    """.format(R2_IPV4)
    )

    step("Verify R2 receives synthesized default (condition met)")
    assert _wait_for(_r2_has_default_no_community) is None

    step("Remove trigger prefix to make condition unmet")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no network 10.10.10.10/32
    """
    )

    step("Verify R2 has NO default route (no fallback to table route)")
    assert _wait_for(_r2_has_no_default) is None

    step("Re-add trigger prefix")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                network 10.10.10.10/32
    """
    )

    step("Verify R2 receives synthesized default again")
    assert _wait_for(_r2_has_default_no_community) is None


# ---------------------------------------------------------------------------
# Test 3: explicit de-config withdraws the default route
# ---------------------------------------------------------------------------

def test_deconfig_withdraw():
    """
    Verify 'no neighbor X default-originate' withdraws the synthesized default.

    This exercises subgroup_default_originate_unconfig(). We test two cases:
    1. No table default - verify explicit withdrawal is sent
    2. Table default exists - verify table route is re-advertised
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Remove table route so only synthesized default exists")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no network 0.0.0.0/0
    """
    )

    step("Configure unconditional default-originate")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Verify R2 receives synthesized default (no community)")
    assert _wait_for(_r2_has_default_no_community) is None

    step("Remove default-originate (no table route to replace it)")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Verify R2 has no default (explicit withdrawal sent)")
    assert _wait_for(_r2_has_no_default) is None

    step("Restore table route and default-originate for next case")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                network 0.0.0.0/0 route-map SET_COMM
                neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Verify R2 receives default again")
    assert _wait_for(_r2_has_default) is None

    step("Remove default-originate (table route should be re-advertised)")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Verify table route (with community) is re-advertised")
    assert _wait_for(_r2_has_default_with_community) is None


# ---------------------------------------------------------------------------
# Test 4: deleting route-map withdraws the default route
# ---------------------------------------------------------------------------

def test_rmap_delete_withdraw():
    """
    Verify deleting the route-map from the library withdraws the default.

    When the map is deleted, peer->default_rmap[afi][safi].name is still set
    but .map becomes NULL.  subgroup_default_originate() treats this as an
    unmet condition and withdraws the default route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure default-originate with route-map")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                neighbor {} default-originate route-map SET_COMM
    """.format(R2_IPV4)
    )

    step("Verify R2 receives default")
    assert _wait_for(_r2_has_default) is None

    step("Delete route-map from library")
    r1.vtysh_cmd(
        """
    configure
        no route-map SET_COMM
    """
    )

    step("Verify default is withdrawn (route-map name configured but map gone)")
    assert _wait_for(_r2_has_no_default) is None

    step("Re-create route-map")
    r1.vtysh_cmd(
        """
    configure
        route-map SET_COMM permit 10
            set community {}
    """.format(COMMUNITY)
    )


# ---------------------------------------------------------------------------
# Test 5: table route is re-advertised after de-config
# ---------------------------------------------------------------------------

def test_table_readvertise():
    """
    Verify table route is re-advertised after removing default-originate.

    While default-originate is active, subgroup_announce_check() skips the
    default prefix.  When removed, subgroup_default_originate_unconfig()
    calls subgroup_process_announce_selected() to re-advertise the table route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure unconditional default-originate")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Verify R2 receives synthesized default (no community)")
    assert _wait_for(_r2_has_default_no_community) is None

    step("Remove default-originate")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Verify table route (with community) is re-advertised")
    assert _wait_for(_r2_has_default_with_community) is None


# ---------------------------------------------------------------------------
# Test 6: conditional default-originate with unmet condition withdraws table route
# ---------------------------------------------------------------------------

def test_cond_withdraw_from_table():
    """
    Verify conditional default-originate withdraws table-advertised 0.0.0.0/0.

    Starting state: no default-originate, table route 0.0.0.0/0 advertised.
    When conditional default-originate is configured with an unmet condition,
    default-originate takes over governance and withdraws the table route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify r2 has table route (starting state from previous test)")
    assert _wait_for(_r2_has_default_with_community) is None

    step("Configure conditional default-originate (matches 2.0.0.0/8, absent)")
    r1.vtysh_cmd(
        """
    configure
        ip prefix-list MATCH_2_0_0_0 seq 5 permit 2.0.0.0/8
        route-map COND_NEVER_MET permit 10
            match ip address prefix-list MATCH_2_0_0_0
        router bgp 65001
            address-family ipv4 unicast
                neighbor {} default-originate route-map COND_NEVER_MET
    """.format(R2_IPV4)
    )

    step("Verify table route is withdrawn (condition unmet)")
    assert _wait_for(_r2_has_no_default) is None


# ---------------------------------------------------------------------------
# Test 7: synthesized default never sent when condition never met
# ---------------------------------------------------------------------------

def test_cond_never_sent():
    """
    Verify synthesized default is never sent when condition is never met.

    Continuing from test_cond_withdraw_from_table: remove the table route
    so there is no table-originated default. Wait for re-evaluation timer
    and verify 0.0.0.0/0 is never advertised.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Remove table route 0.0.0.0/0")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no network 0.0.0.0/0
    """
    )

    step("Monitor for 3 seconds - default must never appear (timer fires at 1s)")
    # Poll periodically to catch any transient announcement that might be withdrawn
    r2 = tgen.gears["r2"]
    for _ in range(6):
        time.sleep(0.5)
        try:
            output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
            if output.get("paths"):
                pytest.fail("0.0.0.0/0 was advertised when condition was never met")
        except json.JSONDecodeError:
            pass  # No route present, as expected

    step("Final verification - 0.0.0.0/0 still absent")
    assert _wait_for(_r2_has_no_default, timeout=5) is None

    step("Restore table route for any future tests")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                network 0.0.0.0/0 route-map SET_COMM
    """
    )


# ---------------------------------------------------------------------------
# Test 8: peer-group inheritance of default-originate
# ---------------------------------------------------------------------------

def test_peergroup_inheritance():
    """
    Verify removing neighbor override inherits default-originate from peer-group.

    When a neighbor has a neighbor-specific default-originate override and that
    override is removed, the neighbor should inherit the peer-group's setting
    and continue receiving the default route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Remove any existing default-originate config")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Create peer-group with default-originate")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            neighbor DEFORG peer-group
            neighbor DEFORG remote-as external
            neighbor DEFORG timers 1 3
            neighbor DEFORG timers connect 1
            address-family ipv4 unicast
                neighbor DEFORG default-originate
                neighbor DEFORG send-community
    """
    )

    step("Add neighbor to peer-group")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            neighbor {} peer-group DEFORG
    """.format(R2_IPV4)
    )

    step("Verify r2 receives default (from peer-group)")
    assert _wait_for(_r2_has_default) is None

    step("Add neighbor-specific override with route-map")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                neighbor {} default-originate route-map CHECK_TRIGGER
    """.format(R2_IPV4)
    )

    step("Verify r2 still receives default (condition met)")
    assert _wait_for(_r2_has_default) is None

    step("Remove neighbor-specific override - should inherit from peer-group")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            address-family ipv4 unicast
                no neighbor {} default-originate
    """.format(R2_IPV4)
    )

    step("Verify r2 still receives default (inherited from peer-group)")
    assert _wait_for(_r2_has_default) is None

    step("Clean up: remove from peer-group and restore direct config")
    r1.vtysh_cmd(
        """
    configure
        router bgp 65001
            no neighbor {} peer-group DEFORG
            neighbor {} remote-as external
            neighbor {} timers 1 3
            neighbor {} timers connect 1
            address-family ipv4 unicast
                neighbor {} default-originate
                neighbor {} send-community
    """.format(R2_IPV4, R2_IPV4, R2_IPV4, R2_IPV4, R2_IPV4, R2_IPV4)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
