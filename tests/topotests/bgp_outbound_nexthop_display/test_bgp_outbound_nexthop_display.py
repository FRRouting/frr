#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP outbound nexthop display in "show bgp advertised-routes".

The outbound attribute stored in the adj-out table uses a shared nexthop
(0.0.0.0/::) common to all update-group members. The actual per-peer
nexthop is computed by bpacket_reformat_for_peer() at packet-send time.
bgp_nexthop_reformat_for_peer() implements the same logic so that
"show bgp [ipv4|ipv6] unicast neighbors X advertised-routes" can display
the nexthop that was actually encoded in the UPDATE for each peer.

Each test validates two things:
  1. The nexthop shown in r1's "advertised-routes" for the peer (JSON
     nextHop / nextHopGlobal, or plain-text line).
  2. The nexthop received by the peer (cross-validates that the displayed
     value matches what was actually sent in the UPDATE).

IPv4 JSON scenarios (tests 1-8):

  1. test_self_originated_ebgp_multiaccess
     r1 self-originates 172.16.1.0/24 (adj-out nexthop = 0.0.0.0).
     Advertised to r4 (EBGP on shared LAN): displayed nexthop = 10.0.0.1
     (r1's LAN address), not 0.0.0.0.

  2. test_self_originated_ebgp_non_multiaccess
     Same self-originated prefix advertised to r5 (EBGP on p2p link):
     displayed nexthop = 192.168.15.1 (r1's p2p address).

  3. test_self_originated_ibgp
     Same self-originated prefix advertised to r2 (IBGP):
     displayed nexthop = 192.168.12.1 (r1's IBGP interface address).

  4. test_third_party_nexthop_multiaccess
     r3 announces 172.16.3.0/24 with nexthop 10.0.0.3 (r3's LAN address).
     r1 re-advertises to r4 (also on the LAN): bgp_multiaccess_check_v4()
     finds 10.0.0.3 reachable from r4's subnet, so the third-party nexthop
     is preserved. Displayed nexthop = 10.0.0.3, NOT r1's address.

  5. test_ebgp_non_multiaccess_nexthop_rewrite
     Same r3 route re-advertised to r5 (p2p link, 192.168.15.0/30):
     10.0.0.3 is NOT on r5's subnet, so EBGP rewrites the nexthop.
     Displayed nexthop = 192.168.15.1 (r1's p2p address).

  6. test_ibgp_nexthop_passthrough
     r3 route re-advertised to r2 (IBGP, no next-hop-self):
     nexthop passes through unchanged. Displayed nexthop = 10.0.0.3.

  7. test_ibgp_next_hop_self
     Same r3 route with next-hop-self configured on r1 → r2:
     displayed nexthop = 192.168.12.1 (r1's IBGP address).

  8. test_rmap_nexthop_peer_address
     Outbound route-map on r1 → r4 sets "set ip next-hop peer-address".
     In FRR, this uses peer->nexthop.v4 = r1's own outgoing LAN address
     (10.0.0.1). The key distinction is that it overrides the multiaccess
     third-party-nexthop preservation: without the route-map, the r3 route
     keeps 10.0.0.3; with it the nexthop becomes 10.0.0.1 (r1's LAN addr).

IPv4 plain-text scenarios (tests 9-10):
These exercise route_vty_out() rather than the JSON route_vty_out_tmp()
path covered by tests 1-8.

  9. test_self_originated_ebgp_text
     Self-originated 172.16.1.0/24 to r4 in plain-text output:
     line must contain 10.0.0.1, not 0.0.0.0.

  10. test_third_party_nexthop_multiaccess_text
      r3 route to r4 in plain-text output: line must contain 10.0.0.3
      (third-party nexthop preserved).

IPv6 scenarios (tests 11-12):
These exercise the IPv6 branch of bgp_nexthop_reformat_for_peer() and
verify the nextHopGlobal JSON field. Neighbors use the shared LAN
2001:db8:1::/64 segment.

  11. test_self_originated_ipv6_ebgp_multiaccess
      r1 self-originates 2001:db8:100::/48 (adj-out nextHopGlobal = ::).
      Advertised to r4 over the IPv6 session: displayed nextHopGlobal =
      2001:db8:1::1 (r1's LAN IPv6 address), not ::.

  12. test_third_party_nexthop_ipv6_multiaccess
      r3 announces 2001:db8:300::/48 with nexthop 2001:db8:1::3.
      r1 re-advertises to r4 (same LAN): third-party nexthop preserved.
      Displayed nextHopGlobal = 2001:db8:1::3, NOT r1's address.

IPv4-mapped nexthop scenario (test 13):
Tests IS_MAPPED_IPV6 path in bgp_nexthop_reformat_for_peer().
::ffff:192.168.15.1/128 is configured on r1-eth2 in startup frr.conf so
if_get_ipv6_global() sets peer->nexthop.v6_global = ::ffff:... persistently.
This test runs before tests 14-15 to avoid DAD interference.

  13. test_ipv6_routes_ipv4_session_mapped_nexthop
      IPv6 unicast AF is activated dynamically on the IPv4 r1-r5 session.
      IS_MAPPED_IPV6(&peer->nexthop.v6_global) fires and the displayed
      nextHopGlobal = ::ffff:192.168.15.1, matching what bpacket encodes.

RFC 5549 scenarios (tests 14-15):
Tests peer_cap_enhe() — the first branch in nhafi determination.
ENHE is configured dynamically via an IPv6 session on the p2p link.

  14. test_rfc5549_self_originated
      r1 and r5 establish an IPv6 BGP session (2001:db8:f:1::/64) with
      extended-nexthop.  peer->nexthop.v6_global = 2001:db8:f:1::1 (r1's
      global IPv6).  Displayed nextHopGlobal = 2001:db8:f:1::1.

  15. test_rfc5549_third_party
      Same ENHE session; r3's route is re-advertised with the same
      IPv6 nexthop.  ENHE is removed at the end to restore clean state.

Topology:

                        LAN 10.0.0.0/24, 2001:db8:1::/64
    r3 (AS65003, .3) --+
    r4 (AS65004, .4) --+-- r1 (AS65001, .1) --+-- r2 (AS65001) [IBGP 192.168.12.0/30]
                                                +-- r5 (AS65005) [EBGP 192.168.15.0/30]

r1-eth2 also carries ::ffff:192.168.15.1/128 (for test 13) and is used
by the dynamic ENHE sessions in tests 14-15.

All routers use "no bgp default ipv4-unicast" with explicit per-AF
neighbor activation to keep IPv4 and IPv6 sessions cleanly separated.
r1 uses "bgp route-map delay-timer 1" to minimize the reconvergence
window after route-map changes (default 5 s would make test 12 flaky).
"""

import os
import re
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

# IPv4 addresses
R1_LAN = "10.0.0.1"       # r1 on shared LAN (eth0)
R3_LAN = "10.0.0.3"       # r3 on shared LAN
R4_LAN = "10.0.0.4"       # r4 on shared LAN
R1_IBGP = "192.168.12.1"  # r1 on IBGP link to r2 (eth1)
R2_IBGP = "192.168.12.2"  # r2
R1_P2P = "192.168.15.1"   # r1 on p2p link to r5 (eth2)
R5_P2P = "192.168.15.2"   # r5

# IPv6 addresses (LAN 2001:db8:1::/64)
R1_LAN_V6 = "2001:db8:1::1"
R3_LAN_V6 = "2001:db8:1::3"
R4_LAN_V6 = "2001:db8:1::4"

# IPv4 prefixes
PFX_SELF = "172.16.1.0/24"   # self-originated by r1
PFX_R3 = "172.16.3.0/24"     # originated by r3

# IPv6 prefixes
PFX_SELF_V6 = "2001:db8:100::/48"   # self-originated by r1
PFX_R3_V6 = "2001:db8:300::/48"     # originated by r3

# RFC 5549: r1 and r5 share the p2p link (192.168.15.0/30).
# Two ENHE session variants are tested dynamically:
#   - Global IPv6 session (2001:db8:f:1::/64): peer->nexthop.v6_global is set,
#     displayed nextHopGlobal = R1_P2P_V6.
#   - Explicit link-local session (fe80:f:1::/64, Style A from bgp_ipv6_ll_peering):
#     peer->nexthop.v6_global is unspecified (only link-local on the interface),
#     IPv4-mapped fires, displayed nextHopGlobal = R1_P2P_MAPPED.
R1_P2P_V6 = "2001:db8:f:1::1"      # r1's global IPv6 toward r5
R5_P2P_V6 = "2001:db8:f:1::2"      # r5's global IPv6
R1_P2P_LL = "fe80:f:1::1"          # r1's explicit link-local toward r5
R5_P2P_LL = "fe80:f:1::2"          # r5's explicit link-local
R1_P2P_MAPPED = "::ffff:192.168.15.1"  # IPv4-mapped nexthop (from peer->nexthop.v4)


def build_topo(tgen):
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    # Shared LAN: r1, r3, r4 — multiaccess segment
    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["r3"])
    s1.add_link(tgen.gears["r4"])

    # IBGP p2p: r1 — r2
    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r1"])
    s2.add_link(tgen.gears["r2"])

    # EBGP non-multiaccess p2p: r1 — r5
    s3 = tgen.add_switch("s3")
    s3.add_link(tgen.gears["r1"])
    s3.add_link(tgen.gears["r5"])


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
# Helpers
# ---------------------------------------------------------------------------


def _wait_for(fn, timeout=30):
    _, result = topotest.run_and_expect(fn, None, count=timeout, wait=1)
    return result


def _bgp_established(router, neighbor):
    output = json.loads(
        router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
    )
    expected = {neighbor: {"bgpState": "Established"}}
    return topotest.json_cmp(output, expected)


def _r1_advertised_nexthop(r1, neighbor, prefix, expected_nh):
    """
    Return None when r1's advertised-routes for 'neighbor' shows 'prefix'
    with nexthop 'expected_nh'.
    """
    try:
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbors {} advertised-routes json".format(
                    neighbor
                )
            )
        )
    except json.JSONDecodeError:
        return "could not parse JSON"

    expected = {"advertisedRoutes": {prefix: {"nextHop": expected_nh}}}
    return topotest.json_cmp(output, expected)


def _peer_received_nexthop(peer, prefix, expected_nh):
    """
    Return None when 'peer' has received 'prefix' with nexthop 'expected_nh'.
    Checks the first path's nexthop inside paths[].nexthops[].
    """
    try:
        output = json.loads(peer.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix)))
    except json.JSONDecodeError:
        return "could not parse JSON"

    paths = output.get("paths", [])
    if not paths:
        return "no paths for {}".format(prefix)

    for path in paths:
        for nh in path.get("nexthops", []):
            if nh.get("ip") == expected_nh:
                return None

    return "nexthop {} not found in paths for {}".format(expected_nh, prefix)


def _peer_received_enhe_nexthop(peer, prefix, expected_nh):
    """
    For RFC 5549: an IPv4 prefix received over an ENHE session lives in the
    IPv4 unicast table but carries an IPv6 nexthop.  Check 'show bgp ipv4
    unicast' (not ipv6) for the nexthop IP value.
    """
    try:
        output = json.loads(
            peer.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
    except json.JSONDecodeError:
        return "could not parse JSON"

    paths = output.get("paths", [])
    if not paths:
        return "no paths for {}".format(prefix)

    for path in paths:
        for nh in path.get("nexthops", []):
            if nh.get("ip") == expected_nh:
                return None

    return "nexthop {} not found for {}".format(expected_nh, prefix)


def _r1_advertised_enhe_nexthop(r1, neighbor, prefix, expected_nh):
    """
    For RFC 5549 (ENHE): IPv4 prefixes advertised with an IPv6 nexthop still
    appear in 'show bgp ipv4 unicast advertised-routes', but the nexthop
    field is nextHopGlobal (not nextHop) because BGP_ATTR_MP_NEXTHOP_LEN_IP6
    is true in the display attribute.
    """
    try:
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbors {} advertised-routes json".format(
                    neighbor
                )
            )
        )
    except json.JSONDecodeError:
        return "could not parse JSON"

    expected = {"advertisedRoutes": {prefix: {"nextHopGlobal": expected_nh}}}
    return topotest.json_cmp(output, expected)


def _r1_advertised_nexthop_v6(r1, neighbor, prefix, expected_nh):
    """
    Return None when r1's IPv6 advertised-routes for 'neighbor' shows 'prefix'
    with nextHopGlobal 'expected_nh'.
    """
    try:
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv6 unicast neighbors {} advertised-routes json".format(
                    neighbor
                )
            )
        )
    except json.JSONDecodeError:
        return "could not parse JSON"

    expected = {"advertisedRoutes": {prefix: {"nextHopGlobal": expected_nh}}}
    return topotest.json_cmp(output, expected)


def _r1_advertised_nexthop_text(r1, neighbor, afisafi, prefix, expected_nh):
    """
    Return None when the plain-text advertised-routes output on r1 for
    'neighbor' contains a line with both 'prefix' and 'expected_nh'.
    """
    output = r1.vtysh_cmd(
        "show bgp {} neighbors {} advertised-routes".format(afisafi, neighbor)
    )
    for line in output.splitlines():
        if prefix in line and expected_nh in line:
            return None
    return "prefix {} with nexthop {} not found in output:\n{}".format(
        prefix, expected_nh, output
    )


def _peer_received_nexthop_v6(peer, prefix, expected_nh):
    """
    Return None when 'peer' has received IPv6 'prefix' with nexthop 'expected_nh'.
    """
    try:
        output = json.loads(
            peer.vtysh_cmd("show bgp ipv6 unicast {} json".format(prefix))
        )
    except json.JSONDecodeError:
        return "could not parse JSON"

    paths = output.get("paths", [])
    if not paths:
        return "no paths for {}".format(prefix)

    for path in paths:
        for nh in path.get("nexthops", []):
            if nh.get("ip") == expected_nh:
                return None

    return "nexthop {} not found in paths for {}".format(expected_nh, prefix)


def _wait_sessions(r1):
    """Wait for all BGP sessions on r1 to be established."""
    for neighbor in [R3_LAN, R4_LAN, R2_IBGP, R5_P2P,
                     R3_LAN_V6, R4_LAN_V6]:
        assert (
            _wait_for(functools.partial(_bgp_established, r1, neighbor)) is None
        ), "BGP session to {} not established".format(neighbor)


# ---------------------------------------------------------------------------
# Test 1: Self-originated route — EBGP multiaccess peer (r4)
# ---------------------------------------------------------------------------


def test_self_originated_ebgp_multiaccess():
    """
    Self-originated route: adj-out nexthop is 0.0.0.0; must display as
    r1's LAN address (10.0.0.1) when advertised to EBGP multiaccess peer r4.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    step("Wait for all BGP sessions")
    _wait_sessions(r1)

    step("Check advertised-routes display on r1 toward r4")
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R4_LAN, PFX_SELF, R1_LAN)
        )
        is None
    )

    step("Cross-validate: r4 received {} with nexthop {}".format(PFX_SELF, R1_LAN))
    assert (
        _wait_for(functools.partial(_peer_received_nexthop, r4, PFX_SELF, R1_LAN))
        is None
    )


# ---------------------------------------------------------------------------
# Test 2: Self-originated route — EBGP non-multiaccess peer (r5)
# ---------------------------------------------------------------------------


def test_self_originated_ebgp_non_multiaccess():
    """
    Self-originated route advertised to EBGP non-multiaccess peer r5:
    displayed nexthop must be r1's p2p address (192.168.15.1).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r5 = tgen.gears["r5"]

    step("Check advertised-routes display on r1 toward r5")
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R5_P2P, PFX_SELF, R1_P2P)
        )
        is None
    )

    step("Cross-validate: r5 received {} with nexthop {}".format(PFX_SELF, R1_P2P))
    assert (
        _wait_for(functools.partial(_peer_received_nexthop, r5, PFX_SELF, R1_P2P))
        is None
    )


# ---------------------------------------------------------------------------
# Test 3: Self-originated route — IBGP peer (r2)
# ---------------------------------------------------------------------------


def test_self_originated_ibgp():
    """
    Self-originated route advertised to IBGP peer r2:
    displayed nexthop must be r1's IBGP interface address (192.168.12.1).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Check advertised-routes display on r1 toward r2")
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R2_IBGP, PFX_SELF, R1_IBGP)
        )
        is None
    )

    step("Cross-validate: r2 received {} with nexthop {}".format(PFX_SELF, R1_IBGP))
    assert (
        _wait_for(functools.partial(_peer_received_nexthop, r2, PFX_SELF, R1_IBGP))
        is None
    )


# ---------------------------------------------------------------------------
# Test 4: Third-party nexthop — EBGP multiaccess (r4)
# ---------------------------------------------------------------------------


def test_third_party_nexthop_multiaccess():
    """
    r3 announces 172.16.3.0/24 with nexthop 10.0.0.3. r1 re-advertises to
    r4 (also on the 10.0.0.0/24 LAN): bgp_multiaccess_check_v4() finds
    10.0.0.3 reachable from r4's subnet, so the third-party nexthop is
    preserved. Displayed nexthop must be 10.0.0.3 (not r1's address).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    step("Check advertised-routes display: third-party nexthop preserved to r4")
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R4_LAN, PFX_R3, R3_LAN)
        )
        is None
    )

    step("Cross-validate: r4 received {} with nexthop {}".format(PFX_R3, R3_LAN))
    assert (
        _wait_for(functools.partial(_peer_received_nexthop, r4, PFX_R3, R3_LAN))
        is None
    )


# ---------------------------------------------------------------------------
# Test 5: EBGP non-multiaccess nexthop rewrite (r5)
# ---------------------------------------------------------------------------


def test_ebgp_non_multiaccess_nexthop_rewrite():
    """
    r3 route re-advertised to r5 (p2p link 192.168.15.0/30): 10.0.0.3
    is not on r5's subnet, so EBGP non-multiaccess rewrites the nexthop
    to r1's outgoing p2p address. Displayed nexthop must be 192.168.15.1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r5 = tgen.gears["r5"]

    step("Check advertised-routes display: nexthop rewritten to r1's p2p addr")
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R5_P2P, PFX_R3, R1_P2P)
        )
        is None
    )

    step("Cross-validate: r5 received {} with nexthop {}".format(PFX_R3, R1_P2P))
    assert (
        _wait_for(functools.partial(_peer_received_nexthop, r5, PFX_R3, R1_P2P))
        is None
    )


# ---------------------------------------------------------------------------
# Test 6: IBGP nexthop pass-through (no next-hop-self)
# ---------------------------------------------------------------------------


def test_ibgp_nexthop_passthrough():
    """
    r3 route re-advertised to IBGP peer r2 without next-hop-self:
    the nexthop passes through unchanged. Displayed nexthop must be
    10.0.0.3 (r3's LAN address), not r1's address.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Ensure next-hop-self is not configured on r1 → r2")
    r1.vtysh_cmd(
        """
configure
  router bgp 65001
    address-family ipv4 unicast
      no neighbor {} next-hop-self
""".format(
            R2_IBGP
        )
    )

    step("Check advertised-routes display: nexthop passes through to IBGP peer")
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R2_IBGP, PFX_R3, R3_LAN)
        )
        is None
    )

    step("Cross-validate: r2 received {} with nexthop {}".format(PFX_R3, R3_LAN))
    assert (
        _wait_for(functools.partial(_peer_received_nexthop, r2, PFX_R3, R3_LAN))
        is None
    )


# ---------------------------------------------------------------------------
# Test 7: IBGP with next-hop-self
# ---------------------------------------------------------------------------


def test_ibgp_next_hop_self():
    """
    r3 route re-advertised to IBGP peer r2 with next-hop-self configured:
    displayed nexthop must be r1's IBGP interface address (192.168.12.1).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Configure next-hop-self on r1 → r2")
    r1.vtysh_cmd(
        """
configure
  router bgp 65001
    address-family ipv4 unicast
      neighbor {} next-hop-self
""".format(
            R2_IBGP
        )
    )

    step("Check advertised-routes display: nexthop is r1's IBGP address")
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R2_IBGP, PFX_R3, R1_IBGP)
        )
        is None
    )

    step("Cross-validate: r2 received {} with nexthop {}".format(PFX_R3, R1_IBGP))
    assert (
        _wait_for(functools.partial(_peer_received_nexthop, r2, PFX_R3, R1_IBGP))
        is None
    )

    step("Restore: remove next-hop-self")
    r1.vtysh_cmd(
        """
configure
  router bgp 65001
    address-family ipv4 unicast
      no neighbor {} next-hop-self
""".format(
            R2_IBGP
        )
    )


# ---------------------------------------------------------------------------
# Test 8: Route-map set next-hop peer-address
# ---------------------------------------------------------------------------


def test_rmap_nexthop_peer_address():
    """
    Outbound route-map on r1 → r4 sets "set ip next-hop peer-address".
    In FRR, peer->nexthop.v4 is r1's own outgoing LAN address (10.0.0.1),
    so the nexthop in the UPDATE = 10.0.0.1. The route-map overrides the
    multiaccess third-party-nexthop preservation: the r3 route would
    normally keep 10.0.0.3, but the route-map forces it to 10.0.0.1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    step("Configure route-map setting next-hop to peer-address on r1 → r4")
    r1.vtysh_cmd(
        """
configure
  route-map NH_PEER_ADDR permit 10
    set ip next-hop peer-address
  router bgp 65001
    address-family ipv4 unicast
      neighbor {} route-map NH_PEER_ADDR out
""".format(
            R4_LAN
        )
    )

    step("Check advertised-routes display: nexthop = r1's LAN address (not r3's)")
    # Both PFX_R3 and PFX_SELF should now show r1's LAN address as nexthop.
    # For PFX_R3 this is the distinctive result: without the route-map,
    # multiaccess preservation would keep 10.0.0.3 (r3's addr); the
    # route-map forces it to 10.0.0.1 (r1's outgoing addr, peer->nexthop.v4).
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R4_LAN, PFX_R3, R1_LAN)
        )
        is None
    )
    assert (
        _wait_for(
            functools.partial(_r1_advertised_nexthop, r1, R4_LAN, PFX_SELF, R1_LAN)
        )
        is None
    )

    step("Cross-validate: r4 received {} with nexthop {}".format(PFX_R3, R1_LAN))
    assert (
        _wait_for(functools.partial(_peer_received_nexthop, r4, PFX_R3, R1_LAN))
        is None
    )

    step("Restore: remove route-map from r1 → r4")
    r1.vtysh_cmd(
        """
configure
  router bgp 65001
    address-family ipv4 unicast
      no neighbor {} route-map NH_PEER_ADDR out
  no route-map NH_PEER_ADDR
""".format(
            R4_LAN
        )
    )


# ---------------------------------------------------------------------------
# Test 9: Plain-text path — self-originated route
# ---------------------------------------------------------------------------


def test_self_originated_ebgp_text():
    """
    Plain-text advertised-routes path: self-originated prefix must show r1's
    real nexthop instead of 0.0.0.0. This exercises route_vty_out() rather
    than the JSON route_vty_out_tmp() path checked by test 1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Plain-text: self-originated to r4 shows r1's LAN address (not 0.0.0.0)")
    assert (
        _wait_for(
            functools.partial(
                _r1_advertised_nexthop_text,
                r1, R4_LAN, "ipv4 unicast", PFX_SELF, R1_LAN,
            )
        )
        is None
    )


# ---------------------------------------------------------------------------
# Test 10: Plain-text path — third-party nexthop preserved
# ---------------------------------------------------------------------------


def test_third_party_nexthop_multiaccess_text():
    """
    Plain-text advertised-routes path: third-party nexthop from r3 must be
    preserved when re-advertising to r4 (same LAN). Tests route_vty_out().
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Plain-text: r3 route to r4 shows r3's nexthop (third-party preserved)")
    assert (
        _wait_for(
            functools.partial(
                _r1_advertised_nexthop_text,
                r1, R4_LAN, "ipv4 unicast", PFX_R3, R3_LAN,
            )
        )
        is None
    )


# ---------------------------------------------------------------------------
# Test 11: IPv6 self-originated route — EBGP multiaccess peer (r4)
# ---------------------------------------------------------------------------


def test_self_originated_ipv6_ebgp_multiaccess():
    """
    IPv6 self-originated route: adj-out nextHopGlobal is ::; display must
    show r1's LAN IPv6 address (not ::). Tests the IPv6 branch of
    bgp_nexthop_reformat_for_peer() and the nextHopGlobal JSON field.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    step("IPv6: self-originated advertised-routes to r4 shows r1's LAN IPv6 addr")
    assert (
        _wait_for(
            functools.partial(
                _r1_advertised_nexthop_v6, r1, R4_LAN_V6, PFX_SELF_V6, R1_LAN_V6
            )
        )
        is None
    )

    step("Cross-validate: r4 received {} with nexthop {}".format(PFX_SELF_V6, R1_LAN_V6))
    assert (
        _wait_for(
            functools.partial(_peer_received_nexthop_v6, r4, PFX_SELF_V6, R1_LAN_V6)
        )
        is None
    )


# ---------------------------------------------------------------------------
# Test 12: IPv6 third-party nexthop — EBGP multiaccess (r4)
# ---------------------------------------------------------------------------


def test_third_party_nexthop_ipv6_multiaccess():
    """
    IPv6 third-party nexthop: r3 announces 2001:db8:300::/48 with nexthop
    2001:db8:1::3. When r1 re-advertises to r4 (same LAN), the nexthop is
    reachable from r4's subnet so it is preserved. nextHopGlobal must be
    r3's LAN IPv6 address, not r1's.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    step("IPv6: r3 route advertised to r4 shows r3's nexthop (third-party preserved)")
    # Use a longer timeout: after several earlier tests modify BGP state,
    # the update-group for r4's IPv6 session may take a moment to converge.
    assert (
        _wait_for(
            functools.partial(
                _r1_advertised_nexthop_v6, r1, R4_LAN_V6, PFX_R3_V6, R3_LAN_V6
            ),
            timeout=60,
        )
        is None
    )

    step("Cross-validate: r4 received {} with nexthop {}".format(PFX_R3_V6, R3_LAN_V6))
    assert (
        _wait_for(
            functools.partial(_peer_received_nexthop_v6, r4, PFX_R3_V6, R3_LAN_V6)
        )
        is None
    )


# ---------------------------------------------------------------------------
# Test 13: IPv4-mapped nexthop — IPv6 AF over IPv4 TCP session
#
# r1-eth2 has ::ffff:192.168.15.1/128 configured in startup frr.conf so
# if_get_ipv6_global() sets peer->nexthop.v6_global = ::ffff:192.168.15.1
# at session establishment.  IS_MAPPED_IPV6() then fires in
# bgp_nexthop_reformat_for_peer() and the displayed nextHopGlobal is
# ::ffff:192.168.15.1 — matching what bpacket encodes in the UPDATE.
#
# This test runs before tests 14-15 (which add/remove IPv6 addresses on
# r1-eth2) to avoid DAD interference with the ::ffff: address.
# ---------------------------------------------------------------------------


def test_ipv6_routes_ipv4_session_mapped_nexthop():
    """
    IPv6 AF over IPv4 TCP session: IPv4-mapped nextHopGlobal.

    ::ffff:192.168.15.1/128 is configured on r1-eth2 in startup frr.conf so
    if_get_ipv6_global() persistently returns that address and FRR sets
    peer->nexthop.v6_global = ::ffff:192.168.15.1.  With IPv6 unicast
    activated dynamically on the IPv4 r1-r5 session, the EBGP non-multiaccess
    reset clears adj_attr->mp_nexthop_global to ::;
    bgp_nexthop_reformat_for_peer() substitutes peer->nexthop.v6_global and
    IS_MAPPED_IPV6() confirms the final value.  The displayed nextHopGlobal
    must be ::ffff:192.168.15.1, matching what bpacket encodes in the UPDATE.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r5 = tgen.gears["r5"]

    step("Activate IPv6 unicast on the IPv4 r1-r5 session")
    r1.vtysh_cmd(
        """
configure
  router bgp 65001
    address-family ipv6 unicast
      neighbor {} activate
      neighbor {} soft-reconfiguration inbound
""".format(R5_P2P, R5_P2P)
    )
    r5.vtysh_cmd(
        """
configure
  router bgp 65005
    address-family ipv6 unicast
      neighbor {} activate
      neighbor {} soft-reconfiguration inbound
""".format(R1_P2P, R1_P2P)
    )

    step("IPv6 self-originated route shows IPv4-mapped nextHopGlobal")
    assert (
        _wait_for(
            functools.partial(
                _r1_advertised_nexthop_v6, r1, R5_P2P, PFX_SELF_V6, R1_P2P_MAPPED
            )
        )
        is None
    )

    step("Cross-validate: r5 received {} with nexthop {}".format(PFX_SELF_V6, R1_P2P_MAPPED))
    assert (
        _wait_for(
            functools.partial(_peer_received_nexthop_v6, r5, PFX_SELF_V6, R1_P2P_MAPPED)
        )
        is None
    )

    step("Deactivate IPv6 unicast to restore clean state")
    r1.vtysh_cmd(
        """
configure
  router bgp 65001
    address-family ipv6 unicast
      no neighbor {}
""".format(R5_P2P)
    )
    r5.vtysh_cmd(
        """
configure
  router bgp 65005
    address-family ipv6 unicast
      no neighbor {}
""".format(R1_P2P)
    )


# ---------------------------------------------------------------------------
# Tests 14-15: RFC 5549 -- IPv6-transport session with extended-nexthop
#
# bgp_connection_enhe_af_adv() requires AF_INET6 transport, so ENHE must
# be tested on an IPv6 BGP session.  IPv6 addresses are added to the
# existing r1-eth2 / r5-eth0 interfaces dynamically so the startup configs
# and existing tests 1-12 are completely unaffected.
# ---------------------------------------------------------------------------


def _enhe_setup(r1, r5):
    """Add IPv6 addresses and an ENHE-capable BGP session on the r1-r5 p2p link."""
    r1.cmd("ip addr add {}/64 dev r1-eth2".format(R1_P2P_V6))
    r5.cmd("ip addr add {}/64 dev r5-eth0".format(R5_P2P_V6))
    r1.vtysh_cmd(
        """
configure
  router bgp 65001
    neighbor {} remote-as 65005
    neighbor {} timers 1 3
    neighbor {} timers connect 1
    neighbor {} capability extended-nexthop
    address-family ipv4 unicast
      neighbor {} activate
      neighbor {} soft-reconfiguration inbound
""".format(*([R5_P2P_V6] * 6))
    )
    r5.vtysh_cmd(
        """
configure
  router bgp 65005
    neighbor {} remote-as 65001
    neighbor {} timers 1 3
    neighbor {} timers connect 1
    neighbor {} capability extended-nexthop
    address-family ipv4 unicast
      neighbor {} activate
      neighbor {} soft-reconfiguration inbound
""".format(*([R1_P2P_V6] * 6))
    )


def _enhe_teardown(r1, r5):
    """Remove the ENHE BGP session, IPv6 addresses, and disable IPv6 on the
    p2p interfaces so that test 15 sees no IPv6 on r1-eth2 / r5-eth0."""
    r1.vtysh_cmd(
        """
configure
  router bgp 65001
    no neighbor {}
""".format(R5_P2P_V6)
    )
    r5.vtysh_cmd(
        """
configure
  router bgp 65005
    no neighbor {}
""".format(R1_P2P_V6)
    )
    r1.cmd("ip addr del {}/64 dev r1-eth2".format(R1_P2P_V6))
    r5.cmd("ip addr del {}/64 dev r5-eth0".format(R5_P2P_V6))
    # Disable IPv6 so the kernel link-local also disappears; test 15 needs
    # peer->nexthop.v6_global = :: to trigger the IPv4-mapped path.
    r1.cmd("sysctl -w net.ipv6.conf.r1-eth2.disable_ipv6=1")
    r5.cmd("sysctl -w net.ipv6.conf.r5-eth0.disable_ipv6=1")


def test_rfc5549_self_originated():
    """
    RFC 5549: self-originated IPv4 route over an IPv6-transport ENHE session.

    IPv6 addresses (2001:db8:f:1::/64) are added to the r1-r5 p2p interfaces
    and an IPv6 BGP session with 'capability extended-nexthop' is configured.
    peer_cap_enhe() returns true because bgp_connection_enhe_af_adv() sees
    AF_INET6 transport.  bgp_nexthop_reformat_for_peer() selects nhafi=AFI_IP6
    and substitutes peer->nexthop.v6_global (r1's IPv6 address toward r5).
    The displayed nextHopGlobal must be 2001:db8:f:1::1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r5 = tgen.gears["r5"]

    step("Add IPv6 addresses and configure IPv6 ENHE session on r1-r5 p2p link")
    _enhe_setup(r1, r5)

    step("Wait for IPv6 ENHE session to establish")
    assert _wait_for(functools.partial(_bgp_established, r1, R5_P2P_V6)) is None

    step("Self-originated IPv4 route over IPv6 ENHE session shows IPv6 nextHopGlobal")
    assert (
        _wait_for(
            functools.partial(
                _r1_advertised_enhe_nexthop, r1, R5_P2P_V6, PFX_SELF, R1_P2P_V6
            )
        )
        is None
    )

    step("Cross-validate: r5 received {} with nexthop {}".format(PFX_SELF, R1_P2P_V6))
    assert (
        _wait_for(
            functools.partial(_peer_received_enhe_nexthop, r5, PFX_SELF, R1_P2P_V6)
        )
        is None
    )


def test_rfc5549_third_party():
    """
    RFC 5549: third-party IPv4 route over an IPv6-transport ENHE session.

    r3 announces 172.16.3.0/24 (nexthop 10.0.0.3).  r1 re-advertises to r5
    over the IPv6 ENHE session.  10.0.0.3 is not on the 2001:db8:f:1::/64
    subnet, so the EBGP non-multiaccess check in the IPv6 branch fires and
    rewrites the nexthop to peer->nexthop.v6_global = 2001:db8:f:1::1.
    The displayed nextHopGlobal must match the encoded nexthop.

    The IPv6 ENHE session and addresses are removed at the end of this test
    to restore clean state.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r5 = tgen.gears["r5"]

    step("Third-party IPv4 route over IPv6 ENHE session shows r1 IPv6 nextHopGlobal")
    assert (
        _wait_for(
            functools.partial(
                _r1_advertised_enhe_nexthop, r1, R5_P2P_V6, PFX_R3, R1_P2P_V6
            )
        )
        is None
    )

    step("Cross-validate: r5 received {} with nexthop {}".format(PFX_R3, R1_P2P_V6))
    assert (
        _wait_for(
            functools.partial(_peer_received_enhe_nexthop, r5, PFX_R3, R1_P2P_V6)
        )
        is None
    )

    step("Remove IPv6 ENHE session and addresses to restore clean state")
    _enhe_teardown(r1, r5)




if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
