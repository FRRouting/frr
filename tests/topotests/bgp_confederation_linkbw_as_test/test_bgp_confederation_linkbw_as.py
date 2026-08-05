#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
Test BGP confederation link-bandwidth AS number handling.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


# AS number constants
LOCAL_AS = "65101"  # Local sub-AS for r1, r2, r7
CONFEDERATION_AS = "65100"  # Confederation AS

# Standard test prefix, originated by both r2 and r7 (multipath at r1),
# used by the transitive/automatic link-bandwidth test cases.
TRANS_PREFIX_V4 = "192.0.2.1/32"
TRANS_PREFIX_V6 = "2001:db8::1/128"

# Prefix used to test non-transitive link-bandwidth (originated by r2 only,
# no route-map at origination). r1's SET_LINKBW route-map matches this
# prefix specifically and sets link-bandwidth as non-transitive, to verify
# the AS is still corrected for the confederation boundary even though
# ecommunity_replace_linkbw() must not otherwise touch non-transitive
# communities.
NONTRANS_PREFIX_V4 = "192.0.2.2/32"
NONTRANS_PREFIX_V6 = "2001:db8::2/128"

# Prefix originated by r1 itself via a route-map (network ... route-map),
# with no per-neighbor outbound route-map on any destination. Verifies the
# AS still gets corrected for confederation boundaries even when
# BATTR_RMAP_LINK_BW_SET was only set at origination, not by an outbound
# route-map on the destination peer.
ORIG_PREFIX_V4 = "192.0.2.8/32"
ORIG_PREFIX_V6 = "2001:db8::8/128"


# Peer address mapping: [router][peer][address_family]
# This maps how each router sees its peers
PEER_ADDRESSES = {
    "r1": {
        "r2": {"ipv4": "10.0.1.2", "ipv6": "2001:db8:1::2"},
        "r7": {"ipv4": "10.0.2.2", "ipv6": "2001:db8:2::2"},
    },
    "r3": {
        "r1": {"ipv4": "10.0.3.1", "ipv6": "2001:db8:3::1"},
    },
    "r4": {
        "r1": {"ipv4": "10.0.4.1", "ipv6": "2001:db8:4::1"},
    },
    "r5": {
        "r1": {"ipv4": "10.0.5.1", "ipv6": "2001:db8:5::1"},
    },
    "r6": {
        "r1": {"ipv4": "10.0.6.1", "ipv6": "2001:db8:6::1"},
    },
}


def get_peer_address(router_name, peer_name, ipv6=False):
    """
    Get the peer address as seen by the router.

    Args:
        router_name: Router name (e.g., "r1", "r3")
        peer_name: Peer router name (e.g., "r2", "r1")
        ipv6: True for IPv6, False for IPv4

    Returns:
        str: Peer IP address

    Example:
        get_peer_address("r1", "r2", ipv6=False)  # Returns "10.0.1.2"
        get_peer_address("r3", "r1", ipv6=True)   # Returns "2001:db8:3::1"
    """
    af = "ipv6" if ipv6 else "ipv4"

    if router_name not in PEER_ADDRESSES:
        raise ValueError("Router {} not found in PEER_ADDRESSES".format(router_name))

    if peer_name not in PEER_ADDRESSES[router_name]:
        raise ValueError(
            "Peer {} not found for router {}".format(peer_name, router_name)
        )

    return PEER_ADDRESSES[router_name][peer_name][af]


def get_bgp_path_from_peer(router, prefix, peer_id, ipv6=False):
    """
    Get BGP path information for a specific prefix from a specific peer.

    Args:
        router: Router object to query
        prefix: BGP prefix (e.g., "192.0.2.1/32" or "2001:db8::1/128")
        peer_id: Peer ID to look for (e.g., "10.0.1.2")
        ipv6: True for IPv6, False for IPv4

    Returns:
        dict: Path information from the specified peer, or None if not found
    """
    if ipv6:
        cmd = "show bgp ipv6 unicast {} json".format(prefix)
    else:
        cmd = "show ip bgp {} json".format(prefix)

    output = router.vtysh_cmd(cmd)
    data = json.loads(output)

    if "paths" not in data:
        return None

    # Find the path from the specified peer
    for path in data["paths"]:
        if path.get("peer", {}).get("peerId") == peer_id:
            return path

    return None


def validate_linkbw_as(
    router,
    peer_router_name,
    expected_as,
    peer_type,
    prefix,
    ipv6=False,
    forbidden_as=None,
):
    """
    Validate that link-bandwidth extended community has the correct AS number.

    Args:
        router: Router object to query
        peer_router_name: Peer router name (e.g., "r2", "r1") - address will be auto-looked up
        expected_as: AS number that should be present (e.g., "65101")
        peer_type: Description of peer type for error messages (e.g., "iBGP peer r2")
        prefix: BGP prefix to check (e.g., TRANS_PREFIX_V4, NONTRANS_PREFIX_V6)
        ipv6: True for IPv6, False for IPv4
        forbidden_as: AS number that must not appear in LB (e.g., "65100" on iBGP paths)

    Returns:
        str: Extended community string for logging

    Raises:
        AssertionError: If validation fails
    """
    # Auto-lookup peer address based on router and peer names
    peer_id = get_peer_address(router.name, peer_router_name, ipv6)

    path = get_bgp_path_from_peer(router, prefix, peer_id, ipv6)

    assert path is not None, "No path found from peer {} ({}) on router {}".format(
        peer_router_name, peer_id, router.name
    )

    # Get extended community string
    extcomm = path.get("extendedCommunity", {}).get("string", "")

    # Validate expected AS is present
    assert (
        "LB:{}:".format(expected_as) in extcomm
    ), "Expected AS {} in link-bandwidth for {}, got: {}".format(
        expected_as, peer_type, extcomm
    )

    if forbidden_as is not None:
        assert (
            "LB:{}:".format(forbidden_as) not in extcomm
        ), "Unexpected AS {} in link-bandwidth for {}, got: {}".format(
            forbidden_as, peer_type, extcomm
        )

    return extcomm


def assert_no_linkbw(router, peer_router_name, peer_type, prefix, ipv6=False):
    """
    Assert that no link-bandwidth extended community is present.

    Used where the community must not cross an AS boundary: RFC 4360 Section 6
    says a non-transitive extended community SHOULD be removed before the route
    is advertised across an Autonomous System boundary, so a non-transitive
    link-bandwidth never reaches a plain external eBGP peer. Confederation and
    EBGP-OAD peers are not such a boundary and do still receive it.
    """
    peer_id = get_peer_address(router.name, peer_router_name, ipv6)

    path = get_bgp_path_from_peer(router, prefix, peer_id, ipv6)

    assert path is not None, "No path found from peer {} ({}) on router {}".format(
        peer_router_name, peer_id, router.name
    )

    extcomm = path.get("extendedCommunity", {}).get("string", "")

    assert (
        "LB:" not in extcomm
    ), "Non-transitive link-bandwidth must not be advertised to {}, got: {}".format(
        peer_type, extcomm
    )

    return extcomm


def build_topo(tgen):
    """Build the test topology."""

    for routern in range(1, 8):
        tgen.add_router("r{}".format(routern))

    # r1-r2 (iBGP same sub-AS)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-r7 (iBGP same sub-AS)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r7"])

    # r1-r3 (confederation peer)
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # r1-r4 (confederation peer with route-map)
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    # r1-r5 (external eBGP)
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r5"])

    # r1-r6 (external eBGP with route-map)
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r6"])


def setup_module(mod):
    """Set up the test environment."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Tear down the test environment."""
    tgen = get_topogen()
    tgen.stop_topology()


def _test_bgp_convergence(prefix, min_paths=2):
    """Test BGP convergence."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Waiting for BGP convergence")

    router = tgen.gears["r1"]

    def _bgp_converge(router):
        output = router.vtysh_cmd("show ip bgp {} json".format(prefix))
        if not output:
            return "No output"
        try:
            data = json.loads(output)
            if "paths" in data and len(data["paths"]) >= min_paths:
                return None
        except:
            pass
        return "Not converged"

    test_func = functools.partial(_bgp_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BGP did not converge on r1"

    step("BGP converged successfully")


def test_bgp_convergence():
    """Test BGP convergence."""
    _test_bgp_convergence(TRANS_PREFIX_V4)


def test_bgp_convergence_nontransitive():
    """Test BGP convergence for the non-transitive link-bandwidth test prefix."""
    _test_bgp_convergence(NONTRANS_PREFIX_V4, min_paths=1)


def test_ibgp_peer_linkbw_as():
    """Test link-bandwidth AS for iBGP peer - check what r1 receives from r2."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Checking link-bandwidth AS for iBGP peer r2 (AS 65101) - what r1 receives")

    router_r1 = tgen.gears["r1"]

    # r2 should send link-bandwidth with local AS 65101
    # because r2 and r1 are iBGP peers (same AS)
    extcomm = validate_linkbw_as(
        router=router_r1,
        peer_router_name="r2",
        expected_as=LOCAL_AS,
        peer_type="iBGP peer r2",
        prefix=TRANS_PREFIX_V4,
        ipv6=False,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r2→r1 path extended community: {}".format(extcomm))
    step(
        "PASS: r2 (iBGP peer AS 65101): Correctly uses local AS 65101 when sending to r1"
    )


def test_ibgp_peer_r7_linkbw_as():
    """Test link-bandwidth AS for iBGP peer r7 - same sub-AS as r1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Checking link-bandwidth AS for iBGP peer r7 (AS 65101) - what r1 receives")

    router_r1 = tgen.gears["r1"]

    extcomm = validate_linkbw_as(
        router=router_r1,
        peer_router_name="r7",
        expected_as=LOCAL_AS,
        peer_type="iBGP peer r7",
        prefix=TRANS_PREFIX_V4,
        ipv6=False,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r7→r1 path extended community: {}".format(extcomm))
    step(
        "PASS: r7 (iBGP peer AS 65101): Correctly uses local AS 65101 when sending to r1"
    )


def test_confederation_peer_linkbw_as():
    """Test link-bandwidth AS for confederation peer (r3)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Checking link-bandwidth AS for confederation peer r3 (AS 65102)")

    router_r3 = tgen.gears["r3"]

    # Should use sub-AS 65101
    # This tests the automatic link-bandwidth code path
    extcomm = validate_linkbw_as(
        router=router_r3,
        peer_router_name="r1",
        expected_as=LOCAL_AS,
        peer_type="confederation peer r3",
        prefix=TRANS_PREFIX_V4,
        ipv6=False,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r1→r3 path extended community: {}".format(extcomm))
    step("PASS: r3 (confederation peer AS 65102): Correctly uses sub-AS 65101")


def test_confederation_peer_origination_only_linkbw_as():
    """Test link-bandwidth AS for confederation peer (r3), origination-only route-map."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking origination-only link-bandwidth AS for confederation peer r3 (AS 65102)"
    )

    router_r3 = tgen.gears["r3"]

    # r1 originates ORIG_PREFIX_V4 via "network ... route-map", with no
    # outbound route-map on r3. Should still use sub-AS 65101.
    extcomm = validate_linkbw_as(
        router=router_r3,
        peer_router_name="r1",
        expected_as=LOCAL_AS,
        peer_type="confederation peer r3 (origination-only route-map)",
        prefix=ORIG_PREFIX_V4,
        ipv6=False,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r1→r3 origination-only path extended community: {}".format(extcomm))
    step(
        "PASS: r3 (confederation peer AS 65102, origination-only route-map): "
        "Correctly uses sub-AS 65101"
    )


def _test_confederation_peer_with_routemap_linkbw_as(prefix):
    """Test link-bandwidth AS for confederation peer with route-map (r4)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking link-bandwidth AS for confederation peer r4 (AS 65103) with route-map"
    )

    router_r4 = tgen.gears["r4"]

    # Should use sub-AS 65101 (route-map code path)
    extcomm = validate_linkbw_as(
        router=router_r4,
        peer_router_name="r1",
        expected_as=LOCAL_AS,
        peer_type="confederation peer r4 (route-map)",
        prefix=prefix,
        ipv6=False,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r1→r4 path extended community: {}".format(extcomm))
    step(
        "PASS: r4 (confederation peer AS 65103, route-map): Correctly uses sub-AS 65101"
    )


def test_confederation_peer_with_routemap_linkbw_as():
    """Test link-bandwidth AS for confederation peer with route-map (r4)."""
    _test_confederation_peer_with_routemap_linkbw_as(prefix=TRANS_PREFIX_V4)


def test_confederation_peer_with_routemap_nontransitive_linkbw_as():
    """Test link-bandwidth AS for confederation peer with non-transitive route-map (r4)."""
    _test_confederation_peer_with_routemap_linkbw_as(prefix=NONTRANS_PREFIX_V4)


def test_external_ebgp_peer_linkbw_as():
    """Test link-bandwidth AS for external eBGP peer (r5)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Checking link-bandwidth AS for external eBGP peer r5 (AS 64001)")

    router_r5 = tgen.gears["r5"]

    # Should use confederation AS 65100 (automatic code path)
    # This is the KEY test - external peers should see confederation AS
    extcomm = validate_linkbw_as(
        router=router_r5,
        peer_router_name="r1",
        expected_as=CONFEDERATION_AS,
        peer_type="external eBGP peer r5",
        prefix=TRANS_PREFIX_V4,
        ipv6=False,
    )

    step("r1→r5 path extended community: {}".format(extcomm))
    step(
        "PASS: r5 (external eBGP AS 64001, no route-map): Correctly uses confederation AS 65100"
    )


def test_external_ebgp_peer_origination_only_linkbw_as():
    """Test link-bandwidth AS for external eBGP peer (r5), origination-only route-map."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking origination-only link-bandwidth AS for external eBGP peer r5 (AS 64001)"
    )

    router_r5 = tgen.gears["r5"]

    # r1 originates ORIG_PREFIX_V4 via "network ... route-map", with no
    # outbound route-map on r5. This is the key regression check: the AS
    # correction for route-map-set link-bandwidth must apply here too,
    # even though the route-map only ran at origination and this specific
    # destination has no outbound route-map of its own.
    extcomm = validate_linkbw_as(
        router=router_r5,
        peer_router_name="r1",
        expected_as=CONFEDERATION_AS,
        peer_type="external eBGP peer r5 (origination-only route-map)",
        prefix=ORIG_PREFIX_V4,
        ipv6=False,
        forbidden_as=LOCAL_AS,
    )

    step("r1→r5 origination-only path extended community: {}".format(extcomm))
    step(
        "PASS: r5 (external eBGP AS 64001, origination-only route-map): "
        "Correctly uses confederation AS 65100"
    )


def _test_external_ebgp_peer_with_routemap_linkbw_as(prefix):
    """Test link-bandwidth AS for external eBGP peer with route-map (r6)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking link-bandwidth AS for external eBGP peer r6 (AS 64002) with route-map"
    )

    router_r6 = tgen.gears["r6"]

    # Should use confederation AS 65100 (route-map code path)
    extcomm = validate_linkbw_as(
        router=router_r6,
        peer_router_name="r1",
        expected_as=CONFEDERATION_AS,
        peer_type="external eBGP peer r6 (route-map)",
        prefix=prefix,
        ipv6=False,
    )

    step("r1→r6 path extended community: {}".format(extcomm))
    step(
        "PASS: r6 (external eBGP AS 64002, route-map): Correctly uses confederation AS 65100"
    )


def test_external_ebgp_peer_with_routemap_linkbw_as():
    """Test link-bandwidth AS for external eBGP peer with route-map (r6)."""
    _test_external_ebgp_peer_with_routemap_linkbw_as(prefix=TRANS_PREFIX_V4)


def test_external_ebgp_peer_with_routemap_nontransitive_linkbw_stripped():
    """Non-transitive link-bandwidth must not reach external eBGP peer r6.

    The AS correction for a route-map set non-transitive link-bandwidth is
    covered by test_confederation_peer_with_routemap_nontransitive_linkbw_as(),
    where r4 is a confederation peer and therefore not an AS boundary.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Checking non-transitive link-bandwidth is stripped towards eBGP peer r6")

    assert_no_linkbw(
        router=tgen.gears["r6"],
        peer_router_name="r1",
        peer_type="external eBGP peer r6 (route-map, non-transitive)",
        prefix=NONTRANS_PREFIX_V4,
        ipv6=False,
    )


def _test_bgp_convergence_ipv6(prefix, min_paths=2):
    """Test BGP IPv6 convergence."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Waiting for BGP IPv6 convergence")

    router = tgen.gears["r1"]

    def _bgp_converge(router):
        output = router.vtysh_cmd("show bgp ipv6 unicast {} json".format(prefix))
        if not output:
            return "No output"
        try:
            data = json.loads(output)
            if "paths" in data and len(data["paths"]) >= min_paths:
                return None
        except:
            pass
        return "Not converged"

    test_func = functools.partial(_bgp_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BGP IPv6 did not converge on r1"

    step("BGP IPv6 converged successfully")


def test_bgp_ipv6_convergence():
    """Test BGP IPv6 convergence."""
    _test_bgp_convergence_ipv6(TRANS_PREFIX_V6)


def test_bgp_convergence_nontransitive_ipv6():
    """Test BGP convergence for the non-transitive link-bandwidth test prefix (IPv6)."""
    _test_bgp_convergence_ipv6(NONTRANS_PREFIX_V6, min_paths=1)


def test_ibgp_peer_linkbw_as_ipv6():
    """Test link-bandwidth AS for iBGP peer - check what r1 receives from r2 (IPv6)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking link-bandwidth AS for iBGP peer r2 (AS 65101) - what r1 receives (IPv6)"
    )

    router_r1 = tgen.gears["r1"]

    # r2 should send link-bandwidth with local AS 65101
    # because r2 and r1 are iBGP peers (same AS)
    extcomm = validate_linkbw_as(
        router=router_r1,
        peer_router_name="r2",
        expected_as=LOCAL_AS,
        peer_type="iBGP peer r2 (IPv6)",
        prefix=TRANS_PREFIX_V6,
        ipv6=True,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r2→r1 path extended community (IPv6): {}".format(extcomm))
    step(
        "PASS: r2 (iBGP peer AS 65101, IPv6): Correctly uses local AS 65101 when sending to r1"
    )


def test_ibgp_peer_r7_linkbw_as_ipv6():
    """Test link-bandwidth AS for iBGP peer r7 (IPv6) - same sub-AS as r1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking link-bandwidth AS for iBGP peer r7 (AS 65101) - what r1 receives (IPv6)"
    )

    router_r1 = tgen.gears["r1"]

    extcomm = validate_linkbw_as(
        router=router_r1,
        peer_router_name="r7",
        expected_as=LOCAL_AS,
        peer_type="iBGP peer r7 (IPv6)",
        prefix=TRANS_PREFIX_V6,
        ipv6=True,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r7→r1 path extended community (IPv6): {}".format(extcomm))
    step(
        "PASS: r7 (iBGP peer AS 65101, IPv6): Correctly uses local AS 65101 when sending to r1"
    )


def test_confederation_peer_linkbw_as_ipv6():
    """Test link-bandwidth AS for confederation peer (r3) - IPv6."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Checking link-bandwidth AS for confederation peer r3 (AS 65102) - IPv6")

    router_r3 = tgen.gears["r3"]

    # Should use sub-AS 65101
    extcomm = validate_linkbw_as(
        router=router_r3,
        peer_router_name="r1",
        expected_as=LOCAL_AS,
        peer_type="confederation peer r3 (IPv6)",
        prefix=TRANS_PREFIX_V6,
        ipv6=True,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r1→r3 path extended community (IPv6): {}".format(extcomm))
    step("PASS: r3 (confederation peer AS 65102, IPv6): Correctly uses sub-AS 65101")


def test_confederation_peer_origination_only_linkbw_as_ipv6():
    """Test link-bandwidth AS for confederation peer (r3), origination-only route-map - IPv6."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking origination-only link-bandwidth AS for confederation peer r3 (AS 65102) - IPv6"
    )

    router_r3 = tgen.gears["r3"]

    extcomm = validate_linkbw_as(
        router=router_r3,
        peer_router_name="r1",
        expected_as=LOCAL_AS,
        peer_type="confederation peer r3 (origination-only route-map, IPv6)",
        prefix=ORIG_PREFIX_V6,
        ipv6=True,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r1→r3 origination-only path extended community (IPv6): {}".format(extcomm))
    step(
        "PASS: r3 (confederation peer AS 65102, origination-only route-map, IPv6): "
        "Correctly uses sub-AS 65101"
    )


def _test_confederation_peer_with_routemap_linkbw_as_ipv6(prefix):
    """Test link-bandwidth AS for confederation peer with route-map (r4) - IPv6."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking link-bandwidth AS for confederation peer r4 (AS 65103) with route-map - IPv6"
    )

    router_r4 = tgen.gears["r4"]

    # Should use sub-AS 65101 (route-map code path)
    extcomm = validate_linkbw_as(
        router=router_r4,
        peer_router_name="r1",
        expected_as=LOCAL_AS,
        peer_type="confederation peer r4 (route-map, IPv6)",
        prefix=prefix,
        ipv6=True,
        forbidden_as=CONFEDERATION_AS,
    )

    step("r1→r4 path extended community (IPv6): {}".format(extcomm))
    step(
        "PASS: r4 (confederation peer AS 65103, route-map, IPv6): Correctly uses sub-AS 65101"
    )


def test_confederation_peer_with_routemap_linkbw_as_ipv6():
    """Test link-bandwidth AS for confederation peer with route-map (r4) - IPv6."""
    _test_confederation_peer_with_routemap_linkbw_as_ipv6(prefix=TRANS_PREFIX_V6)


def test_confederation_peer_with_routemap_nontransitive_linkbw_as_ipv6():
    """Test link-bandwidth AS for confederation peer with non-transitive route-map (r4) - IPv6."""
    _test_confederation_peer_with_routemap_linkbw_as_ipv6(prefix=NONTRANS_PREFIX_V6)


def test_external_ebgp_peer_linkbw_as_ipv6():
    """Test link-bandwidth AS for external eBGP peer (r5) - IPv6."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Checking link-bandwidth AS for external eBGP peer r5 (AS 64001) - IPv6")

    router_r5 = tgen.gears["r5"]

    # Should use confederation AS 65100 (automatic code path)
    extcomm = validate_linkbw_as(
        router=router_r5,
        peer_router_name="r1",
        expected_as=CONFEDERATION_AS,
        peer_type="external eBGP peer r5 (IPv6)",
        prefix=TRANS_PREFIX_V6,
        ipv6=True,
    )

    step("r1→r5 path extended community (IPv6): {}".format(extcomm))
    step(
        "PASS: r5 (external eBGP AS 64001, no route-map, IPv6): Correctly uses confederation AS 65100"
    )


def test_external_ebgp_peer_origination_only_linkbw_as_ipv6():
    """Test link-bandwidth AS for external eBGP peer (r5), origination-only route-map - IPv6."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking origination-only link-bandwidth AS for external eBGP peer r5 (AS 64001) - IPv6"
    )

    router_r5 = tgen.gears["r5"]

    extcomm = validate_linkbw_as(
        router=router_r5,
        peer_router_name="r1",
        expected_as=CONFEDERATION_AS,
        peer_type="external eBGP peer r5 (origination-only route-map, IPv6)",
        prefix=ORIG_PREFIX_V6,
        ipv6=True,
        forbidden_as=LOCAL_AS,
    )

    step("r1→r5 origination-only path extended community (IPv6): {}".format(extcomm))
    step(
        "PASS: r5 (external eBGP AS 64001, origination-only route-map, IPv6): "
        "Correctly uses confederation AS 65100"
    )


def _test_external_ebgp_peer_with_routemap_linkbw_as_ipv6(prefix):
    """Test link-bandwidth AS for external eBGP peer with route-map (r6) - IPv6."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Checking link-bandwidth AS for external eBGP peer r6 (AS 64002) with route-map - IPv6"
    )

    router_r6 = tgen.gears["r6"]

    # Should use confederation AS 65100 (route-map code path)
    extcomm = validate_linkbw_as(
        router=router_r6,
        peer_router_name="r1",
        expected_as=CONFEDERATION_AS,
        peer_type="external eBGP peer r6 (route-map, IPv6)",
        prefix=prefix,
        ipv6=True,
    )

    step("r1→r6 path extended community (IPv6): {}".format(extcomm))
    step(
        "PASS: r6 (external eBGP AS 64002, route-map, IPv6): Correctly uses confederation AS 65100"
    )


def test_external_ebgp_peer_with_routemap_linkbw_as_ipv6():
    """Test link-bandwidth AS for external eBGP peer with route-map (r6) - IPv6."""
    _test_external_ebgp_peer_with_routemap_linkbw_as_ipv6(prefix=TRANS_PREFIX_V6)


def test_external_ebgp_peer_with_routemap_nontransitive_linkbw_stripped_ipv6():
    """Non-transitive link-bandwidth must not reach external eBGP peer r6 - IPv6."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Checking non-transitive link-bandwidth is stripped towards eBGP peer r6")

    assert_no_linkbw(
        router=tgen.gears["r6"],
        peer_router_name="r1",
        peer_type="external eBGP peer r6 (route-map, non-transitive)",
        prefix=NONTRANS_PREFIX_V6,
        ipv6=True,
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
