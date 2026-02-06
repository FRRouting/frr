#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by NVIDIA Corporation
# Mitesh Kanjariya <mkanjariya@nvidia.com>
#

"""
Test BGP Graceful Restart stale-route preservation.

These tests covers the bug fix for the issue where:
   Routes already marked BGP_PATH_STALE were incorrectly deleted during GR
   clearing instead of being re-marked stale. Removed the BGP_PATH_STALE
   check from both bgp_clear_route_node() and clearing_clear_one_pi().
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
from lib.topogen import Topogen, get_topogen
from lib.common_config import step, kill_router_daemons, start_router_daemons
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """Build topology with 10 parallel links between r5 and r6."""
    for routern in range(5, 7):
        tgen.add_router(f"r{routern}")

    # Ten switches for ten parallel eBGP sessions
    for i in range(1, 11):
        switch = tgen.add_switch(f"s{i}")
        switch.add_link(tgen.gears["r5"])  # r5-eth0 through r5-eth9
        switch.add_link(tgen.gears["r6"])  # r6-eth0 through r6-eth9


def setup_module(mod):
    """Set up the pytest environment."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _add_static_routes(router, count, base="10.0"):
    """Add 'count' /32 static routes via vtysh on 'router'.

    Routes are 10.0.0.0/32, 10.0.0.1/32, ..., 10.0.0.255/32,
    10.0.1.0/32, 10.0.1.1/32, ... etc.
    """
    cfg = "configure terminal\n"
    for i in range(count):
        third = i // 256
        fourth = i % 256
        cfg += f"ip route {base}.{third}.{fourth}/32 Null0\n"
    cfg += "end\n"
    router.vtysh_cmd(cfg)


def _verify_single_peer_established(r6, peer_ip):
    """Verify a single BGP peer is Established."""
    output = json.loads(
        r6.vtysh_cmd(f"show bgp ipv4 neighbors {peer_ip} json")
    )
    n = output.get(peer_ip, {})
    if n.get("bgpState") != "Established":
        return f"Peer {peer_ip} state: {n.get('bgpState')}"
    return None


def _verify_peer_not_established(router, peer_ip):
    """Return None when peer is not Established (peer down); else error string."""
    output = json.loads(
        router.vtysh_cmd(f"show bgp ipv4 neighbors {peer_ip} json")
    )
    n = output.get(peer_ip, {})
    if n.get("bgpState") == "Established":
        return f"Peer {peer_ip} still Established"
    return None


def _verify_prefix_count(r6, expected_count, base="10.0"):
    """Verify that r6 has exactly expected_count prefixes matching base."""
    output = json.loads(r6.vtysh_cmd("show bgp ipv4 unicast json"))
    routes = output.get("routes", {})
    count = 0
    for prefix in routes:
        if prefix.startswith(base + "."):
            count += 1
    if count != expected_count:
        return f"Prefix count {count} != expected {expected_count}"
    return None


def _verify_prefix_count_stable(r6, expected_count, num_polls=5, poll_interval=0.4, base="10.0"):
    """
    Verify prefix count is expected_count on every poll over a short window.
    Use after peer-down so we only pass once clearing has had time to run
    and routes are still present (avoids race with async clearing).
    """
    for i in range(num_polls):
        err = _verify_prefix_count(r6, expected_count, base=base)
        if err is not None:
            return f"{err} (poll {i + 1}/{num_polls})"
        if i < num_polls - 1:
            time.sleep(poll_interval)
    return None


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_bgp_gr_enhanced_refresh_then_kill():
    """
    Triggers enhanced-refresh (BoRR) to mark routes stale, then kills
    bgpd on r5 before EoRR completes. The already-stale routes must be
    preserved for the GR cycle rather than deleted.

    Uses only one BGP peer (10.10.10.1) to ensure all routes come from
    that peer and get marked stale by route refresh.

    Expectation is that the already-stale routes are preserved for the GR cycle.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r5 = tgen.gears["r5"]
    r6 = tgen.gears["r6"]
    route_count = 10

    step("Wait for peer 10.10.10.1 to establish")
    test_func = functools.partial(_verify_single_peer_established, r6, "10.10.10.1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, f"Session not established: {result}"

    step(f"Add {route_count} static routes on r5")
    _add_static_routes(r5, route_count)

    step(f"Wait for r6 to receive all {route_count} prefixes")
    test_func = functools.partial(_verify_prefix_count, r6, route_count)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Route count mismatch: {result}"

    step("Trigger enhanced-refresh on r6 for peer 10.10.10.1 (marks routes stale via BoRR)")
    r6.vtysh_cmd("clear bgp 10.10.10.1 soft in")

    step("Immediately kill bgpd on r5 (before EoRR completes)")
    kill_router_daemons(tgen, "r5", ["bgpd"])

    step("Wait for r6 to see peer down")
    test_func = functools.partial(_verify_peer_not_established, r6, "10.10.10.1")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assert result is None, f"Peer did not go down: {result}"

    step("Verify routes remain present (no race with clearing)")
    result = _verify_prefix_count_stable(r6, route_count, num_polls=5, poll_interval=0.4)
    assert result is None, f"Routes were deleted or not stable: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
