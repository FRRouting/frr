#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Test RFC 5549 BGP peering on multi-access segments.

Verify that when multiple RA sources exist on a shared VLAN segment,
BGP correctly round-robins through nbr_connected entries to find the
peer with the matching external ASN.  This exercises the per-peer
169.254.x.y mapping and the BGP FSM IMMEDIATE_RETRY round-robin
mechanism introduced for multi-access segments.

Topology:
    R1 (AS 65001) ---+
    R2 (AS 65001) ---+--- switch s1 (shared L2 segment)
    R3 (AS 65002) ---+

R1 peers via "neighbor r1-eth0 interface remote-as external".
R2 has the same ASN as R1 so any R1->R2 attempt triggers Bad Peer AS.
R3 has a different ASN so R1<->R3 should establish via round-robin.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    # Shared multi-access segment -- all three routers on one switch
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """R1 should establish BGP with R3 (AS 65002) despite R2 (same ASN) on segment."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R1 establishes eBGP with R3 (AS 65002) via round-robin")

    def _check():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp summary json")
        )
        ipv4 = output.get("ipv4Unicast", {})
        peers = ipv4.get("peers", {})
        for peer_data in peers.values():
            if peer_data.get("remoteAs") == 65002:
                if peer_data.get("state") == "Established":
                    return None
                return "R3 peer state is '{}', expected 'Established'".format(
                    peer_data.get("state")
                )
        return "No peer with remote AS 65002 found in BGP summary"

    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "R1 did not establish with R3: {}".format(result)


def test_route_learned():
    """R1 should learn R3's loopback route (10.0.3.1/32) via BGP."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R1 learns 10.0.3.1/32 from R3")

    def _check():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp 10.0.3.1/32 json")
        )
        if "paths" not in output:
            return "No paths for 10.0.3.1/32 in R1 BGP table"
        for path in output["paths"]:
            if path.get("valid") and path.get("bestpath", {}).get("overall"):
                return None
        return "No valid best path for 10.0.3.1/32"

    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 did not learn R3 loopback route: {}".format(result)


def test_r3_learns_r1_route():
    """R3 should also learn R1's loopback (10.0.1.1/32) -- bidirectional check."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R3 learns 10.0.1.1/32 from R1")

    def _check():
        output = json.loads(
            tgen.gears["r3"].vtysh_cmd("show ip bgp 10.0.1.1/32 json")
        )
        if "paths" not in output:
            return "No paths for 10.0.1.1/32 in R3 BGP table"
        for path in output["paths"]:
            if path.get("valid") and path.get("bestpath", {}).get("overall"):
                return None
        return "No valid best path for 10.0.1.1/32"

    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R3 did not learn R1 loopback route: {}".format(result)


def test_no_established_with_same_asn():
    """R1 must NOT have an Established session with R2 (same ASN via external)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R1 has no Established session with AS 65001 peer")

    output = json.loads(
        tgen.gears["r1"].vtysh_cmd("show bgp summary json")
    )
    ipv4 = output.get("ipv4Unicast", {})
    peers = ipv4.get("peers", {})
    for peer_key, peer_data in peers.items():
        if peer_data.get("remoteAs") == 65001:
            assert peer_data.get("state") != "Established", (
                "R1 established iBGP with R2 via 'remote-as external' -- "
                "should have been rejected as Bad Peer AS"
            )


def _find_ebgp_peer_data(router, remote_as):
    """Return peer_data dict for the first peer matching remote_as, or None."""
    output = json.loads(router.vtysh_cmd("show bgp summary json"))
    peers = output.get("ipv4Unicast", {}).get("peers", {})
    for peer_data in peers.values():
        if peer_data.get("remoteAs") == remote_as:
            return peer_data
    return None


def test_link_flap_recovery():
    """After link down/up, R1 must re-establish with R3 via round-robin.

    This is the primary regression test for the nbr_conn_found fix.
    Without the fix, established > 0 permanently disables round-robin
    and the peer gets stuck trying the wrong nbr_connected entry.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Bring r1-eth0 down")
    r1.cmd_raises("ip link set down dev r1-eth0")

    step("Verify R1 session with R3 drops")

    def _check_session_down():
        peer = _find_ebgp_peer_data(r1, 65002)
        if peer is None:
            return None  # peer gone from summary — down
        if peer.get("state") != "Established":
            return None
        return "R3 peer still Established after link down"

    test_func = functools.partial(_check_session_down)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session did not drop: {}".format(result)

    step("Bring r1-eth0 back up")
    r1.cmd_raises("ip link set up dev r1-eth0")

    step("Verify R1 re-establishes with R3 (AS 65002)")

    def _check_session_up():
        peer = _find_ebgp_peer_data(r1, 65002)
        if peer is None:
            return "No peer with remote AS 65002 found"
        if peer.get("state") == "Established":
            return None
        return "R3 peer state is '{}', expected 'Established'".format(
            peer.get("state")
        )

    test_func = functools.partial(_check_session_up)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, (
        "R1 did not re-establish with R3 after link flap "
        "(nbr_conn_found / round-robin bug?): {}".format(result)
    )


def test_connections_established_counter():
    """After recovery, connectionsEstablished must be >= 2.

    Proves that round-robin works even when established > 0 (the old
    bug used established == 0 as the gate condition).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify connectionsEstablished >= 2 and connectionsDropped >= 1")

    peer = _find_ebgp_peer_data(tgen.gears["r1"], 65002)
    assert peer is not None, "No peer with remote AS 65002 found"
    assert peer.get("state") == "Established", (
        "Expected Established, got '{}'".format(peer.get("state"))
    )

    conn_est = peer.get("connectionsEstablished", 0)
    conn_drop = peer.get("connectionsDropped", 0)
    step(
        "connectionsEstablished={}, connectionsDropped={}".format(
            conn_est, conn_drop
        )
    )

    assert conn_est >= 2, (
        "connectionsEstablished is {} (expected >= 2 after recovery)".format(
            conn_est
        )
    )
    assert conn_drop >= 1, (
        "connectionsDropped is {} (expected >= 1 after link flap)".format(
            conn_drop
        )
    )


def test_same_asn_rejected_after_recovery():
    """After link flap, R1 must still reject R2 (same ASN via external).

    Identical invariant to test_no_established_with_same_asn, but run
    after the link flap cycle to verify Bad Peer AS logic survives recovery.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify no Established session with AS 65001 after link flaps")

    output = json.loads(
        tgen.gears["r1"].vtysh_cmd("show bgp summary json")
    )
    ipv4 = output.get("ipv4Unicast", {})
    peers = ipv4.get("peers", {})
    for peer_key, peer_data in peers.items():
        if peer_data.get("remoteAs") == 65001:
            assert peer_data.get("state") != "Established", (
                "R1 established with same-ASN peer {} after recovery -- "
                "Bad Peer AS invariant broken".format(peer_key)
            )


def test_route_relearned_after_recovery():
    """After link flap recovery, routes must be re-exchanged bidirectionally."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R1 re-learns 10.0.3.1/32 from R3")

    def _check_r1():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp 10.0.3.1/32 json")
        )
        if "paths" not in output:
            return "No paths for 10.0.3.1/32 in R1 BGP table"
        for path in output["paths"]:
            if path.get("valid") and path.get("bestpath", {}).get("overall"):
                return None
        return "No valid best path for 10.0.3.1/32"

    test_func = functools.partial(_check_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 did not re-learn R3 route: {}".format(result)

    step("Verify R3 re-learns 10.0.1.1/32 from R1")

    def _check_r3():
        output = json.loads(
            tgen.gears["r3"].vtysh_cmd("show ip bgp 10.0.1.1/32 json")
        )
        if "paths" not in output:
            return "No paths for 10.0.1.1/32 in R3 BGP table"
        for path in output["paths"]:
            if path.get("valid") and path.get("bestpath", {}).get("overall"):
                return None
        return "No valid best path for 10.0.1.1/32"

    test_func = functools.partial(_check_r3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R3 did not re-learn R1 route: {}".format(result)


def test_rapid_flap_stability():
    """5 rapid link flap cycles must not crash bgpd or leave stale state."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Rapid flap: 5 cycles with 150ms between transitions")
    for i in range(5):
        r1.cmd_raises("ip link set down dev r1-eth0")
        time.sleep(0.15)
        r1.cmd_raises("ip link set up dev r1-eth0")
        time.sleep(0.15)

    step("Verify no daemon crash after rapid flapping")
    assert not tgen.routers_have_failure(), "Router failure after rapid flap"

    step("Verify R1 eventually re-establishes with R3")

    def _check():
        peer = _find_ebgp_peer_data(r1, 65002)
        if peer is None:
            return "No peer with remote AS 65002 found"
        if peer.get("state") == "Established":
            return None
        return "R3 peer state is '{}', expected 'Established'".format(
            peer.get("state")
        )

    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, (
        "R1 did not recover after rapid flap: {}".format(result)
    )


def test_memory_leak():
    """Standard memory leak check."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
