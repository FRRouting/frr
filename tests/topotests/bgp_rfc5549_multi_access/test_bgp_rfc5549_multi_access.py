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

Every router has "ipv6 nd multi-access" on its segment interface.
R1 peers via "neighbor r1-eth0 interface remote-as external".
R2 has the same ASN as R1 so any R1->R2 attempt triggers Bad Peer AS.
R2's remote-as matches nobody, so R3 (itself one unnumbered peer) cannot
end up with R2 instead of R1.
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

    step("R2 has its passive unnumbered neighbor, remote-as 65099")
    output = json.loads(tgen.gears["r2"].vtysh_cmd("show bgp neighbors r2-eth0 json"))
    p = output.get("r2-eth0", {})
    assert p.get("remoteAs") == 65099, output
    assert p.get("bgpState") != "Established", p.get("bgpState")
    out = tgen.gears["r2"].vtysh_cmd("show running-config bgpd")
    assert "neighbor r2-eth0 passive" in out, out


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

    step("Only one neighbor passed remote-as on R1 and R3: not ambiguous")
    for rname in ["r1", "r3"]:
        iface = "{}-eth0".format(rname)
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp neighbors {} json".format(iface))
        )
        p = output.get(iface, {})
        assert "multiAccessAmbiguous" not in p, "{} ambiguous: {}".format(
            rname, p.get("remoteAsMatchedNeighbors")
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


def _ipv4ll_neighbors(router):
    out = json.loads(router.cmd("ip -4 -j neigh show dev r1-eth0"))
    return sorted(n["dst"] for n in out if n["dst"].startswith("169.254."))


def _wait_r3_established(r1, seconds):
    def _check():
        peer = _find_ebgp_peer_data(r1, 65002)
        if peer and peer.get("state") == "Established":
            return None
        return "R3 peer: {}".format(peer and peer.get("state"))

    _, result = topotest.run_and_expect(_check, None, count=seconds, wait=1)
    assert result is None, result


def test_multi_access_off_is_stock():
    """Without "ipv6 nd multi-access" r1-eth0 is point-to-point, as in
    stock FRR: one neighbor that each new RA source replaces.  An
    Established session must survive RAs from another source."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("One 169.254.0.1 neighbor with multi-access on")
    assert _ipv4ll_neighbors(r1) == ["169.254.0.1"], _ipv4ll_neighbors(r1)

    step("Only R3 on the segment: R2 down, r1-eth0 flapped to forget R2")
    r2.cmd_raises("ip link set down dev r2-eth0")
    r1.cmd_raises("ip link set down dev r1-eth0")
    r1.cmd_raises("ip link set up dev r1-eth0")
    _wait_r3_established(r1, 60)

    step("no ipv6 nd multi-access on r1: R3, the only neighbor, is kept")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nno ipv6 nd multi-access")
    _wait_r3_established(r1, 30)

    step("R2 back: its RAs replace r1's neighbor, the session stays up")
    dropped = _find_ebgp_peer_data(r1, 65002).get("connectionsDropped")
    r2.cmd_raises("ip link set up dev r2-eth0")
    time.sleep(15)
    peer = _find_ebgp_peer_data(r1, 65002)
    assert peer.get("state") == "Established", peer.get("state")
    assert peer.get("connectionsDropped") == dropped, (
        "Session dropped without multi-access: {} -> {}".format(
            dropped, peer.get("connectionsDropped")
        )
    )
    assert _ipv4ll_neighbors(r1) == ["169.254.0.1"], _ipv4ll_neighbors(r1)

    step("ipv6 nd multi-access again: R1 stays with R3")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nipv6 nd multi-access")
    _wait_r3_established(r1, 60)


# Bad Peer AS entries are skipped for this long (BGP_NBR_CONN_BAD_HOLD)
BAD_HOLD = 120
R2_FIXED_AS = 65003


def _link_local(router, iface):
    out = json.loads(router.cmd("ip -6 -j addr show dev {} scope link".format(iface)))
    return out[0]["addr_info"][0]["local"]


def _r1_peer(r1):
    output = json.loads(r1.vtysh_cmd("show bgp neighbors r1-eth0 json"))
    return output.get("r1-eth0", {})


def _wait_r2_skipped(r1, r2_ll, asn):
    """Wait for R1 to skip R2 for Bad Peer AS; return the seconds left.
    asn is the AS R2 announced, or None when R1 may not have seen R2's
    OPEN (R2 rejected R1 first)."""

    def _check():
        for e in _r1_peer(r1).get("badPeerAsNeighbors", []):
            if e["neighbor"] == r2_ll and e.get("remoteAs") in (asn, None):
                return e
        return None

    _, entry = topotest.run_and_expect_type(_check, dict, count=60, wait=1)
    assert isinstance(entry, dict), "R1 does not skip {}: {}".format(
        r2_ll, _r1_peer(r1).get("badPeerAsNeighbors")
    )
    assert 0 < entry["expiresIn"] <= BAD_HOLD, entry
    out = r1.vtysh_cmd("show bgp neighbors r1-eth0")
    assert "Skipped neighbors (Bad Peer AS): {} (".format(r2_ll) in out, out
    assert "expires in" in out, out
    return entry["expiresIn"]


def _wait_r1_established_with(r1, asn, seconds):
    def _check():
        p = _r1_peer(r1)
        if p.get("bgpState") == "Established" and p.get("remoteAs") == asn:
            return None
        return "{} remoteAs={}".format(p.get("bgpState"), p.get("remoteAs"))

    _, result = topotest.run_and_expect(_check, None, count=seconds, wait=1)
    assert result is None, "R1 not Established with AS {}: {}".format(asn, result)


def _r2_config(old_as, new_as, neighbor):
    """Replace R2's BGP instance: AS new_as, active, its unnumbered peer
    configured with neighbor (the rest of the command)."""
    return (
        "configure terminal\nno router bgp {}\nrouter bgp {}\n"
        "no bgp ebgp-requires-policy\ntimers bgp 3 9\n"
        "neighbor r2-eth0 interface {}\nneighbor r2-eth0 timers connect 1"
    ).format(old_as, new_as, neighbor)


def test_bad_peer_as_new_as_retried_at_once():
    """R2 is misconfigured with R1's AS, so R1 sends it Bad Peer AS; then
    its AS is fixed.  As soon as its OPEN announces the new AS, R1 forgets
    it and the session comes up, within the hold time and with no change
    on R1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]
    r2_ll = _link_local(r2, "r2-eth0")

    step("Shut R3's session; R2 (AS 65001) accepts R1, R1 rejects R2")
    r3.vtysh_cmd("configure terminal\nrouter bgp 65002\nneighbor r3-eth0 shutdown")
    r2.vtysh_cmd(_r2_config(65001, 65001, "remote-as internal"))
    # Forget entries from earlier tests: the hold time starts now
    r1.cmd_raises("ip link set down dev r1-eth0")
    r1.cmd_raises("ip link set up dev r1-eth0")
    left = _wait_r2_skipped(r1, r2_ll, 65001)

    step("R2 moves to AS {}; R1 establishes with it in time".format(R2_FIXED_AS))
    start = time.time()
    r2.vtysh_cmd(_r2_config(65001, R2_FIXED_AS, "remote-as 65001"))
    _wait_r1_established_with(r1, R2_FIXED_AS, max(left - 5, 5))
    assert time.time() - start < left, "Took longer than the hold time"
    assert "badPeerAsNeighbors" not in _r1_peer(r1)


def test_bad_peer_as_same_as_retried_after_hold():
    """R2 rejects R1 (wrong remote-as), then its remote-as is fixed: it
    announces the same AS as before, so R1 keeps skipping it until the
    entry expires, then the session comes up with no change on R1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]
    r2_ll = _link_local(r2, "r2-eth0")

    step("R2's remote-as no longer matches R1: it sends Bad Peer AS")
    r2.vtysh_cmd(_r2_config(R2_FIXED_AS, R2_FIXED_AS, "remote-as 65099"))
    left = _wait_r2_skipped(r1, r2_ll, R2_FIXED_AS)

    step("Fix R2's remote-as: R1 establishes only once the entry expires")
    start = time.time()
    r2.vtysh_cmd(_r2_config(R2_FIXED_AS, R2_FIXED_AS, "remote-as 65001"))
    # R2 may have refreshed the entry since left was read: up to a full hold
    _wait_r1_established_with(r1, R2_FIXED_AS, BAD_HOLD + 60)
    elapsed = time.time() - start
    assert elapsed >= left - 5, "Up after {:.0f}s, {}s before expiry".format(
        elapsed, left
    )


def test_bad_peer_as_reset_by_operator():
    """A hard "clear bgp" or "neighbor shutdown" on R1 forgets the Bad Peer
    AS entries: R2, fixed but announcing the same AS, gets the session at
    once instead of after the hold time."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]
    r2_ll = _link_local(r2, "r2-eth0")

    for name, cmds in [
        ("clear bgp r1-eth0", ["clear bgp r1-eth0"]),
        (
            "neighbor shutdown",
            [
                "configure terminal\nrouter bgp 65001\nneighbor r1-eth0 shutdown",
                "configure terminal\nrouter bgp 65001\nno neighbor r1-eth0 shutdown",
            ],
        ),
    ]:
        step("R2 sends Bad Peer AS, then is fixed with the same AS")
        r2.vtysh_cmd(_r2_config(R2_FIXED_AS, R2_FIXED_AS, "remote-as 65099"))
        left = _wait_r2_skipped(r1, r2_ll, R2_FIXED_AS)
        r2.vtysh_cmd(_r2_config(R2_FIXED_AS, R2_FIXED_AS, "remote-as 65001"))

        step("{} on R1 empties the list; R1 establishes with R2".format(name))
        start = time.time()
        for cmd in cmds:
            r1.vtysh_cmd(cmd)
        assert "badPeerAsNeighbors" not in _r1_peer(r1), _r1_peer(r1)
        _wait_r1_established_with(r1, R2_FIXED_AS, 30)
        elapsed = time.time() - start
        assert elapsed < left - 30, "Up after {:.0f}s, hold {}s".format(elapsed, left)
        assert "badPeerAsNeighbors" not in _r1_peer(r1)

    step("Restore R2 and R3; R1 goes back to R3")
    r2.vtysh_cmd(
        "configure terminal\nno router bgp {}\nrouter bgp 65001\n"
        "no bgp ebgp-requires-policy\n"
        "neighbor r2-eth0 interface remote-as 65099\n"
        "neighbor r2-eth0 passive".format(R2_FIXED_AS)
    )
    r3.vtysh_cmd("configure terminal\nrouter bgp 65002\nno neighbor r3-eth0 shutdown")
    _wait_r3_established(r1, 120)


def test_memory_leak():
    """Standard memory leak check."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
