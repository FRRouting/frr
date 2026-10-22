#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_hello_neighbor_identity.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#

r"""
test_ospf_hello_neighbor_identity.py
====================================

Regression test for the silent OSPF neighbor identity rewrite in ospfd
(B4: forged Hello tears down an adjacency and/or relabels a Full
neighbor's router ID).

ospf_nbr_get() unconditionally executed ``nbr->router_id =
ospfh->router_id`` for every Hello.  On broadcast networks neighbors
are keyed by source address, so a forged Hello that spoofed the source
address of an established Full neighbor but carried a different router
ID silently rewrote the neighbor's identity: no FSM restart, no log,
the old Full state and the retransmission/request queues stayed
attached under the attacker's router ID.

RFC 2328 section 10.3 mandates the OneWayReceived transition (a Hello
that does not list our router ID must drop the adjacency back to Init);
that behavior is specification-mandated and is exercised here as a
control, not changed by the fix.

Topology
--------

    r1 (victim, RID 10.255.4.1, DR on the LAN)
      |
      +-- eth0 --+            +-- eth0 -- r2 (peer, RID 10.255.4.2,
      |           \          /              DROther on the LAN,
      |            +-- s1 --+               loopback 198.18.4.2/32)
      |
      +-- eth1 ------------------------- eth1 -- r2
         (point-to-point link, 10.244.5.0/29)

r1 and r2 share one broadcast segment (10.244.4.0/24, DR/DROther) and
one point-to-point link (10.244.5.0/29).  All triggers are injected
from r2's namespace with scapy: the Ethernet/IP source is r2's own,
only the OSPF router ID and the neighbor list are forged.  Each
injection is captured on the wire (pcap under tgen.logdir); r1's
receipt is cross-checked through the per-interface helloIn counter and
the ospfd log.

Test plan
---------

1. test_adjacency_full
     Baseline: LAN adjacency Full (r1 sees DROther, r2 sees DR), p2p
     adjacency Full, route to 198.18.4.2/32 present on r1.

2. test_lan_no_attack_control
     Without injection the Full adjacency stays up.

3. test_lan_invalid_checksum_control
     A Hello with a corrupted OSPF checksum is dropped before Hello
     processing: no state change, no 1-WayReceived.

4. test_lan_one_way_teardown_rfc2328
     A valid Hello that omits r1's router ID triggers the RFC 2328
     section 10.3 OneWayReceived transition Full -> Init, logged, and
     the adjacency recovers.  This specification-mandated teardown must
     keep working with the fix.

5. test_lan_same_rid_two_way_control
     A valid two-way Hello carrying the neighbor's own router ID has
     no effect (the fix must not fire on ordinary Hellos).

6. test_lan_rogue_rid_identity_change
     A valid two-way Hello from r2's address but with a rogue router ID
     must not silently relabel the Full neighbor.  The identity change
     is handled explicitly: the stale neighbor is torn down with a
     warning, the rogue ID never appears in the neighbor table, and
     the adjacency re-establishes with the original router ID.
     Before the fix the Full neighbor was silently relabeled to the
     rogue router ID with no FSM restart, no log and preserved uptime.

7. test_p2p_same_rid_control
     On the point-to-point link (neighbors keyed by router ID) an
     ordinary two-way Hello keeps the adjacency Full.

8. test_p2p_same_rid_alt_src
     Point-to-point neighbors are identified by router ID (RFC 2328
     section 10.5): a two-way Hello with the peer's router ID from a
     different source address still refreshes the same neighbor; the
     adjacency stays Full with the original address.

9. test_p2p_one_way_rogue_rid
     A rogue-router-ID Hello on the p2p link creates a separate
     neighbor entry; it must never touch the Full adjacency with the
     peer's real router ID and never reach Full itself.

10. test_final_full_convergence
     Both adjacencies Full and the route present at the end; daemons
     alive.
"""

import json
import os
import shlex
import sys
import time
from functools import partial

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]

R1 = "r1"
R2 = "r2"
LAN_IF = "eth0"
P2P_IF = "eth1"
R1_LAN_IP = "10.244.4.1"
R2_LAN_IP = "10.244.4.2"
R1_P2P_IP = "10.244.5.1"
R2_P2P_IP = "10.244.5.2"
R2_P2P_ALT_IP = "10.244.5.3"
R1_RID = "10.255.4.1"
R2_RID = "10.255.4.2"
ROGUE_RID = "10.255.4.254"
R2_LOOPBACK = "198.18.4.2"
HELLO_INTERVAL = 2
DEAD_INTERVAL = 6
ADJACENCY_TIMEOUT = 30
CONTROL_DURATION = 1.5
TRIGGER_TIMEOUT = 10.0


def build_topo(tgen):
    r1 = tgen.add_router(R1)
    r2 = tgen.add_router(R2)
    s1 = tgen.add_switch("s1")
    tgen.add_link(r1, s1, ifname1=LAN_IF, ifname2="eth0")
    tgen.add_link(r2, s1, ifname1=LAN_IF, ifname2="eth1")
    tgen.add_link(r1, r2, ifname1=P2P_IF, ifname2=P2P_IF)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _wait_until(func, timeout=15, interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = func()
        if value:
            return value
        time.sleep(interval)
    return func()


def _vty_json(router, command):
    return json.loads(router.vtysh_cmd(command))


def _neighbor_entries(router, source_ip):
    """Neighbor JSON entries whose interface address matches source_ip."""
    raw = _vty_json(router, "show ip ospf neighbor json")
    entries = []
    for router_id, values in raw.get("neighbors", {}).items():
        for value in values:
            if value.get("ifaceAddress") == source_ip:
                entries.append({"router_id": router_id, **value})
    return entries, raw


def _one_full(entries, router_id, role=None):
    if len(entries) != 1:
        return False
    entry = entries[0]
    return (
        entry.get("router_id") == router_id
        and entry.get("converged") == "Full"
        and (role is None or entry.get("role") == role)
    )


def _route_present(router):
    return bool(router.cmd("ip -4 route show %s" % R2_LOOPBACK).strip())


def _hello_in(router, ifname):
    data = _vty_json(router, "show ip ospf interface traffic %s json" % ifname)
    return data[ifname]["helloIn"]


def _iface_mac(node, ifname):
    return node.cmd("cat /sys/class/net/%s/address" % ifname).strip()


def _ospfd_pid(router):
    return router.cmd("pidof ospfd || true").strip()


def _sync_peer_hello(r1, ifname):
    """Wait until the peer's periodic Hello just went out.

    The unpatched daemon relabels the neighbor back to the real router
    ID as soon as the peer's next periodic Hello arrives, so the rogue
    identity is only observable until then.  Syncing on the peer's
    Hello guarantees the full Hello interval of observation window.
    """
    before = _hello_in(r1, ifname)
    _wait_until(lambda: _hello_in(r1, ifname) > before, timeout=4, interval=0.05)


def _log_offset(router):
    path = os.path.join(router.gearlogdir, "ospfd.out")
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _log_since(router, offset):
    path = os.path.join(router.gearlogdir, "ospfd.out")
    try:
        with open(path, errors="replace") as logf:
            logf.seek(offset)
            return logf.read()
    except OSError:
        return ""


def _interesting_log(text):
    tokens = (
        "State change",
        "AdjChg:",
        "1-WayReceived",
        "Header check failed",
        "router ID changed",
        ROGUE_RID,
    )
    return [line for line in text.splitlines() if any(t in line for t in tokens)]


def _inject_hello(
    r2,
    r1,
    label,
    ifname,
    packet_rid,
    neighbor_rids,
    src_ip,
    dr="0.0.0.0",
    corrupt_checksum=False,
):
    """Send one forged Hello from r2 and prove it hit the wire.

    Returns the phase dict with the send/capture evidence, r1's
    helloIn delta and the ospfd log delta for this injection.
    """
    tgen = get_topogen()
    pcap = os.path.join(tgen.logdir, "%s.pcap" % label)
    r2.cmd("rm -f %s" % shlex.quote(pcap))
    hello_before = _hello_in(r1, ifname)
    offset = _log_offset(r1)
    cmd = (
        "python3 %s/send_hello.py --iface %s --src-mac %s --src-ip %s "
        "--packet-rid %s --hello-interval %d --dead-interval %d "
        "--priority 0 --dr %s --bdr 0.0.0.0 --neighbors %s %s--pcap %s"
        % (
            shlex.quote(CWD),
            shlex.quote(ifname),
            shlex.quote(_iface_mac(r2, ifname)),
            shlex.quote(src_ip),
            shlex.quote(packet_rid),
            HELLO_INTERVAL,
            DEAD_INTERVAL,
            shlex.quote(dr),
            shlex.quote(",".join(neighbor_rids)),
            "--corrupt-checksum " if corrupt_checksum else "",
            shlex.quote(pcap),
        )
    )
    out = r2.cmd_raises(cmd)
    markers = [line for line in out.splitlines() if line.startswith("B4_SEND_JSON=")]
    assert markers, "send_hello.py returned no result for %s: %s" % (label, out)
    send = json.loads(markers[-1].split("=", 1)[1])
    assert (
        send["captured"] == 1
    ), "forged Hello %s was not captured exactly once on the wire: %s" % (label, send)
    hello_delta = _hello_in(r1, ifname) - hello_before
    log = _log_since(r1, offset)
    phase = {
        "label": label,
        "send": send,
        "hello_in_delta": hello_delta,
        "log": log,
        "interesting_log": _interesting_log(log),
    }
    logger.info(
        "injected %s: packet_rid=%s neighbors=%s corrupt=%s captured=%d "
        "hello_in_delta=%d",
        label,
        packet_rid,
        neighbor_rids,
        corrupt_checksum,
        send["captured"],
        hello_delta,
    )
    for line in phase["interesting_log"][-12:]:
        logger.info("r1 ospfd: %s", line)
    return phase


def _observe(r1, source_ip, duration, stop_predicate=None, interval=0.05):
    """Sample the neighbor table, recording every signature change."""
    started = time.monotonic()
    deadline = started + duration
    samples = []
    last_signature = None
    condition_met = False
    while True:
        entries, _ = _neighbor_entries(r1, source_ip)
        signature = tuple(
            sorted(
                (entry.get("router_id"), entry.get("converged"), entry.get("role"))
                for entry in entries
            )
        )
        condition = stop_predicate(entries) if stop_predicate else False
        if signature != last_signature or condition:
            samples.append(
                {
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                    "neighbors": entries,
                }
            )
            last_signature = signature
        if condition:
            condition_met = True
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(interval)
    return {
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "samples": samples,
        "condition_met": condition_met,
    }


def _compact(entries):
    return [
        {
            key: entry.get(key)
            for key in (
                "router_id",
                "converged",
                "role",
                "ifaceAddress",
                "upTimeInMsec",
                "linkStateRetransmissionListCounter",
                "linkStateRequestListCounter",
                "databaseSummaryListCounter",
            )
        }
        for entry in entries
    ]


def _observation_has(observation, router_id, state):
    for sample in observation["samples"]:
        for entry in sample["neighbors"]:
            if entry.get("router_id") == router_id and entry.get("converged") == state:
                return True
    return False


def _observation_stays_full(observation, router_id):
    return bool(observation["samples"]) and all(
        _one_full(sample["neighbors"], router_id) for sample in observation["samples"]
    )


def _wait_full(r1, source_ip, router_id, role=None, timeout=ADJACENCY_TIMEOUT):
    def check():
        entries, _ = _neighbor_entries(r1, source_ip)
        return _one_full(entries, router_id, role)

    return bool(_wait_until(check, timeout=timeout, interval=0.2))


def _expect_baseline():
    tgen = get_topogen()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    assert _wait_full(
        r1, R2_LAN_IP, R2_RID, role="DROther"
    ), "LAN adjacency did not reach Full/DROther: %s" % _compact(
        _neighbor_entries(r1, R2_LAN_IP)[0]
    )
    assert _wait_full(
        r1, R2_P2P_IP, R2_RID
    ), "p2p adjacency did not reach Full on r1: %s" % _compact(
        _neighbor_entries(r1, R2_P2P_IP)[0]
    )
    assert _wait_full(
        r2, R1_LAN_IP, R1_RID, role="DR"
    ), "LAN adjacency did not reach Full/DR on r2: %s" % _compact(
        _neighbor_entries(r2, R1_LAN_IP)[0]
    )
    assert _wait_full(
        r2, R1_P2P_IP, R1_RID
    ), "p2p adjacency did not reach Full on r2: %s" % _compact(
        _neighbor_entries(r2, R1_P2P_IP)[0]
    )
    assert _wait_until(
        lambda: _route_present(r1), timeout=ADJACENCY_TIMEOUT, interval=0.5
    ), ("route to %s missing on r1" % R2_LOOPBACK)


def test_adjacency_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()


def test_lan_no_attack_control():
    """Without injection the Full LAN adjacency stays up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    observation = _observe(r1, R2_LAN_IP, 2.0, interval=0.2)
    assert _observation_stays_full(
        observation, R2_RID
    ), "untriggered LAN adjacency was unstable: %s" % _compact(
        observation["samples"][-1]["neighbors"]
    )
    assert _route_present(r1), "route to %s vanished without injection" % R2_LOOPBACK


def test_lan_invalid_checksum_control():
    """A Hello with a corrupted OSPF checksum must have no effect."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    phase = _inject_hello(
        r2,
        r1,
        "lan_invalid_checksum_one_way",
        LAN_IF,
        R2_RID,
        [],
        R2_LAN_IP,
        dr=R1_LAN_IP,
        corrupt_checksum=True,
    )
    observation = _observe(r1, R2_LAN_IP, CONTROL_DURATION, interval=0.1)
    assert "1-WayReceived" not in phase["log"], (
        "corrupted-Checksum Hello triggered 1-WayReceived: %s"
        % phase["interesting_log"]
    )
    assert _observation_stays_full(
        observation, R2_RID
    ), "corrupted-Checksum Hello disturbed the Full adjacency: %s" % _compact(
        observation["samples"][-1]["neighbors"]
    )


def test_lan_one_way_teardown_rfc2328():
    """RFC 2328 section 10.3: a one-way Hello drops Full -> Init (kept)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    phase = _inject_hello(
        r2,
        r1,
        "lan_valid_one_way_omission",
        LAN_IF,
        R2_RID,
        [],
        R2_LAN_IP,
        dr=R1_LAN_IP,
    )
    assert "Full -> Init (1-WayReceived)" in phase["log"], (
        "one-way Hello did not produce the RFC 2328 10.3 Full -> Init "
        "transition in the log (hello_in_delta=%d): %s"
        % (phase["hello_in_delta"], phase["interesting_log"])
    )
    assert phase["hello_in_delta"] >= 1, (
        "one-way Hello was captured on the wire but r1 receipt not verified "
        "(hello_in_delta=0)"
    )
    assert _wait_full(
        r1, R2_LAN_IP, R2_RID, role="DROther"
    ), "LAN adjacency did not recover after the one-way teardown: %s" % _compact(
        _neighbor_entries(r1, R2_LAN_IP)[0]
    )


def test_lan_same_rid_two_way_control():
    """A two-way Hello with the neighbor's own router ID has no effect."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    phase = _inject_hello(
        r2,
        r1,
        "lan_valid_two_way_same_rid",
        LAN_IF,
        R2_RID,
        [R1_RID],
        R2_LAN_IP,
        dr=R1_LAN_IP,
    )
    observation = _observe(r1, R2_LAN_IP, CONTROL_DURATION, interval=0.1)
    assert phase["hello_in_delta"] >= 1, (
        "same-RID control Hello was captured on the wire but r1 receipt "
        "not verified (hello_in_delta=0)"
    )
    assert _observation_stays_full(
        observation, R2_RID
    ), "same-RID two-way control Hello disturbed the Full adjacency: %s" % _compact(
        observation["samples"][-1]["neighbors"]
    )
    assert not _observation_has(observation, ROGUE_RID, "Full")


def test_lan_rogue_rid_identity_change():
    """A two-way Hello with a rogue router ID must not relabel the Full
    neighbor: the identity change is handled explicitly (teardown with a
    warning), the rogue ID never appears, and the original identity
    re-establishes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    assert _one_full(
        _neighbor_entries(r1, R2_LAN_IP)[0], R2_RID, role="DROther"
    ), "identity trigger requires an established Full neighbor first"

    _sync_peer_hello(r1, LAN_IF)
    phase = _inject_hello(
        r2,
        r1,
        "lan_valid_two_way_rogue_rid",
        LAN_IF,
        ROGUE_RID,
        [R1_RID],
        R2_LAN_IP,
        dr=R1_LAN_IP,
    )
    assert (
        phase["hello_in_delta"] >= 1 or ROGUE_RID in phase["log"]
    ), "rogue-RID Hello was captured on the wire but r1 receipt not verified"
    observation = _observe(
        r1,
        R2_LAN_IP,
        TRIGGER_TIMEOUT,
        stop_predicate=lambda entries: _one_full(entries, R2_RID, role="DROther"),
        interval=0.05,
    )
    rogue_samples = [
        _compact(sample["neighbors"])
        for sample in observation["samples"]
        if any(entry.get("router_id") == ROGUE_RID for entry in sample["neighbors"])
    ]
    assert not rogue_samples, (
        "rogue router ID %s appeared in the neighbor table after a forged "
        "Hello from %s (silent identity rewrite): %s"
        % (ROGUE_RID, R2_LAN_IP, rogue_samples)
    )
    assert not _observation_has(
        observation, ROGUE_RID, "Full"
    ), "rogue router ID %s reached Full (silent identity rewrite): %s" % (
        ROGUE_RID,
        rogue_samples,
    )
    assert observation["condition_met"], (
        "adjacency did not re-establish Full with the original router ID "
        "%s after the identity change: %s"
        % (R2_RID, [_compact(sample["neighbors"]) for sample in observation["samples"]])
    )
    assert "router ID changed" in phase["log"], (
        "identity change was not handled explicitly (no 'router ID changed' "
        "warning in the ospfd log): %s" % phase["interesting_log"]
    )
    assert "AdjChg:" in phase["log"] or "State change" in phase["log"], (
        "stale neighbor teardown was not logged: %s" % phase["interesting_log"]
    )


def test_p2p_same_rid_control():
    """On p2p an ordinary two-way Hello keeps the adjacency Full."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    phase = _inject_hello(
        r2, r1, "p2p_two_way_same_rid", P2P_IF, R2_RID, [R1_RID], R2_P2P_IP
    )
    observation = _observe(r1, R2_P2P_IP, CONTROL_DURATION, interval=0.1)
    assert phase["hello_in_delta"] >= 1, (
        "p2p same-RID control Hello was captured on the wire but r1 receipt "
        "not verified (hello_in_delta=0)"
    )
    assert _observation_stays_full(
        observation, R2_RID
    ), "p2p same-RID control Hello disturbed the Full adjacency: %s" % _compact(
        observation["samples"][-1]["neighbors"]
    )


def test_p2p_same_rid_alt_src():
    """RFC 2328 section 10.5: p2p neighbors are identified by router ID;
    a two-way Hello with the peer's router ID from another source address
    still refreshes the same Full neighbor."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    phase = _inject_hello(
        r2, r1, "p2p_two_way_same_rid_alt_src", P2P_IF, R2_RID, [R1_RID], R2_P2P_ALT_IP
    )
    observation = _observe(r1, R2_P2P_IP, CONTROL_DURATION, interval=0.1)
    assert phase["hello_in_delta"] >= 1, (
        "p2p alt-src Hello was captured on the wire but r1 receipt not "
        "verified (hello_in_delta=0)"
    )
    assert _observation_stays_full(
        observation, R2_RID
    ), "p2p alt-src same-RID Hello disturbed the Full adjacency: %s" % _compact(
        observation["samples"][-1]["neighbors"]
    )
    entries, _ = _neighbor_entries(r1, R2_P2P_IP)
    assert (
        len(entries) == 1 and entries[0].get("router_id") == R2_RID
    ), "p2p neighbor identity changed after alt-src Hello: %s" % _compact(entries)


def test_p2p_one_way_rogue_rid():
    """A rogue-router-ID Hello on the p2p link must not touch the Full
    adjacency keyed by the peer's real router ID."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    phase = _inject_hello(
        r2, r1, "p2p_one_way_rogue_rid", P2P_IF, ROGUE_RID, [], R2_P2P_IP
    )
    assert phase["hello_in_delta"] >= 1 or ROGUE_RID in phase["log"], (
        "p2p rogue-RID Hello was captured on the wire but r1 receipt not " "verified"
    )
    observation = _observe(r1, R2_P2P_IP, 3.0, interval=0.1)
    # The rogue neighbor is keyed by its own router ID but carries the
    # same interface address, so entries may hold both identities; the
    # real one must stay Full in every sample.
    real_full = [
        any(
            entry.get("router_id") == R2_RID and entry.get("converged") == "Full"
            for entry in sample["neighbors"]
        )
        for sample in observation["samples"]
    ]
    assert all(real_full), "p2p rogue-RID Hello disturbed the Full adjacency: %s" % [
        _compact(sample["neighbors"]) for sample in observation["samples"]
    ]
    assert not _observation_has(observation, ROGUE_RID, "Full"), (
        "rogue router ID %s reached Full on the p2p link" % ROGUE_RID
    )


def test_final_full_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    assert _ospfd_pid(r1), "ospfd not running on r1"
    assert _ospfd_pid(r2), "ospfd not running on r2"
    _expect_baseline()
