#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_fightback_pacing.py
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_ospf_fightback_pacing.py
=============================

Regression for unbounded OSPF fight-back refresh/flooding (B1).

RFC 2328 Section 13.4 requires a router that receives a newer instance
of its own self-originated LSA to re-originate it with a sequence
number one past the received one (the "fight-back").  Section 12.4
bounds successive originations of the same LSA by MinLSInterval.  An
unpatched ospfd refreshed synchronously in the receive path: every
forged self-originated LSA triggered an immediate router-LSA
regeneration plus area-wide flooding, so an on-link attacker injecting
forged LSAs at line rate produced an unbounded refresh/flooding storm
(plus SPF on every router) regardless of MinLSInterval.

Topology (same roles as the original reproducer
topo-fuzz test/manul/ospf_b1_fightback_rate.py)
-----------------------------------------------

    r1 (victim, was rB1t) ---- r1-eth0 ---- s1 ---- r2-eth0 ---- r2 (attacker, was rB1p)

r1: router-id 1.1.1.1, 10.211.12.1/24; r2: router-id 2.2.2.2,
10.211.12.2/24.  Both run `timers throttle lsa all 5000`, so
MinLSInterval is 5000 ms.  r2 injects unicast OSPF LSUs (TTL 1,
protocol 89) whose single router-LSA claims r1 as advertising router
with a sequence number two past r1's current one; the burst carries 8
LSAs spaced 200 ms apart.

Test plan
---------

1. test_adjacency_and_min_ls_interval
     Baseline: adjacency Full both directions, MinLSInterval 5000 ms
     and MinLSArrival 1000 ms in effect, initial router-LSA present.

2. test_baseline_no_injection
     Control: without injection the victim sequence number must not
     move and no refresh/fight-back debug output may appear.

3. test_invalid_checksum_control
     Control: a forged LSA with a corrupted Fletcher checksum must be
     rejected (checksum error logged) without any refresh.

4. test_valid_newer_self_lsa_burst_paced
     The 8-LSA burst must all reach the fight-back logic, but the
     refreshes on the wire must be paced by MinLSInterval: at most one
     immediate refresh plus one delayed refresh (never one refresh per
     input packet), every interval between successive refreshes at
     least MinLSInterval, and the sequence number must still advance
     one past the last forged instance so the fight-back wins.  Before
     the fix this burst produced 8 refreshes at ~216 ms intervals with
     MinLSInterval set to 5000 ms.
"""

import json
import os
import shlex
import sys
import time

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]

# Role mapping to the original reproducer (rB1t/rB1p on 10.211.12.0/24).
R1_RID = "1.1.1.1"
R2_RID = "2.2.2.2"
R1_IP = "10.211.12.1"
R2_IP = "10.211.12.2"
R1_IF = "r1-eth0"
R2_IF = "r2-eth0"

MIN_LS_INTERVAL_MS = 5000
MIN_LS_ARRIVAL_MS = 1000
BURST_COUNT = 8
BURST_SPACING = 0.2
BASELINE_DURATION = 2.2
CONTROL_TAIL = 1.5
# The burst capture must stay up long enough to observe the refresh that
# MinLSInterval pacing delays; 7.5s covers the 5s interval with margin.
BURST_TAIL = 7.5
# Paced behavior: one immediate refresh (if MinLSInterval already
# elapsed) plus at most one delayed refresh inside the capture window.
MAX_REFRESHES_ON_WIRE = 2
# Tolerance for timer scheduling granularity when comparing wire
# intervals against MinLSInterval.
INTERVAL_TOLERANCE_MS = 500


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _vty_json(router, command):
    return router.vtysh_cmd(command, isjson=True)


def _find_key(value, key):
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = _find_key(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_key(child, key)
            if found is not None:
                return found
    return None


def _router_lsa(router, self_originated):
    command = "show ip ospf database router "
    command += (
        "self-originate json" if self_originated else "adv-router %s json" % R1_RID
    )
    data = _vty_json(router, command)

    def search(value):
        if isinstance(value, dict):
            lsa_id = value.get("linkStateId", value.get("lsId"))
            adv_router = value.get("advertisingRouter", value.get("advertisedRouter"))
            sequence = value.get("lsaSeqNumber", value.get("sequenceNumber"))
            if lsa_id == R1_RID and adv_router == R1_RID and sequence is not None:
                return value
            for child in value.values():
                found = search(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = search(child)
                if found is not None:
                    return found
        return None

    lsa = search(data)
    assert lsa is not None, "target router-LSA absent on %s: %s" % (router.name, data)
    return lsa


def _lsa_sequence(router, self_originated):
    lsa = _router_lsa(router, self_originated)
    return int(lsa.get("lsaSeqNumber", lsa.get("sequenceNumber")), 16)


def _traffic(router, iface):
    data = _vty_json(router, "show ip ospf interface traffic %s json" % iface)
    counters = data.get(iface)
    assert counters is not None, "traffic counters absent for %s: %s" % (iface, data)
    return counters


def _counter_delta(before, after):
    return {
        key: after[key] - before[key]
        for key in ("lsUpdIn", "lsUpdOut", "lsAckIn", "lsAckOut")
    }


def _ospfd_pid(router):
    return router.cmd("pidof ospfd || true").strip()


def _log_offset(router):
    log_path = os.path.join(get_topogen().logdir, router.name, "ospfd.log")
    try:
        with open(log_path) as fp:
            return sum(1 for _ in fp)
    except FileNotFoundError:
        return 0


def _log_since(router, offset):
    log_path = os.path.join(get_topogen().logdir, router.name, "ospfd.log")
    with open(log_path) as fp:
        lines = fp.readlines()
    return lines[offset:]


def _relevant_logs(lines):
    needles = ("higher seq num", "router-LSA refresh", "LSA checksum error")
    return [line.strip() for line in lines if any(needle in line for needle in needles)]


def _run_inject(r2, name, mode, base_seq=None):
    pcap = os.path.join(get_topogen().logdir, "%s.pcap" % name)
    cmd = [
        "python3",
        os.path.join(CWD, "fightback_inject.py"),
        "--iface %s" % R2_IF,
        "--target-ip %s" % R1_IP,
        "--peer-ip %s" % R2_IP,
        "--target-rid %s" % R1_RID,
        "--peer-rid %s" % R2_RID,
        "--mode %s" % mode,
        "--pcap %s" % shlex.quote(pcap),
    ]
    if mode == "baseline":
        cmd.append("--duration %s" % BASELINE_DURATION)
    elif mode == "invalid":
        cmd.append("--base-seq %s" % base_seq)
        cmd.append("--tail %s" % CONTROL_TAIL)
    else:
        cmd.append("--base-seq %s" % base_seq)
        cmd.append("--count %d" % BURST_COUNT)
        cmd.append("--spacing %s" % BURST_SPACING)
        cmd.append("--tail %s" % BURST_TAIL)
    raw = r2.cmd_raises(" ".join(cmd))
    for line in reversed(raw.splitlines()):
        if line.startswith("B1_CAPTURE_JSON="):
            return json.loads(line.split("=", 1)[1])
    raise RuntimeError("inject helper failed: %s" % raw)


def _target_lsa_events(capture, source=None):
    events = []
    for event in capture["lsas"]:
        if (
            event["type"] == 1
            and event["id"] == R1_RID
            and event["adv_router"] == R1_RID
            and (source is None or event["src"] == source)
        ):
            events.append(event)
    return events


def _measure_phase(name, r1, r2, mode, base_seq=None):
    before_seq = _lsa_sequence(r1, True)
    before_traffic = _traffic(r1, R1_IF)
    before_log = _log_offset(r1)
    pid_before = (r1.name, _ospfd_pid(r1)), (r2.name, _ospfd_pid(r2))
    capture = _run_inject(r2, name, mode, base_seq)
    after_seq = _lsa_sequence(r1, True)
    after_traffic = _traffic(r1, R1_IF)
    lines = _log_since(r1, before_log)
    result = {
        "name": name,
        "seq_before": before_seq,
        "seq_after": after_seq,
        "seq_delta": after_seq - before_seq,
        "traffic_delta": _counter_delta(before_traffic, after_traffic),
        "sent": capture["sent"],
        "injected": _target_lsa_events(capture, R2_IP),
        "target_lsa_on_wire": _target_lsa_events(capture, R1_IP),
        "refresh_log_count": sum("router-LSA refresh" in line for line in lines),
        "higher_seq_log_count": sum("higher seq num" in line for line in lines),
        "checksum_error_count": sum("LSA checksum error" in line for line in lines),
        "relevant_logs": _relevant_logs(lines),
        "pcap_path": capture["pcap_path"],
    }
    logger.info(
        "%s: seq 0x%08x -> 0x%08x, traffic %s, wire refreshes %d, "
        "refresh logs %d, higher-seq logs %d, checksum errors %d",
        name,
        before_seq,
        after_seq,
        result["traffic_delta"],
        len(result["target_lsa_on_wire"]),
        result["refresh_log_count"],
        result["higher_seq_log_count"],
        result["checksum_error_count"],
    )
    assert _ospfd_pid(r1) == pid_before[0][1] and pid_before[0][1], (
        "ospfd pid on r1 changed during %s" % name
    )
    assert _ospfd_pid(r2) == pid_before[1][1] and pid_before[1][1], (
        "ospfd pid on r2 changed during %s" % name
    )
    return result


def _burst_timing(burst):
    matches = []
    wire = burst["target_lsa_on_wire"]
    for sent in burst["sent"]:
        expected = sent["seq"] + 1
        candidates = [event for event in wire if event["seq"] == expected]
        matches.append(
            {
                "input_seq": sent["seq"],
                "expected_refresh_seq": expected,
                "refresh_count_on_wire": len(candidates),
                "latency_ms": (
                    round((candidates[0]["time"] - sent["time"]) * 1000, 3)
                    if candidates
                    else None
                ),
                "refresh_time": candidates[0]["time"] if candidates else None,
            }
        )
    refresh_times = [
        match["refresh_time"] for match in matches if match["refresh_time"] is not None
    ]
    intervals = [
        round((later - earlier) * 1000, 3)
        for earlier, later in zip(refresh_times, refresh_times[1:])
    ]
    return matches, intervals


def _wire_seq_matches(events, seq):
    return all(event["seq"] == seq for event in events)


def test_adjacency_and_min_ls_interval():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r1.expect_ospfv2_neighbor(R2_RID)
    r2.expect_ospfv2_neighbor(R1_RID)

    ospf_info = _vty_json(r1, "show ip ospf json")
    min_interval = _find_key(ospf_info, "lsaMinIntervalMsecs")
    min_arrival = _find_key(ospf_info, "lsaMinArrivalMsecs")
    assert min_interval == MIN_LS_INTERVAL_MS, (
        "MinLSInterval did not take effect: %s" % min_interval
    )
    assert min_arrival == MIN_LS_ARRIVAL_MS, (
        "MinLSArrival did not take effect: %s" % min_arrival
    )

    assert _lsa_sequence(r1, True) > 0, "no self-originated router-LSA on r1"
    assert _lsa_sequence(r2, False) > 0, "no router-LSA for r1 on r2"


def test_baseline_no_injection():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    baseline = _measure_phase("baseline_no_injection", r1, r2, "baseline")

    assert baseline["seq_delta"] == 0, (
        "victim sequence number moved without injection: %s" % baseline["seq_delta"]
    )
    assert baseline["refresh_log_count"] == 0, "refresh logged without injection"
    assert baseline["higher_seq_log_count"] == 0, "fight-back logged without injection"
    assert _wire_seq_matches(baseline["target_lsa_on_wire"], baseline["seq_before"]), (
        "victim re-originated its router-LSA without injection: %s"
        % baseline["target_lsa_on_wire"]
    )


def test_invalid_checksum_control():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    base_seq = _lsa_sequence(r1, True)
    invalid = _measure_phase("invalid_checksum_control", r1, r2, "invalid", base_seq)

    assert len(invalid["injected"]) == 1, (
        "corrupted LSA not observed on the wire: %s" % invalid["injected"]
    )
    assert invalid["seq_delta"] == 0, (
        "corrupted LSA moved the victim sequence number: %s" % invalid["seq_delta"]
    )
    assert invalid["refresh_log_count"] == 0, "refresh triggered by corrupted LSA"
    assert (
        invalid["checksum_error_count"] >= 1
    ), "no LSA checksum error logged for corrupted LSA"
    assert _wire_seq_matches(invalid["target_lsa_on_wire"], invalid["seq_before"]), (
        "victim re-originated its router-LSA after a corrupted LSA: %s"
        % invalid["target_lsa_on_wire"]
    )


def test_valid_newer_self_lsa_burst_paced():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r1.expect_ospfv2_neighbor(R2_RID)
    r2.expect_ospfv2_neighbor(R1_RID)

    base_seq = _lsa_sequence(r1, True)
    burst = _measure_phase("valid_newer_self_lsa_burst", r1, r2, "burst", base_seq)
    matches, _ = _burst_timing(burst)
    logger.info(
        "burst per-input measurement: %s",
        json.dumps(matches, sort_keys=True),
    )

    # Every forged LSA must have reached the wire and the fight-back
    # logic; otherwise the pacing assertions below would be vacuous.
    assert (
        len(burst["injected"]) == BURST_COUNT
    ), "not all forged LSAs observed on the wire: %d/%d" % (
        len(burst["injected"]),
        BURST_COUNT,
    )
    assert (
        burst["higher_seq_log_count"] == BURST_COUNT
    ), "not all forged LSAs reached the fight-back logic: %d/%d" % (
        burst["higher_seq_log_count"],
        BURST_COUNT,
    )
    assert burst["traffic_delta"]["lsUpdIn"] >= BURST_COUNT, (
        "victim did not receive every forged LSU: %s" % burst["traffic_delta"]
    )

    # Paced behavior: refreshes on the wire are bounded by MinLSInterval,
    # not one per injected packet (unpatched ospfd produced 8 refreshes
    # at ~216 ms intervals with MinLSInterval set to 5000 ms).  Count
    # distinct sequence numbers so retransmissions of one instance do
    # not inflate the number of re-originations.
    refreshes = burst["target_lsa_on_wire"]
    first_seen = {}
    for event in refreshes:
        if event["seq"] not in first_seen or event["time"] < first_seen[event["seq"]]:
            first_seen[event["seq"]] = event["time"]
    refresh_times = sorted(first_seen.values())
    intervals = [
        round((later - earlier) * 1000, 3)
        for earlier, later in zip(refresh_times, refresh_times[1:])
    ]
    logger.info(
        "burst wire refreshes: %d distinct sequence numbers, intervals %s ms",
        len(first_seen),
        intervals,
    )
    assert len(first_seen) >= 1, "no fight-back refresh observed on the wire"
    assert len(first_seen) <= MAX_REFRESHES_ON_WIRE, (
        "fight-back refresh storm: %d distinct re-originations on the wire for %d "
        "forged LSAs (limit %d, MinLSInterval %d ms)"
        % (len(first_seen), BURST_COUNT, MAX_REFRESHES_ON_WIRE, MIN_LS_INTERVAL_MS)
    )
    for interval in intervals:
        assert (
            interval >= MIN_LS_INTERVAL_MS - INTERVAL_TOLERANCE_MS
        ), "refreshes closer than MinLSInterval: %s ms (limit %d ms)" % (
            intervals,
            MIN_LS_INTERVAL_MS - INTERVAL_TOLERANCE_MS,
        )
    assert 1 <= burst["refresh_log_count"] <= MAX_REFRESHES_ON_WIRE, (
        "refresh log count %d does not match paced refreshes"
        % burst["refresh_log_count"]
    )

    # The fight-back must still win: after the paced refresh the victim
    # sequence number is one past the last forged instance.
    expected_final_seq = burst["seq_before"] + 2 * BURST_COUNT
    assert burst["seq_after"] == expected_final_seq, (
        "fight-back did not advance past the last forged instance: "
        "0x%08x != 0x%08x" % (burst["seq_after"], expected_final_seq)
    )

    # The refreshed instance must reach the peer and the adjacency must
    # survive the burst.
    r1.expect_ospfv2_neighbor(R2_RID)
    r2.expect_ospfv2_neighbor(R1_RID)

    def _peer_has_final_seq():
        return _lsa_sequence(r2, False) >= expected_final_seq

    deadline = time.time() + 15
    while time.time() < deadline and not _peer_has_final_seq():
        time.sleep(0.5)
    assert (
        _peer_has_final_seq()
    ), "peer did not install the final fight-back instance: 0x%08x < 0x%08x" % (
        _lsa_sequence(r2, False),
        expected_final_seq,
    )
