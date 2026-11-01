#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf6_fightback_pacing.py
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_ospf6_fightback_pacing.py
=============================

Regression for unbounded OSPFv3 fight-back refresh/flooding.

RFC 2328 Section 13.4 requires a router that receives a newer instance
of its own self-originated LSA to re-originate it with a sequence
number one past the received one (the "fight-back").  Section 12.4
bounds successive originations of the same LSA by MinLSInterval.
ospf6d never implemented MinLSInterval (the `originated` field in
struct ospf6_lsa is reserved for it but was never read), and the
fight-back refresh scheduled from ospf6_receive_lsa() fired
immediately, so an on-link attacker injecting forged self-originated
LSAs produced an unbounded refresh/flooding storm (plus SPF on every
router).  The storm is worst for self-originated MaxAge LSAs: those
bypass the MinLSArrival check in ospf6_receive_lsa() (needed so a
restarting router can always install the pre-restart MaxAge copies
flooded back by its peers), so every forged MaxAge LSA is installed
and immediately refreshed at the attacker's packet rate.

Topology (same roles as the original reproducer
topo-fuzz test/manul/ospf6_fightback_pacing.py)
-----------------------------------------------

    r1 (victim, was r6v) ---- r1-eth0 ---- s1 ---- r2-eth0 ---- r2 (attacker, was r6i)
                                     |
                                     ---- r3-eth0 ---- r3 (observer, was r6o)

r1: router-id 1.1.1.1, 2001:db8:1::1/64, DR (priority 100); r2:
router-id 2.2.2.2, 2001:db8:1::2/64; r3: router-id 3.3.3.3,
2001:db8:1::3/64.  r2 and r3 run priority 0 so r1 is always DR.
r2 injects unicast OSPFv3 LSUs (hop limit 1, next header 89) whose
single LSA claims r1 as advertising router with a sequence number two
past r1's current one; bursts carry 8 (MaxAge path) or 12 (fresh
path) LSAs spaced 200 ms apart.

Test plan
---------

1. test_adjacency_and_baseline
     Baseline: adjacency Full, r1 DR, no injection must not move the
     victim sequence number or produce any refresh.

2. test_single_legal_fightback
     One forged newer Router-LSA must still produce exactly one
     immediate fight-back refresh (RFC 2328 Section 13.4 behavior the
     fix must preserve).

3. test_invalid_checksum_control
     A forged LSA with a corrupted Fletcher checksum must be rejected
     without any refresh.

4. test_maxage_burst_paced
     8 forged self-originated MaxAge Router-LSAs at 200 ms: before the
     fix each bypassed MinLSArrival and refreshed immediately (8
     re-originations at ~200 ms intervals).  The fix must pace them
     the same way while the bypass itself (install of every forged
     MaxAge LSA) is preserved, and the fight-back must still advance
     the sequence number one past the last forged instance.

5. test_fresh_burst_paced
     12 forged fresh Router-LSAs at 200 ms: MinLSArrival (1000 ms)
     gates the installs, but before the fix every accepted instance
     still refreshed immediately (2-3 re-originations at ~1 s
     intervals, far below MinLSInterval).  The fix must pace them:
     at most one immediate refresh plus one delayed refresh, every
     interval at least MinLSInterval.

6. test_per_key_independence
     Router-LSA (key A) and Network-LSA (key B) pacing state must be
     independent: a first fight-back on key B stays immediate even
     while key A has a refresh pending inside its MinLSInterval
     window; a key A retrigger inside the window is delayed.

7. test_recovery
     With injection stopped, no further re-originations, adjacency
     and routes stay up.
"""

import json
import os
import re
import shlex
import sys
import time

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospf6d]

# Role mapping to the original reproducer (r6v/r6i/r6o on 2001:db8:1::/64).
R1_RID = "1.1.1.1"
R2_RID = "2.2.2.2"
R3_RID = "3.3.3.3"
R1_IP = "2001:db8:1::1"
R2_IP = "2001:db8:1::2"
R3_IP = "2001:db8:1::3"
R1_IF = "r1-eth0"
R2_IF = "r2-eth0"
R3_IF = "r3-eth0"

MIN_LS_INTERVAL_MS = 5000
MIN_LS_ARRIVAL_MS = 1000
MAX_AGE = 3600
BURST_SPACING = 0.2
P2_COUNT = 12
P3_COUNT = 8
# Tolerance for timer scheduling granularity when comparing wire
# intervals against MinLSInterval.
INTERVAL_TOLERANCE_MS = 200
# Quiet time between phases so the per-key MinLSInterval state from the
# previous phase cannot leak into the next one.
SETTLE_SECONDS = 5.2

OSPF6_LSTYPE_ROUTER = 0x2001
OSPF6_LSTYPE_NETWORK = 0x2002


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)
    switch.add_link(r3)


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


def _find_in_json(value, predicate):
    if isinstance(value, dict):
        if predicate(value):
            return value
        for child in value.values():
            found = _find_in_json(child, predicate)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_in_json(child, predicate)
            if found is not None:
                return found
    return None


def _mac(router, iface):
    out = router.cmd("ip link show dev %s" % iface)
    match = re.search(r"link/ether (\S+)", out)
    assert match, "no MAC for %s on %s: %s" % (iface, router.name, out)
    return match.group(1)


def _linklocal(router, iface):
    out = router.cmd("ip -6 addr show dev %s" % iface)
    match = re.search(r"inet6 (fe80::[0-9a-f:]+)/", out)
    assert match, "no link-local for %s on %s: %s" % (iface, router.name, out)
    return match.group(1)


def _lsdb_entry(router, db_command, ls_id, adv_router):
    data = _vty_json(router, db_command)
    return _find_in_json(
        data,
        lambda item: item.get("lsId") == ls_id
        and item.get("advRouter") == adv_router,
    )


def _key_a_id(r1):
    entry = _find_in_json(
        _vty_json(r1, "show ipv6 ospf6 database router json"),
        lambda item: item.get("advRouter") == R1_RID
        and item.get("lsId") is not None,
    )
    assert entry is not None, "no self-originated Router-LSA on r1"
    return entry["lsId"]


def _key_b_id(r1):
    entry = _find_in_json(
        _vty_json(r1, "show ipv6 ospf6 database network json"),
        lambda item: item.get("advRouter") == R1_RID
        and item.get("lsId") is not None,
    )
    assert entry is not None, "no self-originated Network-LSA on r1"
    return entry["lsId"]


def _key_a_seq(router, key_a_id):
    entry = _lsdb_entry(
        router, "show ipv6 ospf6 database router json", key_a_id, R1_RID
    )
    assert entry is not None, "no Router-LSA for r1 on %s" % router.name
    return int(entry["seqNum"])


def _key_b_seq(router, key_b_id):
    entry = _lsdb_entry(
        router, "show ipv6 ospf6 database network json", key_b_id, R1_RID
    )
    assert entry is not None, "no Network-LSA for r1 on %s" % router.name
    return int(entry["seqNum"])


def _neighbor_state(router, peer_rid):
    data = _vty_json(router, "show ipv6 ospf6 neighbor json")
    entry = _find_in_json(data, lambda item: item.get("neighborId") == peer_rid)
    return entry.get("state") if entry else "Absent"


def _wait_full(router, peer_rid, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if str(_neighbor_state(router, peer_rid)).startswith("Full"):
            return True
        time.sleep(1)
    return False


def _traffic(router, iface):
    data = _vty_json(router, "show ipv6 ospf6 interface traffic %s json" % iface)
    counters = data.get(iface)
    assert counters is not None, "traffic counters absent for %s: %s" % (
        iface,
        data,
    )
    return counters


def _counter_delta(before, after):
    return {
        key: after[key] - before[key]
        for key in ("lsUpdateRx", "lsUpdateTx", "lsAckRx", "lsAckTx")
    }


def _ospf6d_pid(router):
    return router.cmd("pidof ospf6d || true").strip()


def _log_offset(router):
    log_path = os.path.join(get_topogen().logdir, router.name, "ospf6d.log")
    try:
        with open(log_path) as fp:
            return sum(1 for _ in fp)
    except FileNotFoundError:
        return 0


def _log_since(router, offset):
    log_path = os.path.join(get_topogen().logdir, router.name, "ospf6d.log")
    with open(log_path) as fp:
        lines = fp.readlines()
    return lines[offset:]


LOG_NEEDLES = {
    "refresh": "LSA Refresh:",
    "originate": "LSA Originate:",
    "install": "Install LSA:",
    "minarrival_reject": "can't be updated within MinLSArrival",
    "maxage_bypass": "Bypassing MinLSArrival for self-originated MaxAge",
    "bad_checksum": "Wrong LSA Checksum",
    "newer_self": "Newer instance of the self-originated LSA",
    "delayed": "fight-back refresh delayed",
}


def _log_counts(lines):
    return {
        name: sum(needle in line for line in lines)
        for name, needle in LOG_NEEDLES.items()
    }


def _parse_capture(raw):
    for line in reversed(raw.splitlines()):
        if line.startswith("O6FP_CAPTURE_JSON="):
            return json.loads(line.split("=", 1)[1])
    raise RuntimeError("inject helper failed: %s" % raw)


def _lsa_events(capture, src_ips, ls_type, ls_id, adv_router, max_age=None):
    events = []
    for packet in capture["events"]:
        if packet["type"] != 4 or packet["src"] not in src_ips:
            continue
        for lsa in packet.get("lsas", []):
            if (
                lsa["type"] == ls_type
                and lsa["id"] == ls_id
                and lsa["adv_router"] == adv_router
            ):
                if max_age is not None and lsa["age"] >= max_age:
                    continue
                events.append(
                    {
                        "time": packet["time"],
                        "seq": lsa["seq"],
                        "age": lsa["age"],
                        "src": packet["src"],
                    }
                )
    return events


def _origin_events(capture, src_ips, ls_type, ls_id, adv_router):
    """Victim-sent fresh (non-MaxAge) instances of the key = originations.

    Dedupe by sequence number: one origination may appear on the wire
    more than once (e.g. retransmission); the first sighting is the
    origination time.
    """
    fresh = _lsa_events(capture, src_ips, ls_type, ls_id, adv_router,
                        max_age=MAX_AGE)
    by_seq = {}
    for event in fresh:
        by_seq.setdefault(event["seq"], event)
    return [by_seq[seq] for seq in sorted(by_seq)]


def _origin_intervals(origins):
    times = [event["time"] for event in origins]
    return [
        round((later - earlier) * 1000, 3)
        for earlier, later in zip(times, times[1:])
    ]


def _match_inputs(sent, origins):
    matches = []
    for item in sent:
        expected = item["seq"] + 1
        candidates = [event for event in origins if event["seq"] == expected]
        matches.append(
            {
                "label": item["label"],
                "key": item["key"],
                "input_seq": item["seq"],
                "expected_origin_seq": expected,
                "origin_count": len(candidates),
                "latency_ms": (
                    round((candidates[0]["time"] - item["time"]) * 1000, 3)
                    if candidates
                    else None
                ),
            }
        )
    return matches


def _measure_phase(name, r1, r2, r3, specs, spacing, tail, key_a_id, key_b_id):
    """Run one injection phase; r2 injects and captures, r3 captures the
    observer link concurrently.  Returns the phase evidence dict."""
    before_seq = _key_a_seq(r1, key_a_id)
    before_traffic = _traffic(r1, R1_IF)
    before_log = _log_offset(r1)
    pid_before = {r.name: _ospf6d_pid(r) for r in (r1, r2, r3)}

    base_args = {
        "src_ip": R2_IP,
        "dst_ip": R1_IP,
        "src_mac": _mac(r2, R2_IF),
        "dst_mac": _mac(r1, R1_IF),
        "header_rid": R2_RID,
        "key_a_id": key_a_id,
        "key_b_id": key_b_id,
        "spacing": spacing,
    }
    duration = spacing * max(0, len(specs) - 1) + tail

    def helper_argv(router, iface, spec_list, helper_tail):
        pcap = os.path.join(
            get_topogen().logdir, "%s_%s.pcap" % (name, router.name)
        )
        return [
            "python3",
            os.path.join(CWD, "fightback_inject6.py"),
            "--iface", iface,
            "--src-ip", base_args["src_ip"],
            "--dst-ip", base_args["dst_ip"],
            "--src-mac", base_args["src_mac"],
            "--dst-mac", base_args["dst_mac"],
            "--header-rid", base_args["header_rid"],
            "--victim-rid", R1_RID,
            "--key-a-id", base_args["key_a_id"],
            "--key-b-id", base_args["key_b_id"],
            "--specs-json", json.dumps(spec_list),
            "--spacing", str(base_args["spacing"]),
            "--tail", str(helper_tail),
            "--pcap", pcap,
        ]

    r3_proc = r3.popen(helper_argv(r3, R3_IF, [], duration + 1.0))
    time.sleep(0.6)
    raw = r2.cmd_raises(
        " ".join(shlex.quote(part) for part in helper_argv(r2, R2_IF, specs, tail))
    )
    capture = _parse_capture(raw)
    stdout, stderr = r3_proc.communicate(timeout=60)
    if r3_proc.returncode != 0:
        raise RuntimeError("observer capture failed: %s" % stderr)
    if isinstance(stdout, bytes):
        stdout = stdout.decode()
    observer_capture = _parse_capture(stdout)

    after_seq = _key_a_seq(r1, key_a_id)
    after_traffic = _traffic(r1, R1_IF)
    lines = _log_since(r1, before_log)
    result = {
        "name": name,
        "seq_before": before_seq,
        "seq_after": after_seq,
        "traffic_delta": _counter_delta(before_traffic, after_traffic),
        "sent": capture["sent"],
        "log_counts": _log_counts(lines),
        "capture": capture,
        "observer_capture": observer_capture,
        "pcap": capture["pcap_path"],
        "observer_pcap": observer_capture["pcap_path"],
        "victim_srcs": (R1_IP, _linklocal(r1, R1_IF)),
    }
    for router in (r1, r2, r3):
        assert _ospf6d_pid(router) == pid_before[router.name] and pid_before[
            router.name
        ], "ospf6d pid on %s changed during %s" % (router.name, name)
    return result


def _settle():
    time.sleep(SETTLE_SECONDS)


def test_adjacency_and_baseline():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    assert _wait_full(r1, R2_RID), "r1-r2 not Full"
    assert _wait_full(r1, R3_RID), "r1-r3 not Full"

    key_a_id = _key_a_id(r1)
    key_b_id = _key_b_id(r1)

    # Let one-time adjacency-formation originations settle.
    time.sleep(5)
    phase = _measure_phase(
        "baseline_no_injection", r1, r2, r3, [], 0, 3, key_a_id, key_b_id
    )
    origins = _origin_events(
        phase["capture"], phase["victim_srcs"], OSPF6_LSTYPE_ROUTER, key_a_id, R1_RID
    )

    assert phase["seq_after"] == phase["seq_before"], (
        "victim sequence number moved without injection: %s"
        % (phase["seq_after"] - phase["seq_before"])
    )
    assert len(origins) == 0, "victim re-originated without injection"
    assert phase["log_counts"]["refresh"] == 0, "refresh logged without injection"
    assert phase["log_counts"]["newer_self"] == 0, (
        "fight-back logged without injection"
    )
    assert phase["traffic_delta"]["lsUpdateRx"] == 0, (
        "LSUpdate received without injection: %s" % phase["traffic_delta"]
    )


def test_single_legal_fightback():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    key_a_id = _key_a_id(r1)
    key_b_id = _key_b_id(r1)

    base_seq = _key_a_seq(r1, key_a_id)
    phase = _measure_phase(
        "single_legal_fightback",
        r1,
        r2,
        r3,
        [{"label": "keyA_fresh", "key": "A", "seq": base_seq + 1, "age": 1}],
        0,
        2,
        key_a_id,
        key_b_id,
    )
    origins = _origin_events(
        phase["capture"], phase["victim_srcs"], OSPF6_LSTYPE_ROUTER, key_a_id, R1_RID
    )
    matches = _match_inputs(phase["sent"], origins)

    assert phase["traffic_delta"]["lsUpdateRx"] >= 1, (
        "forged LSA did not reach the victim: %s" % phase["traffic_delta"]
    )
    assert len(matches) == 1 and matches[0]["origin_count"] == 1, (
        "single forged LSA must produce exactly one fight-back: %s" % matches
    )
    assert (
        matches[0]["latency_ms"] is not None and matches[0]["latency_ms"] < 1000
    ), "first legal fight-back must stay immediate: %s" % matches
    assert phase["seq_after"] == base_seq + 2, (
        "fight-back did not advance the sequence number: 0x%08x != 0x%08x"
        % (phase["seq_after"], base_seq + 2)
    )
    assert phase["log_counts"]["newer_self"] == 1, (
        "fight-back trigger log count %d != 1" % phase["log_counts"]["newer_self"]
    )
    assert phase["log_counts"]["refresh"] == 1, (
        "refresh log count %d != 1" % phase["log_counts"]["refresh"]
    )


def test_invalid_checksum_control():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    key_a_id = _key_a_id(r1)
    key_b_id = _key_b_id(r1)

    base_seq = _key_a_seq(r1, key_a_id)
    phase = _measure_phase(
        "invalid_checksum_control",
        r1,
        r2,
        r3,
        [
            {
                "label": "keyA_bad",
                "key": "A",
                "seq": base_seq + 1,
                "age": 1,
                "corrupt": True,
            }
        ],
        0,
        1.5,
        key_a_id,
        key_b_id,
    )
    origins = _origin_events(
        phase["capture"], phase["victim_srcs"], OSPF6_LSTYPE_ROUTER, key_a_id, R1_RID
    )

    assert phase["traffic_delta"]["lsUpdateRx"] >= 1, (
        "corrupted LSA did not reach the victim: %s" % phase["traffic_delta"]
    )
    assert len(origins) == 0, "refresh triggered by corrupted LSA: %s" % origins
    assert phase["seq_after"] == base_seq, (
        "corrupted LSA moved the victim sequence number: 0x%08x != 0x%08x"
        % (phase["seq_after"], base_seq)
    )
    assert phase["log_counts"]["bad_checksum"] >= 1, (
        "no LSA checksum error logged for corrupted LSA"
    )
    assert phase["log_counts"]["refresh"] == 0, (
        "refresh triggered by corrupted LSA"
    )


def test_maxage_burst_paced():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    key_a_id = _key_a_id(r1)
    key_b_id = _key_b_id(r1)

    _settle()
    base_seq = _key_a_seq(r1, key_a_id)
    phase = _measure_phase(
        "maxage_burst",
        r1,
        r2,
        r3,
        [
            {
                "label": "keyA_maxage_%d" % i,
                "key": "A",
                "seq": base_seq + 1 + 2 * i,
                "age": MAX_AGE,
            }
            for i in range(P3_COUNT)
        ],
        BURST_SPACING,
        5.5,
        key_a_id,
        key_b_id,
    )
    origins = _origin_events(
        phase["capture"], phase["victim_srcs"], OSPF6_LSTYPE_ROUTER, key_a_id, R1_RID
    )
    intervals = _origin_intervals(origins)
    matches = _match_inputs(phase["sent"], origins)

    assert phase["traffic_delta"]["lsUpdateRx"] >= P3_COUNT, (
        "not all forged MaxAge LSAs reached the victim: %s"
        % phase["traffic_delta"]
    )
    # The MinLSArrival bypass for self-originated MaxAge LSAs must stay
    # (it fixes the restart sequence-number race): every forged MaxAge
    # LSA is installed.
    assert phase["log_counts"]["maxage_bypass"] == P3_COUNT, (
        "self-MaxAge MinLSArrival bypass did not run for every input: %d/%d"
        % (phase["log_counts"]["maxage_bypass"], P3_COUNT)
    )
    assert len(origins) >= 1, "no fight-back refresh observed on the wire"
    assert phase["log_counts"]["delayed"] >= 1, (
        "no paced (delayed) fight-back logged during the MaxAge burst: %s"
        % phase["log_counts"]
    )
    assert len(origins) <= 2, (
        "fight-back refresh storm on the MaxAge path: %d re-originations for %d "
        "forged LSAs (MinLSInterval %d ms)"
        % (len(origins), P3_COUNT, MIN_LS_INTERVAL_MS)
    )
    for interval in intervals:
        assert interval >= MIN_LS_INTERVAL_MS - INTERVAL_TOLERANCE_MS, (
            "refreshes closer than MinLSInterval: %s ms" % intervals
        )
    assert all(match["origin_count"] <= 1 for match in matches), (
        "more than one refresh per input: %s" % matches
    )
    # The fight-back must still win: after the paced refresh the victim
    # sequence number is one past the last forged instance.
    assert phase["seq_after"] == base_seq + 2 * P3_COUNT, (
        "fight-back did not advance past the last forged instance: "
        "0x%08x != 0x%08x" % (phase["seq_after"], base_seq + 2 * P3_COUNT)
    )
    # The reoriginated instances must also be seen on the observer link.
    observer_origins = _origin_events(
        phase["observer_capture"],
        phase["victim_srcs"],
        OSPF6_LSTYPE_ROUTER,
        key_a_id,
        R1_RID,
    )
    assert len(observer_origins) >= 1, (
        "no fight-back instance seen on the observer link"
    )
    assert _wait_full(r1, R2_RID, timeout=10), "adjacency down after MaxAge burst"


def test_fresh_burst_paced():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    key_a_id = _key_a_id(r1)
    key_b_id = _key_b_id(r1)

    _settle()
    base_seq = _key_a_seq(r1, key_a_id)
    phase = _measure_phase(
        "fresh_burst",
        r1,
        r2,
        r3,
        [
            {
                "label": "keyA_fresh_%d" % i,
                "key": "A",
                "seq": base_seq + 1 + 2 * i,
                "age": 1,
            }
            for i in range(P2_COUNT)
        ],
        BURST_SPACING,
        4,
        key_a_id,
        key_b_id,
    )
    origins = _origin_events(
        phase["capture"], phase["victim_srcs"], OSPF6_LSTYPE_ROUTER, key_a_id, R1_RID
    )
    intervals = _origin_intervals(origins)
    matches = _match_inputs(phase["sent"], origins)

    assert phase["traffic_delta"]["lsUpdateRx"] >= P2_COUNT, (
        "not all forged LSAs reached the victim: %s" % phase["traffic_delta"]
    )
    assert phase["log_counts"]["minarrival_reject"] >= 1, (
        "MinLSArrival did not gate the fresh burst: %s" % phase["log_counts"]
    )
    assert len(origins) >= 1, "no fight-back refresh observed on the wire"
    assert phase["log_counts"]["delayed"] >= 1, (
        "no paced (delayed) fight-back logged during the fresh burst: %s"
        % phase["log_counts"]
    )
    assert len(origins) <= 2, (
        "fight-back refresh storm on the fresh path: %d re-originations for %d "
        "forged LSAs (MinLSInterval %d ms)"
        % (len(origins), P2_COUNT, MIN_LS_INTERVAL_MS)
    )
    for interval in intervals:
        assert interval >= MIN_LS_INTERVAL_MS - INTERVAL_TOLERANCE_MS, (
            "refreshes closer than MinLSInterval: %s ms" % intervals
        )
    # MinLSArrival, not packet loss, must explain the missing responses:
    # every accepted input still gets exactly one reoriginated copy.
    assert all(match["origin_count"] <= 1 for match in matches), (
        "more than one refresh per accepted input: %s" % matches
    )


def test_per_key_independence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    key_a_id = _key_a_id(r1)
    key_b_id = _key_b_id(r1)

    _settle()
    base_a = _key_a_seq(r1, key_a_id)
    base_b = _key_b_seq(r1, key_b_id)
    phase = _measure_phase(
        "per_key_independence",
        r1,
        r2,
        r3,
        [
            {"label": "keyA_fresh", "key": "A", "seq": base_a + 1, "age": 1},
            {"label": "keyB_fresh", "key": "B", "seq": base_b + 1, "age": 1},
            {
                "label": "keyA_maxage",
                "key": "A",
                "seq": base_a + 3,
                "age": MAX_AGE,
            },
        ],
        0.3,
        5.5,
        key_a_id,
        key_b_id,
    )
    origins_a = _origin_events(
        phase["capture"], phase["victim_srcs"], OSPF6_LSTYPE_ROUTER, key_a_id, R1_RID
    )
    origins_b = _origin_events(
        phase["capture"], phase["victim_srcs"], OSPF6_LSTYPE_NETWORK, key_b_id, R1_RID
    )
    matches_a = _match_inputs(
        [item for item in phase["sent"] if item["key"] == "A"], origins_a
    )
    matches_b = _match_inputs(
        [item for item in phase["sent"] if item["key"] == "B"], origins_b
    )

    assert matches_a[0]["origin_count"] == 1, (
        "first key A fight-back missing: %s" % matches_a
    )
    assert matches_a[0]["latency_ms"] is not None
    assert matches_a[0]["latency_ms"] < 1000, (
        "first key A fight-back must stay immediate: %s" % matches_a
    )
    assert matches_b[0]["origin_count"] == 1, (
        "key B fight-back missing: %s" % matches_b
    )
    assert matches_b[0]["latency_ms"] is not None
    assert matches_b[0]["latency_ms"] < 1000, (
        "key B fight-back must be immediate even while key A has a refresh "
        "pending (independent per-key pacing state): %s" % matches_b
    )
    assert matches_a[1]["origin_count"] == 1, (
        "key A retrigger did not refresh exactly once: %s" % matches_a
    )
    assert matches_a[1]["latency_ms"] is not None
    assert 4000 <= matches_a[1]["latency_ms"] <= 6000, (
        "key A retrigger inside the MinLSInterval window must be delayed "
        "to the window edge: %s" % matches_a
    )
    assert phase["seq_after"] == base_a + 4, (
        "key A sequence number did not advance past the retrigger: "
        "0x%08x != 0x%08x" % (phase["seq_after"], base_a + 4)
    )
    assert _key_b_seq(r1, key_b_id) == base_b + 2, (
        "key B sequence number did not advance: 0x%08x != 0x%08x"
        % (_key_b_seq(r1, key_b_id), base_b + 2)
    )


def test_recovery():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    key_a_id = _key_a_id(r1)
    key_b_id = _key_b_id(r1)

    phase = _measure_phase("recovery", r1, r2, r3, [], 0, 8, key_a_id, key_b_id)
    origins = _origin_events(
        phase["capture"], phase["victim_srcs"], OSPF6_LSTYPE_ROUTER, key_a_id, R1_RID
    )

    assert len(origins) == 0, (
        "refresh after injection stopped: %s"
        % [(event["seq"], event["time"]) for event in origins]
    )
    assert phase["log_counts"]["refresh"] == 0, (
        "refresh logged after injection stopped"
    )
    assert phase["traffic_delta"]["lsUpdateRx"] == 0, (
        "LSUpdate received after injection stopped: %s" % phase["traffic_delta"]
    )
    assert _wait_full(r1, R2_RID, timeout=10), "r1-r2 adjacency down"
    assert _wait_full(r1, R3_RID, timeout=10), "r1-r3 adjacency down"
    route = r1.vtysh_cmd("show ipv6 ospf6 route")
    assert "2001:db8:1::/64" in route, "OSPFv3 route missing after recovery"
