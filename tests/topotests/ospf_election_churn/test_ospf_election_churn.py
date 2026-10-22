#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_election_churn.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#

r"""
test_ospf_election_churn.py
============================

Regression test for OSPF DR election churn in ospfd (B7): a stream of
Hellos that flip the DR/BDR/priority fields forces a full DR election
per packet, and whenever the election result flips, an AdjOK storm plus
unpaced router/network-LSA re-origination well below MinLSInterval.

Every Hello that changes a neighbor's DR, BDR or priority field raises
ISM_NeighborChange (ospfd/ospf_packet.c), which runs the two-pass DR
election (ospfd/ospf_ism.c).  When the result changes, the interface
state change re-originates the router-LSA, flushes/originates the
network-LSA and sends AdjOK to every neighbor.  There was no bound on
how often this work could repeat: an on-link attacker sending a handful
of packets per second kept the victim re-electing, re-originating and
flooding LSAs with sequence numbers advancing at packet rate, ignoring
the configured MinLSInterval.

The fix coalesces repeated ISM_NeighborChange events per interface:
the first event after a quiet period still runs immediately, further
events within the same MinLSInterval window collapse into one pending
election, and any pending election fires at most MinLSInterval after
the previous one.  Legitimate DR/BDR/priority changes therefore still
take effect within one MinLSInterval (asserted here), while a hostile
burst produces a bounded number of elections and LSA re-originations
that respect MinLSInterval.

Topology
--------

    r1 (victim, RID 10.255.7.1, DR on the LAN)
      |
      +-- eth0 --+            +-- eth0 -- r2 (peer, RID 10.255.7.2,
      |           \          /              BDR on the LAN)
      |            +-- s1 --+
      |
    10.217.7.0/24, hello-interval 30s, dead-interval 40s,
    MinLSInterval 5000ms on both routers.

All triggers are injected from r2's namespace with scapy: the
Ethernet/IP source is r2's own, only the OSPF DR/BDR/priority fields
are forged.  Each injection is captured on the wire (pcap under
tgen.logdir); r1's receipt is cross-checked through the per-interface
helloIn counter and the ospfd log.

Test plan
---------

1. test_adjacency_full
     Baseline: adjacency Full, r1 is DR and r2 is BDR, MinLSInterval
     is 5000ms as configured.
2. test_no_injection_control
     Without injection no election, no AdjOK and no LSA re-origination
     happens.
3. test_invalid_checksum_control
     A Hello with a corrupted OSPF checksum is dropped before Hello
     processing: no election.
4. test_legit_dr_change_converges_bounded
     A single valid Hello claiming a new DR still triggers a prompt
     election and converges within a bounded time; restoring the real
     fields converges back.  The fix must not delay isolated,
     legitimate changes beyond one MinLSInterval.
5. test_election_churn_rate_limited
     Bursts of 16 Hellos flipping the DR, BDR and priority fields at
     20 packets/s: elections, AdjOK events, state changes and LSA
     re-originations are bounded, and successive router-LSA
     re-originations respect MinLSInterval.  Before the fix every
     packet triggered an election and the router-LSA was refreshed at
     packet rate, far below MinLSInterval.
6. test_final_full_convergence
     r1 is DR again, the adjacency is Full, daemons alive, pcaps
     present.
"""

import json
import os
import re
import shlex
import sys
import time
from datetime import datetime
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
R1_LAN_IP = "10.217.7.1"
R2_LAN_IP = "10.217.7.2"
R1_RID = "10.255.7.1"
R2_RID = "10.255.7.2"
HELLO_INTERVAL = 30
DEAD_INTERVAL = 40
MIN_LS_INTERVAL_MS = 5000
# Interval slack when comparing successive router-LSA re-originations
# against MinLSInterval (log timestamp granularity, scheduling jitter).
MIN_LS_SLACK_MS = 250
ADJACENCY_TIMEOUT = 120
BURST_COUNT = 16
BURST_SPACING = 0.05
# Observation window after the last injected packet: long enough for a
# coalesced (delayed) election to fire within one MinLSInterval.
CAPTURE_TAIL = 7.0
# Bounds for the coalescing fix: one immediate election plus at most
# one coalesced election per MinLSInterval window, plus one spare.
MAX_ELECTIONS_PER_BURST = 3

LOG_TS = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")


def _parse_log_ts(text):
    for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def build_topo(tgen):
    r1 = tgen.add_router(R1)
    r2 = tgen.add_router(R2)
    s1 = tgen.add_switch("s1")
    tgen.add_link(r1, s1, ifname1=LAN_IF, ifname2="eth0")
    tgen.add_link(r2, s1, ifname1=LAN_IF, ifname2="eth1")


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


def _interface_info(router):
    data = _vty_json(router, "show ip ospf interface %s json" % LAN_IF)
    return data.get("interfaces", {}).get(LAN_IF, {})


def _neighbor_full(router, rid):
    data = _vty_json(router, "show ip ospf neighbor json")
    entries = data.get("neighbors", {}).get(rid, [])
    return bool(entries) and entries[0].get("converged") == "Full"


def _router_lsa_seq(router):
    data = _vty_json(router, "show ip ospf database router self-originate json")
    found = []

    def walk(value):
        if isinstance(value, dict):
            lsa_id = value.get("linkStateId", value.get("lsId"))
            adv = value.get("advertisingRouter", value.get("advertisedRouter"))
            if lsa_id == R1_RID and adv == R1_RID:
                found.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    if not found:
        raise RuntimeError("r1 router-LSA not found: %s" % data)
    seq = found[0].get("lsaSeqNumber", found[0].get("sequenceNumber"))
    return int(seq, 16)


def _min_ls_interval(router):
    data = _vty_json(router, "show ip ospf json")
    found = []

    def walk(value):
        if isinstance(value, dict):
            if "lsaMinIntervalMsecs" in value:
                found.append(value["lsaMinIntervalMsecs"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found[0] if found else None


def _hello_in(router):
    data = _vty_json(router, "show ip ospf interface traffic %s json" % LAN_IF)
    return data[LAN_IF]["helloIn"]


def _iface_mac(node, ifname):
    return node.cmd("cat /sys/class/net/%s/address" % ifname).strip()


def _ospfd_pid(router):
    return router.cmd("pidof ospfd || true").strip()


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
        "NeighborChange",
        "AdjOK",
        "State change",
        "router-LSA refresh",
        "network-LSA",
        "MaxAge set",
        "checksum",
    )
    return [line for line in text.splitlines() if any(t in line for t in tokens)]


def _sync_peer_hello(r1):
    """Wait until the peer's periodic Hello just went out.

    The peer's real periodic Hello carries the real DR/BDR fields and
    would restore them mid-burst, so every phase starts right after one
    went out, leaving a full Hello interval of quiet wire.
    """
    before = _hello_in(r1)
    _wait_until(
        lambda: _hello_in(r1) > before, timeout=HELLO_INTERVAL + 5, interval=0.05
    )


def _inject(r2, r1, label, mode, count, spacing, tail, variants):
    """Send forged Hellos from r2 and prove they hit the wire.

    Returns the phase dict with the send/capture evidence, r1's
    helloIn delta and the ospfd log delta for this injection.
    """
    tgen = get_topogen()
    pcap = os.path.join(tgen.logdir, "%s.pcap" % label)
    variants_path = os.path.join(tgen.logdir, "%s_variants.json" % label)
    with open(variants_path, "w") as variantf:
        json.dump(variants, variantf, sort_keys=True)
    r2.cmd("rm -f %s" % shlex.quote(pcap))
    hello_before = _hello_in(r1)
    offset = _log_offset(r1)
    cmd = (
        "python3 %s/send_burst.py --iface %s --src-mac %s --src-ip %s "
        "--dst-ip %s --packet-rid %s --neighbors %s "
        "--hello-interval %d --dead-interval %d --mode %s "
        "--count %d --spacing %s --tail %s --variants-json %s --pcap %s"
        % (
            shlex.quote(CWD),
            shlex.quote(LAN_IF),
            shlex.quote(_iface_mac(r2, LAN_IF)),
            shlex.quote(R2_LAN_IP),
            shlex.quote(R1_LAN_IP),
            shlex.quote(R2_RID),
            shlex.quote(R1_RID),
            HELLO_INTERVAL,
            DEAD_INTERVAL,
            mode,
            count,
            spacing,
            tail,
            shlex.quote(variants_path),
            shlex.quote(pcap),
        )
    )
    out = r2.cmd_raises(cmd)
    markers = [line for line in out.splitlines() if line.startswith("B7_SEND_JSON=")]
    assert markers, "send_burst.py returned no result for %s: %s" % (label, out)
    send = json.loads(markers[-1].split("=", 1)[1])
    assert send["captured_matching"] == len(
        send["sent"]
    ), "forged Hellos %s were not all captured on the wire: %s" % (label, send)
    hello_delta = _hello_in(r1) - hello_before
    log = _log_since(r1, offset)
    phase = {
        "label": label,
        "send": send,
        "hello_in_delta": hello_delta,
        "log": log,
        "interesting_log": _interesting_log(log),
    }
    logger.info(
        "injected %s: packets=%d captured=%d hello_in_delta=%d",
        label,
        len(send["sent"]),
        send["captured_matching"],
        hello_delta,
    )
    for line in phase["interesting_log"][-12:]:
        logger.info("r1 ospfd: %s", line)
    return phase


def _count_events(text):
    lines = text.splitlines()
    elections = sum("ISM[" in line and "(NeighborChange)" in line for line in lines)
    adjok = sum("AdjOK next-state=" in line for line in lines)
    state_changes = sum("ISM[" in line and "State change" in line for line in lines)
    router_refresh = sum("]: router-LSA refresh" in line for line in lines)
    network_events = sum(
        "Originate network-LSA" in line
        or line.strip().endswith("]: network-LSA refresh")
        or "MaxAge set to LSA[Type2:" in line
        for line in lines
    )
    return {
        "elections": elections,
        "adjok": adjok,
        "state_changes": state_changes,
        "router_refresh": router_refresh,
        "network_events": network_events,
    }


def _router_refresh_times(text):
    times = []
    for line in text.splitlines():
        if "]: router-LSA refresh" not in line:
            continue
        match = LOG_TS.match(line)
        if not match:
            continue
        stamp = _parse_log_ts(match.group(1))
        if stamp is not None:
            times.append(stamp)
    return times


def _router_refresh_intervals_ms(text):
    times = _router_refresh_times(text)
    return [
        round((later - earlier).total_seconds() * 1000, 3)
        for earlier, later in zip(times, times[1:])
    ]


def _wait_roles(r1, r1_dr=True, timeout=30):
    def check():
        iface = _interface_info(r1)
        if r1_dr:
            return (
                iface.get("state") == "DR"
                and iface.get("drAddress") == R1_LAN_IP
                and _neighbor_full(r1, R2_RID)
            )
        return iface.get("state") != "DR" and iface.get("drAddress") == R2_LAN_IP

    return bool(_wait_until(check, timeout=timeout, interval=0.2))


def _restore_and_settle(r1, r2):
    """Inject the real DR/BDR fields and wait for the baseline roles."""
    _inject(
        r2,
        r1,
        "restore_%d" % time.time_ns(),
        "burst",
        1,
        0,
        0.5,
        [{"dr": R1_LAN_IP, "bdr": R2_LAN_IP, "priority": 100}],
    )
    assert _wait_roles(
        r1, r1_dr=True, timeout=30
    ), "baseline roles did not restore: %s" % _interface_info(r1)


def _expect_baseline():
    tgen = get_topogen()
    r1 = tgen.gears[R1]
    assert _wait_roles(
        r1, r1_dr=True, timeout=ADJACENCY_TIMEOUT
    ), "baseline DR/Full not reached: %s" % _interface_info(r1)
    assert _neighbor_full(tgen.gears[R2], R1_RID), "r2 does not see r1 Full"


def test_adjacency_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()
    r1 = tgen.gears[R1]
    assert (
        _min_ls_interval(r1) == MIN_LS_INTERVAL_MS
    ), "MinLSInterval did not take effect: %s" % _min_ls_interval(r1)


def test_no_injection_control():
    """Without injection no election or LSA re-origination happens."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    _sync_peer_hello(r1)
    seq_before = _router_lsa_seq(r1)
    offset = _log_offset(r1)
    time.sleep(3.0)
    events = _count_events(_log_since(r1, offset))
    assert events["elections"] == 0, "untriggered elections: %s" % events
    assert events["adjok"] == 0, "untriggered AdjOK events: %s" % events
    assert events["router_refresh"] == 0, "untriggered router-LSA refresh: %s" % events
    assert events["network_events"] == 0, "untriggered network-LSA events: %s" % events
    assert _router_lsa_seq(r1) == seq_before, "router-LSA sequence moved untriggered"


def test_invalid_checksum_control():
    """A Hello with a corrupted OSPF checksum must have no effect."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    _sync_peer_hello(r1)
    phase = _inject(
        r2,
        r1,
        "invalid_checksum",
        "invalid",
        1,
        0,
        1.0,
        [{"dr": R2_LAN_IP, "bdr": "0.0.0.0", "priority": 255}],
    )
    assert phase["hello_in_delta"] >= 0
    events = _count_events(phase["log"])
    assert events["elections"] == 0, (
        "corrupted-Checksum Hello triggered an election: %s" % phase["interesting_log"]
    )
    assert events["router_refresh"] == 0
    assert _neighbor_full(r1, R2_RID), "corrupted Hello disturbed the adjacency"


def test_legit_dr_change_converges_bounded():
    """An isolated, legitimate DR field change still elects promptly and
    converges back within a bounded time (one MinLSInterval plus slack)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    _sync_peer_hello(r1)
    phase = _inject(
        r2,
        r1,
        "legit_dr_change",
        "burst",
        1,
        0,
        0.5,
        [{"dr": R2_LAN_IP, "bdr": "0.0.0.0", "priority": 255}],
    )
    assert (
        phase["hello_in_delta"] >= 1
    ), "legit change Hello was captured on the wire but r1 receipt not verified"
    assert _wait_roles(r1, r1_dr=False, timeout=MIN_LS_INTERVAL_MS / 1000 + 5), (
        "legitimate DR change did not converge within a bounded time: %s"
        % _interface_info(r1)
    )
    events = _count_events(phase["log"])
    assert events["elections"] >= 1, (
        "legitimate DR change did not trigger an election: %s"
        % phase["interesting_log"]
    )
    _restore_and_settle(r1, r2)


def _churn_phase(r1, r2, kind, variants):
    """One burst phase: inject, observe, restore, settle; return the
    measured per-phase evidence."""
    _sync_peer_hello(r1)
    label = "churn_%s" % kind
    phase = _inject(
        r2,
        r1,
        label,
        "burst",
        BURST_COUNT,
        BURST_SPACING,
        CAPTURE_TAIL,
        variants,
    )
    events = _count_events(phase["log"])
    intervals = _router_refresh_intervals_ms(phase["log"])
    _restore_and_settle(r1, r2)
    return {
        "label": label,
        "sent": len(phase["send"]["sent"]),
        "hello_in_delta": phase["hello_in_delta"],
        "events": events,
        "router_refresh_intervals_ms": intervals,
    }


def test_election_churn_rate_limited():
    """Bursts of Hello DR/BDR/priority flips must produce bounded
    election/AdjOK/LSA work that respects MinLSInterval."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    assert _wait_roles(
        r1, r1_dr=True, timeout=30
    ), "churn test requires the baseline roles: %s" % _interface_info(r1)
    kinds = {
        "dr": [
            {"dr": R1_LAN_IP, "bdr": "0.0.0.0", "priority": 255},
            {"dr": R2_LAN_IP, "bdr": "0.0.0.0", "priority": 255},
        ],
        "bdr": [
            {"dr": R1_LAN_IP, "bdr": "0.0.0.0", "priority": 100},
            {"dr": R1_LAN_IP, "bdr": R2_LAN_IP, "priority": 100},
        ],
        "priority": [
            {"dr": R2_LAN_IP, "bdr": "0.0.0.0", "priority": 0},
            {"dr": R2_LAN_IP, "bdr": "0.0.0.0", "priority": 255},
        ],
    }
    failures = []
    for kind, variants in kinds.items():
        result = _churn_phase(r1, r2, kind, variants)
        logger.info("churn phase %s: %s", kind, json.dumps(result, sort_keys=True))
        events = result["events"]
        if not (result["hello_in_delta"] >= result["sent"]):
            failures.append(
                "%s: valid Hello receipt not verified (hello_in_delta=%d sent=%d)"
                % (kind, result["hello_in_delta"], result["sent"])
            )
        for key in ("elections", "adjok", "state_changes", "router_refresh"):
            if events[key] > MAX_ELECTIONS_PER_BURST:
                failures.append(
                    "%s: %s=%d exceeds the coalescing bound %d"
                    % (kind, key, events[key], MAX_ELECTIONS_PER_BURST)
                )
        below = [
            interval
            for interval in result["router_refresh_intervals_ms"]
            if interval < MIN_LS_INTERVAL_MS - MIN_LS_SLACK_MS
        ]
        if below:
            failures.append(
                "%s: router-LSA re-originated below MinLSInterval (%dms): %s"
                % (kind, MIN_LS_INTERVAL_MS, below)
            )
    assert not failures, "election churn was not rate limited: %s" % failures
    assert _ospfd_pid(r1), "ospfd died during the churn phases"


def test_final_full_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    assert _ospfd_pid(r1), "ospfd not running on r1"
    assert _ospfd_pid(r2), "ospfd not running on r2"
    _expect_baseline()
    tgen = get_topogen()
    pcaps = [name for name in os.listdir(tgen.logdir) if name.endswith(".pcap")]
    assert "churn_dr.pcap" in pcaps, "churn pcap evidence missing: %s" % pcaps
