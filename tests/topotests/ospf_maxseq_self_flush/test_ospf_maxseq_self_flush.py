#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_maxseq_self_flush.py
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_ospf_maxseq_self_flush.py
==============================

Regression for the MaxSeq self-flush of a self-originated router-LSA
(CVE-2017-3224 class, RFC 2328 Sections 13.4 and 14.1).

A forged router-LSA that carries the victim's router ID as LS ID and
advertising router with LS sequence number MaxSequenceNumber (0x7fffffff)
and a small LS age forces a vulnerable ospfd to adopt the sequence number.
Re-originating one past it wraps the sequence number, and ospf_lsa_install()
then prematurely ages the victim's own LSA and floods the MaxAge copy.  The
recovery instance (InitialSequenceNumber) is older than the forged MaxSeq
copy under the signed Section 13.1 sequence comparison, so the whole domain
drops it until the MaxAge copy is garbage-collected (~60s), and one packet
per minute keeps the victim's router-LSA suppressed forever.

Fixed ospfd refuses to adopt a received MaxSequenceNumber instance: it
fights back with the next sequence number in the normal range instead, so
its own LSA is never flushed, its sequence number never wraps and no
suppression window opens.

Topology
--------

    r1 (victim, RID 10.255.2.1, DR, pri 200) ---eth0--- r2 (peer, RID 10.255.2.2, DROther, pri 0)

r1 originates 198.51.100.1/32 on lo.  r2 injects the forged LSU on the
broadcast segment towards 224.0.0.6 with TTL 1, exactly as the manual
reproducer does.

Test plan
---------

1. Baseline: adjacency Full (r1 sees DROther, r2 sees DR), both LSDBs hold
   the victim router-LSA with a normal-range sequence number, r2 has the
   route to 198.51.100.1/32.
2. Control: 5 samples without trigger must stay stable.
3. Trigger: inject the forged MaxSeq router-LSA from r2.
4. Observation for 85s (~60s MaxAge window plus margin): the victim LSA
   must never reach MaxSequenceNumber or MaxAge on either router, the
   forged copy must never be installed on r2, the route must stay present,
   no "Premature Aging" may be logged on r1, and both ospfd processes must
   survive.
"""

import json
import os
import sys
import time

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]

VICTIM = "r1"
PEER = "r2"
VICTIM_RID = "10.255.2.1"
PEER_RID = "10.255.2.2"
PEER_IP = "10.242.2.2"
TARGET_PREFIX = "198.51.100.1/32"
MAXSEQ = 0x7FFFFFFF
MAXAGE = 3600
BASELINE_TIMEOUT = 90
CONTROL_SAMPLES = 5
POST_TRIGGER_TIMEOUT = 85
DENSE_SAMPLE_SECONDS = 5
DENSE_INTERVAL = 0.25
SAMPLE_INTERVAL = 1.0


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_link(r1, r2, ifname1="eth0", ifname2="eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _find_victim_lsa(value):
    if isinstance(value, dict):
        if (
            value.get("lsId") == VICTIM_RID
            and value.get("advertisedRouter") == VICTIM_RID
            and "sequenceNumber" in value
            and "lsaAge" in value
        ):
            return value
        for child in value.values():
            found = _find_victim_lsa(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_victim_lsa(child)
            if found is not None:
                return found
    return None


def _victim_lsa(router):
    """Return (seq_int, age) of the victim router-LSA, or None if absent."""
    for _ in range(3):
        raw = router.vtysh_cmd("show ip ospf database json")
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            time.sleep(0.2)
            continue
        lsa = _find_victim_lsa(decoded)
        if lsa is None:
            return None
        return int(str(lsa["sequenceNumber"]), 16), int(lsa["lsaAge"])
    raise AssertionError("show ip ospf database json failed on %s" % router.name)


def _peer_route_present(router):
    out = router.cmd("ip route show %s" % TARGET_PREFIX)
    return "198.51.100.1" in out


def _neighbor_state(router):
    return router.vtysh_cmd("show ip ospf neighbor")


def _ospfd_pid(router):
    return router.cmd("pidof ospfd || true").strip()


def _is_normal(lsa):
    """LSA present, sequence number inside the normal range, not MaxAge."""
    return bool(lsa and lsa[0] != MAXSEQ and lsa[1] < MAXAGE)


def _sample(victim, peer):
    return {
        "victim": _victim_lsa(victim),
        "peer": _victim_lsa(peer),
        "peer_route": _peer_route_present(peer),
    }


def _log_has_premature_aging(tgen, router_name):
    log_path = os.path.join(tgen.logdir, router_name, "ospfd.log")
    if not os.path.exists(log_path):
        return False
    with open(log_path, errors="replace") as fp:
        return any("Premature Aging" in line for line in fp)


def test_ospf_maxseq_self_flush():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    victim = tgen.gears[VICTIM]
    peer = tgen.gears[PEER]

    # Baseline: adjacency, LSAs and route must converge first.
    deadline = time.monotonic() + BASELINE_TIMEOUT
    baseline = None
    while time.monotonic() < deadline:
        victim_nbrs = _neighbor_state(victim)
        peer_nbrs = _neighbor_state(peer)
        candidate = _sample(victim, peer)
        if (
            "Full/DROther" in victim_nbrs
            and "Full/DR" in peer_nbrs
            and _is_normal(candidate["victim"])
            and _is_normal(candidate["peer"])
            and candidate["peer_route"]
        ):
            baseline = candidate
            break
        time.sleep(1)
    assert baseline is not None, (
        "baseline did not converge within %ds: last sample %s, "
        "victim neighbors:\n%s\npeer neighbors:\n%s"
        % (BASELINE_TIMEOUT, candidate, victim_nbrs, peer_nbrs)
    )
    logger.info("baseline: %s", json.dumps(baseline, default=str, sort_keys=True))

    # Control: without the trigger nothing may change.
    for index in range(CONTROL_SAMPLES):
        time.sleep(1)
        control = _sample(victim, peer)
        assert _is_normal(
            control["victim"]
        ), "control sample %d: victim LSA unstable without trigger: %s" % (
            index,
            control["victim"],
        )
        assert _is_normal(
            control["peer"]
        ), "control sample %d: peer LSA unstable without trigger: %s" % (
            index,
            control["peer"],
        )
        assert control[
            "peer_route"
        ], "control sample %d: route to %s vanished without trigger" % (
            index,
            TARGET_PREFIX,
        )
        assert control["victim"][0] == baseline["victim"][0], (
            "control sample %d: victim sequence number moved without trigger" % index
        )

    pids_before = {VICTIM: _ospfd_pid(victim), PEER: _ospfd_pid(peer)}
    assert pids_before[VICTIM] and pids_before[PEER], "ospfd not running"

    # Trigger: forged MaxSeq router-LSA for the victim, sent by the peer.
    src_mac = peer.cmd("cat /sys/class/net/eth0/address").strip()
    out = peer.cmd_raises(
        "python3 %s/inject_maxseq.py eth0 %s %s %s %s"
        % (CWD, PEER_IP, src_mac, PEER_RID, VICTIM_RID)
    )
    logger.info("trigger: %s", out.strip())

    trigger_mono = time.monotonic()
    self_flush_violations = []
    poison_violations = []
    route_violations = []
    final_sample = None
    last_signature = None
    next_progress = 10

    while time.monotonic() - trigger_mono < POST_TRIGGER_TIMEOUT:
        elapsed = time.monotonic() - trigger_mono
        current = _sample(victim, peer)
        final_sample = current
        signature = (current["victim"], current["peer"], current["peer_route"])
        if signature != last_signature or elapsed >= next_progress:
            logger.info(
                "t=%.2f victim=%s peer=%s route=%s",
                elapsed,
                current["victim"],
                current["peer"],
                current["peer_route"],
            )
            last_signature = signature
            next_progress = max(next_progress, int(elapsed) + 10)

        # The victim's own LSA must never be forced to MaxSeq/MaxAge.
        if not _is_normal(current["victim"]):
            self_flush_violations.append((elapsed, current["victim"]))
        # The forged copy must never be installed on the peer.
        if current["peer"] is not None and current["peer"][0] == MAXSEQ:
            poison_violations.append((elapsed, current["peer"]))
        # The route through the victim must stay present.
        if not current["peer_route"]:
            route_violations.append(elapsed)

        if elapsed < DENSE_SAMPLE_SECONDS:
            time.sleep(DENSE_INTERVAL)
        else:
            time.sleep(SAMPLE_INTERVAL)

    pids_after = {VICTIM: _ospfd_pid(victim), PEER: _ospfd_pid(peer)}
    victim_flushed = _log_has_premature_aging(tgen, VICTIM)

    assert not self_flush_violations, (
        "victim router-LSA was flushed by a forged MaxSeq instance "
        "(self-flush): %s" % self_flush_violations[:5]
    )
    assert not poison_violations, (
        "peer installed the forged MaxSequenceNumber copy of the victim "
        "router-LSA: %s" % poison_violations[:5]
    )
    assert not route_violations, (
        "route to %s disappeared for ~%ds after the forged MaxSeq LSA "
        "(recovery suppression window)" % (TARGET_PREFIX, len(route_violations))
    )
    assert not victim_flushed, (
        "victim logged 'Premature Aging' for its own router-LSA after the "
        "forged MaxSeq LSA"
    )
    assert pids_after == pids_before and all(
        pids_after.values()
    ), "ospfd pid changed across the trigger: %s -> %s" % (pids_before, pids_after)
    assert _is_normal(final_sample["victim"]) and _is_normal(final_sample["peer"]), (
        "final LSDB state abnormal: %s" % final_sample
    )
    assert final_sample["peer_route"], "route to %s missing at the end" % TARGET_PREFIX

    _neighbor_state(victim)
    victim.expect_ospfv2_neighbor(PEER_RID)
    peer.expect_ospfv2_neighbor(VICTIM_RID)
