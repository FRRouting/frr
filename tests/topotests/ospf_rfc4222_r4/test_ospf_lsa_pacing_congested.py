#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_lsa_pacing_congested.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_lsa_pacing_congested.py
==================================

RFC4222 R4 LSA Gap Pacing under a congested 100 Kbps link.

Topology
--------

    R1 ----eth1---- R2
    (sender)        (observer)

The eth1 link on R1 is shaped to 100 Kbps using Linux tc/tbf so that
back-to-back LSU bursts cause measurable queuing delay.  This creates
conditions where:

  - Without pacing: a burst of LSUs fills the tx buffer and can delay
    or starve Hello packets, risking adjacency drops.

  - With pacing (G=200ms, max-lsas=1): LSUs are metered, the 100 Kbps
    link is never saturated by OSPF traffic, and Hellos are delivered
    without delay.

Link shaping
------------

    tc qdisc add dev <eth1> root handle 1: tbf rate 100kbit burst 4kb latency 100ms

100 Kbps gives ~12.5 KB/s throughput.  A single OSPF Hello is ~60 bytes
(~0.5 ms at 100 Kbps).  An LSU carrying one Type-5 LSA is ~96 bytes
(~8 ms at 100 Kbps).  With NUM_ROUTES=10 LSAs sent back-to-back the burst
occupies ~80 ms — well within the 4s dead interval but enough to show
measurable inter-packet spacing with pacing enabled.

PCAP capture
------------

tcpdump captures all traffic on R1's eth1 during the test.  Captures are
written to pcaps/ relative to the test working directory and can be
inspected afterward with Wireshark or tshark to verify LSU spacing.

Test plan
---------

1. test_congested_no_pacing_adjacency_stable
     Baseline: without pacing, all LSAs are flooded as a burst.
     The adjacency must survive (Hellos are not completely starved
     on a 100 Kbps link for a small number of LSAs).
     Verifies the legacy flood path works under mild congestion.

2. test_congested_pacing_slows_flood
     With pacing (G=200ms, max-lsas=1): the first LSA arrives at R2
     quickly but the remaining LSAs are held in the per-neighbor queue,
     proving pacing intercepts the flood even under a shaped link.

3. test_congested_pacing_delivers_all
     Correctness under congestion: all NUM_ROUTES LSAs eventually reach
     R2 when pacing is active on the shaped link.

4. test_congested_adjacency_survives_pacing
     Adjacency health: R1–R2 adjacency remains Full while pacing is
     active and LSAs are being drained.  This is the key regression
     guard for the Hello starvation issue — if LSUs starve Hellos the
     adjacency drops and this test fails.

5. test_congested_heavy_load_no_duplicate_retransmits
     Regression guard for paced-retransmit duplicate growth: an ACK
     blackout forces queue residence to exceed the retransmit interval
     while a heavy LSA load is draining.  The retransmit timer must
     reschedule queued LSAs instead of enqueuing duplicate copies
     (r4_qnode dedup), and returning ACKs must purge queued stale
     copies.  Without the fix the queue grows a new generation of
     duplicates every retransmit interval and convergence after the
     blackout blows well past the asserted budget.
"""

import os
import sys
import time

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib import topotest
from lib.common_config import step
from util_pcap import PerInterfacePcapManager

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Number of routes injected as Type-5 LSAs.  Kept higher than the functional
# tests to create a more meaningful burst on the shaped link.
NUM_ROUTES = 10
TEST_PREFIXES = ["10.88.{}.0/24".format(i) for i in range(1, NUM_ROUTES + 1)]
PREFIX_TAG = "10.88."

# Pacing parameters for the congested tests
GAP_MS = 200  # 200 ms inter-LSU gap — well above the ~8 ms LSU tx time
MAX_LSAS = 1  # one LSA per LSU — clean 1:1 timing
ADJINT_MS = 60000  # freeze gap adjuster

# Link shaping — 100 Kbps
LINK_RATE = "100kbit"
LINK_BURST = "4kb"
LINK_LATENCY = "100ms"
R1_ETH1 = "eth1"  # interface name inside R1's network namespace

# Heavy-load / duplicate-suppression test (test 5) parameters
NUM_ROUTES_HEAVY = 20  # heavier burst than the other congested tests
HEAVY_GAP_MS = 500  # 500 ms gap -> 10 s drain for 20 LSAs
HEAVY_RXMT_S = 3  # retransmit interval well below drain time
HEAVY_DEAD_S = 60  # survive the ACK blackout without dead-timer expiry
BLACKOUT_S = 13  # > 4 retransmit intervals of ACK loss
HEAVY_PREFIXES = ["10.99.{}.0/24".format(i) for i in range(1, NUM_ROUTES_HEAVY + 1)]
HEAVY_TAG = "10.99."

# Global pcap manager
PM = None


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


def build_topo(tgen):
    """Two-router topology: R1 (sender) — R2 (observer)."""
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")


# ---------------------------------------------------------------------------
# Module-level setup / teardown
# ---------------------------------------------------------------------------


def teardown_module():
    """Placeholder — topology is destroyed per test in teardown_function."""
    pass


def _setup_topology(test_name):
    """Create and start a fresh topology for one test function."""
    logger.info("RFC4222 R4 congested link test: R1 --[100Kbps]--> R2 [%s]", test_name)

    tgen = Topogen(build_topo, test_name)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config("frr.conf")

    tgen.start_router()

    r1 = tgen.gears["r1"]
    r1.cmd(
        "tc qdisc add dev {} root handle 1: tbf "
        "rate {} burst {} latency {}".format(
            R1_ETH1, LINK_RATE, LINK_BURST, LINK_LATENCY
        )
    )
    logger.info(
        "R1 %s shaped to %s (burst=%s latency=%s)",
        R1_ETH1,
        LINK_RATE,
        LINK_BURST,
        LINK_LATENCY,
    )

    r1.vtysh_cmd("configure terminal\n" "router ospf\n" "redistribute static\n" "end")

    global PM
    PM = PerInterfacePcapManager(outdir="pcaps", tag="congested")
    PM.start_all(tgen)

    for (rname, ifn), pid in list(PM.pids.items()):
        if rname != "r1":
            router = tgen.routers().get(rname)
            if router:
                router.cmd(f"kill -TERM {pid} >/dev/null 2>&1 || true")
                router.cmd(f"kill -KILL {pid} >/dev/null 2>&1 || true")
            PM.pids.pop((rname, ifn), None)

    # Wait for adjacency to form (hello=1s, dead=4s)
    time.sleep(12)


def _teardown_topology():
    """Stop pcap and destroy the topology created by _setup_topology."""
    tgen = get_topogen()
    global PM
    if PM:
        PM.stop_all(tgen)
        PM = None
    tgen.stop_topology()


def setup_function(func):
    _setup_topology(func.__name__)


def teardown_function():
    _teardown_topology()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enable_pacing(r1):
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap {gap} max-gap {gap}\n"
        "ip ospf lsa-pacing initial-gap {gap}\n"
        "ip ospf lsa-pacing max-lsas-per-update {max_lsas}\n"
        "ip ospf lsa-pacing adjust-interval {adjint}\n"
        "end".format(gap=GAP_MS, max_lsas=MAX_LSAS, adjint=ADJINT_MS)
    )
    cfg = r1.vtysh_cmd("show running-config")
    assert (
        "ip ospf lsa-pacing" in cfg
    ), "lsa-pacing did not appear in running-config — vtysh command failed"


def _disable_pacing(r1):
    r1.vtysh_cmd(
        "configure terminal\n" "interface eth1\n" "no ip ospf lsa-pacing\n" "end"
    )


def _add_routes(r1):
    r1.vtysh_cmd(
        "configure terminal\n"
        + "".join("ip route {} null0\n".format(p) for p in TEST_PREFIXES)
        + "end"
    )


def _remove_routes(r1):
    r1.vtysh_cmd(
        "configure terminal\n"
        + "".join("no ip route {} null0\n".format(p) for p in TEST_PREFIXES)
        + "end"
    )


def _count_external_lsas(router):
    out = router.vtysh_cmd("show ip ospf database external")
    return sum(
        1 for line in out.splitlines() if "Link State ID" in line and PREFIX_TAG in line
    )


def _wait_lsas(router, expected, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _count_external_lsas(router) == expected:
            return expected
        time.sleep(0.2)
    return _count_external_lsas(router)


def _wait_at_least(router, minimum, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _count_external_lsas(router) >= minimum:
            return _count_external_lsas(router)
        time.sleep(0.1)
    return _count_external_lsas(router)


def _rxmt_list_count(r1, neighbor_id="2.2.2.2"):
    """Return R1's LS retransmission list length toward neighbor_id, or -1."""
    out = r1.vtysh_cmd("show ip ospf neighbor {} json".format(neighbor_id), isjson=True)
    nbr_list = out.get("default", {}).get(neighbor_id)
    if not nbr_list:
        return -1
    return nbr_list[0].get("linkStateRetransmissionListCounter", -1)


def _count_heavy_lsas(router):
    out = router.vtysh_cmd("show ip ospf database external")
    return sum(
        1 for line in out.splitlines() if "Link State ID" in line and HEAVY_TAG in line
    )


def _wait_heavy_lsas(router, expected, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _count_heavy_lsas(router) == expected:
            return expected
        time.sleep(0.2)
    return _count_heavy_lsas(router)


def _adjacency_is_full(r1, neighbor_id="2.2.2.2"):
    """Return True if R1's adjacency with neighbor_id is Full."""
    out = r1.vtysh_cmd("show ip ospf neighbor {} json".format(neighbor_id), isjson=True)
    nbr_list = out.get("default", {}).get(neighbor_id)
    if not nbr_list:
        return False
    state = nbr_list[0].get("nbrState", "")
    return state.split("/", 1)[0] == "Full"


def _wait_adjacency_full(r1, timeout_s=20, neighbor_id="2.2.2.2"):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _adjacency_is_full(r1, neighbor_id):
            return True
        time.sleep(0.5)
    return False


def _dead_timer_due_ms(r1, neighbor_id="2.2.2.2"):
    """Return the remaining ms on R1's inactivity (dead) timer for
    neighbor_id, or -1 if unavailable."""
    out = r1.vtysh_cmd("show ip ospf neighbor {} json".format(neighbor_id), isjson=True)
    nbr_list = out.get("default", {}).get(neighbor_id)
    if not nbr_list:
        return -1
    due = nbr_list[0].get("routerDeadIntervalTimerDueMsec", -1)
    return due if isinstance(due, int) else -1


def _wait_dead_timer_above(r1, min_ms, timeout_s, neighbor_id="2.2.2.2"):
    """Wait until R1's inactivity timer countdown exceeds min_ms.

    Changing ip ospf dead-interval only affects future re-arms: the
    currently armed timer keeps its old deadline until one more Hello
    is accepted. This helper proves the re-arm happened before the
    test does anything that blocks Hellos.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _dead_timer_due_ms(r1, neighbor_id) > min_ms:
            return True
        time.sleep(0.3)
    return False


# ---------------------------------------------------------------------------
# Test 1: baseline — no pacing, adjacency survives burst on congested link
# ---------------------------------------------------------------------------


def test_congested_no_pacing_adjacency_stable():
    """
    Baseline: without pacing, all LSAs are sent as a burst on the 100 Kbps
    link.  The adjacency must survive — Hellos are not completely starved
    for NUM_ROUTES=10 LSAs (~80ms burst at 100Kbps, well under dead=4s).

    What this proves
    ----------------
    The legacy flood path is unaffected by R4 pacing code when pacing is
    off.  The shaped link adds real queuing delay but not enough to drop
    the adjacency for a moderate burst size.

    Verified in two independent phases so a failure is unambiguous
    about where the problem is:

      Phase 1 - precondition: R1 must actually originate all
      NUM_ROUTES external LSAs after redistribute-static picks up the
      injected routes. This is a redistribution/zebra step, unrelated
      to the legacy flood path being tested here.

      Phase 2 - the actual behavior under test: once R1 has all
      NUM_ROUTES LSAs, the legacy (unpaced) flood path must deliver
      them all to R2.

    Both phases use max(computed, 15s) rather than a tight computed
    budget, per topotest convention -- a loaded CI host gives no
    guarantee that either step finishes quickly even when everything
    is working correctly.

    If this test fails at Phase 2 the link shaping or Hello timing
    needs adjustment.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Test 1: no-pacing baseline on 100Kbps shaped link")

    # No pacing — legacy flood path
    _add_routes(r1)

    # Theoretical timeline: 1s throttle headroom + NUM_ROUTES * 50ms
    # per-LSU margin (conservative vs. the ~8ms actually measured at
    # 100Kbps) + 2s margin. Floored at 15s per topotest convention.
    pacing_time_total = 1 + NUM_ROUTES * 0.05 + 2
    timeout_s = max(pacing_time_total, 15)

    # Phase 1: confirm the precondition on R1 itself before timing the
    # legacy flood path.
    origin_count = _wait_lsas(r1, NUM_ROUTES, timeout_s)
    assert origin_count == NUM_ROUTES, (
        "R1 only originated {}/{} external LSAs within {:.1f}s of "
        "adding the routes. This is a redistribution/zebra issue "
        "(static route -> RIB -> kernel install -> redistribute), "
        "not the legacy flood path.".format(origin_count, NUM_ROUTES, timeout_s)
    )

    # Phase 2: now time the thing actually under test -- the legacy
    # flood path delivering to R2.
    count = _wait_lsas(r2, NUM_ROUTES, timeout_s)
    assert count == NUM_ROUTES, (
        "R1 originated all {} LSAs but only {}/{} arrived at R2 "
        "within {:.1f}s without pacing on 100Kbps link. Check link "
        "shaping parameters.".format(NUM_ROUTES, count, NUM_ROUTES, timeout_s)
    )

    # Adjacency must still be Full after the burst
    assert _adjacency_is_full(r1), (
        "Baseline: adjacency dropped after LSU burst on 100Kbps link "
        "without pacing. The burst may have starved Hellos."
    )

    # Cleanup
    _remove_routes(r1)
    _wait_lsas(r2, 0, timeout_s=20)


# ---------------------------------------------------------------------------
# Test 2: pacing intercepts flood on congested link
# ---------------------------------------------------------------------------


def test_congested_pacing_slows_flood():
    """
    With pacing active (G=200ms, max-lsas=1) on the 100Kbps link:
    the first LSA arrives at R2, but the rest are held in the per-neighbor
    queue behind the gap timer.

    This proves the R4 gate in ospf_flood_through_interface() works
    correctly even when the underlying link is constrained.

    The shaped link makes the timing more realistic — LSUs take ~8ms to
    transmit at 100Kbps, so the 200ms gap is meaningfully larger than the
    wire time, giving clear separation between packets in the pcap.

    This test asserts a negative, transient property ("not all LSAs
    have arrived yet"), unlike the other tests in this file. That
    property is checked immediately after the *first* LSA is observed
    at R2, not after a fixed wall-clock deadline from when the routes
    were added -- so widening the wait for that first arrival is safe
    and does not weaken the test: R4 only starts spacing sends apart
    once an LSA is actually queued, so "first arrival, then still
    incomplete" holds regardless of how long redistribution took to
    get that first LSA originated. (Contrast this with the other
    congested-link tests, where a precondition wait on R1 was added
    before timing R2 -- doing that here instead would risk the whole
    15s precondition wait completing only after R4's ~1.8s drain had
    already finished, which would make the "still queued" assertion
    fail for a reason unrelated to pacing.)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Test 2: pacing slows flood on 100Kbps shaped link")

    _enable_pacing(r1)
    _add_routes(r1)

    # Wait for the first LSA -- may be delayed by 1s LSA throttle plus
    # whatever redistribution/zebra takes. Floored at 15s per topotest
    # convention rather than the previous tight 4s.
    first = _wait_at_least(r2, 1, timeout_s=15)
    assert first >= 1, (
        "No LSA arrived at R2 within 15s on shaped link with pacing. "
        "Check adjacency and redistribution."
    )

    # Immediately after first LSA, the rest must still be queued
    count_now = _count_external_lsas(r2)
    assert count_now < NUM_ROUTES, (
        "Pacing had no effect on 100Kbps link: all {} LSAs arrived "
        "immediately. Expected remaining {} held in per-neighbor queue "
        "for {}ms each.".format(NUM_ROUTES, NUM_ROUTES - 1, GAP_MS)
    )

    # Cleanup
    _remove_routes(r1)
    _disable_pacing(r1)
    _wait_lsas(r2, 0, timeout_s=20)


# ---------------------------------------------------------------------------
# Test 3: pacing delivers all LSAs on congested link
# ---------------------------------------------------------------------------


def test_congested_pacing_delivers_all():
    """
    Correctness: all NUM_ROUTES LSAs reach R2 when pacing is active on
    the 100Kbps shaped link.

    Timeline with G=200ms, max-lsas=1, NUM_ROUTES=10:
      t+0s  : LSA-1  sent (delay=0, timer fires immediately)
      t+0.2s: LSA-2  sent
      ...
      t+1.8s: LSA-10 sent

    Verified in two independent phases so a failure is unambiguous
    about where the problem is:

      Phase 1 - precondition: R1 must actually originate all
      NUM_ROUTES external LSAs after redistribute-static picks up the
      injected routes. This step is entirely outside R4 pacing
      (static route -> zebra RIB -> kernel dataplane confirmation ->
      redistribute -> ospf_external_lsa_originate()) and its timing
      is not governed by GAP_MS at all. A failure here points at
      redistribution/zebra, not at R4 pacing.

      Phase 2 - the actual behavior under test: once R1 has all
      NUM_ROUTES LSAs queued, R4 pacing must drain them to R2. A
      failure here, with Phase 1 already confirmed, points at
      ospf_r4_nbr_send_timer() and the re-arm logic.

    Both phases use max(pacing_time_total, 15s) rather than timing to
    the computed best case: the 15s floor matches the project's
    general "look for state generously" topotest convention, since a
    CI host running many tests in parallel gives no guarantee that a
    given step finishes inside a tight window even when everything is
    working correctly. The shaped link adds ~8ms per packet at
    100Kbps, folded into pacing_time_total's margin term.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Test 3: pacing delivers all LSAs on 100Kbps shaped link")

    _enable_pacing(r1)
    _add_routes(r1)

    # Theoretical pacing timeline: 1s throttle headroom + (NUM_ROUTES-1)
    # gaps of GAP_MS + 2s margin/link-delay. Floored at 15s per
    # topotest convention -- a computed "just enough" budget doesn't
    # survive a loaded CI host.
    pacing_time_total = 1 + (NUM_ROUTES - 1) * (GAP_MS / 1000.0) + 2
    timeout_s = max(pacing_time_total, 15)

    # Phase 1: confirm the precondition on R1 itself before timing
    # anything pacing-related.
    origin_count = _wait_lsas(r1, NUM_ROUTES, timeout_s)
    assert origin_count == NUM_ROUTES, (
        "R1 only originated {}/{} external LSAs within {:.1f}s of "
        "adding the routes. This is a redistribution/zebra issue "
        "(static route -> RIB -> kernel install -> redistribute), "
        "not R4 pacing -- ospf_r4_nbr_send_timer() never had a "
        "chance to run.".format(origin_count, NUM_ROUTES, timeout_s)
    )

    # Phase 2: now time the thing actually under test -- R4 pacing
    # draining the queue to R2.
    count = _wait_lsas(r2, NUM_ROUTES, timeout_s)
    assert count == NUM_ROUTES, (
        "R1 originated all {} LSAs but only {}/{} reached R2 within "
        "{:.1f}s with pacing on the 100Kbps link (expected delivery "
        "at {}ms intervals). Check ospf_r4_nbr_send_timer() re-arm "
        "logic.".format(NUM_ROUTES, count, NUM_ROUTES, timeout_s, GAP_MS)
    )

    # Cleanup
    _remove_routes(r1)
    _disable_pacing(r1)
    _wait_lsas(r2, 0, timeout_s=20)


# ---------------------------------------------------------------------------
# Test 4: adjacency survives while pacing drains queue on congested link
# ---------------------------------------------------------------------------


def test_congested_adjacency_survives_pacing():
    """
    Key regression guard for Hello starvation under R4 pacing.

    When pacing is active and draining a queue of LSAs on a 100Kbps link,
    Hello packets must not be starved.  ospf_hello_send_sub() uses
    ospf_packet_add_top() to insert Hellos at the HEAD of oi->obuf,
    ahead of pending LSUs.  This test verifies that mechanism holds
    under real link congestion.

    Scenario
    --------
    1. Enable pacing with G=200ms (slow drain) and inject NUM_ROUTES LSAs.
    2. Poll the adjacency state continuously from the moment the routes
       are added, for long enough to cover both a possibly-slow
       redistribution round trip and the subsequent pacing drain.
       R4 starts pacing and sending each LSA as soon as *that one*
       originates, not once all NUM_ROUTES exist -- so if redistribution
       staggers origination, watching only starts after a separate
       precondition wait could let the real congestion happen entirely
       before monitoring begins, passing the test without observing
       anything. Watching continuously from t=0 avoids that gap.
    3. The adjacency must remain Full throughout — dead-interval is 4s,
       so even one missed Hello cycle (1s) must not drop the adjacency.
    4. Separately confirm R1 actually originated all NUM_ROUTES LSAs
       (this is a redistribution/zebra concern, not a Hello-starvation
       one) and that they all reached R2.

    If the adjacency drops it means Hellos are being delayed behind LSUs
    in either oi->obuf or the kernel socket send buffer — indicating the
    Hello priority mechanism is not working under the shaped link.

    The origination precondition and the final delivery check both use
    max(computed, 15s) rather than a tight computed budget, per
    topotest convention -- a loaded CI host gives no guarantee that
    either step finishes quickly even when everything is working
    correctly.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Test 4: adjacency survives pacing drain on 100Kbps shaped link")

    _enable_pacing(r1)
    _add_routes(r1)

    # Theoretical pacing timeline, floored at 15s per topotest convention.
    pacing_time_total = 1 + (NUM_ROUTES - 1) * (GAP_MS / 1000.0) + 2
    timeout_s = max(pacing_time_total, 15)

    # Monitor adjacency continuously from the moment the routes are
    # added, for timeout_s (covering a possibly-slow redistribution
    # round trip) plus the pacing drain duration -- rather than waiting
    # for an origination precondition first and watching a separate
    # window afterward, which could let the real congestion finish
    # entirely before monitoring ever starts.
    drain_duration = (NUM_ROUTES - 1) * (GAP_MS / 1000.0) + 1.0
    monitor_end = time.time() + timeout_s + drain_duration
    adjacency_dropped = False

    while time.time() < monitor_end:
        if not _adjacency_is_full(r1):
            adjacency_dropped = True
            break
        time.sleep(0.2)

    assert not adjacency_dropped, (
        "Adjacency dropped to non-Full while R4 pacing was draining {} LSAs "
        "on 100Kbps link with G={}ms. "
        "Hellos may be starved by LSUs in oi->obuf or kernel socket buffer. "
        "Check ospf_hello_send_sub() uses ospf_packet_add_top().".format(
            NUM_ROUTES, GAP_MS
        )
    )

    # Confirm R1 actually originated everything -- the monitor loop
    # above already spanned timeout_s, so this should already be true;
    # a distinct failure here points at redistribution/zebra, not
    # Hello starvation.
    origin_count = _wait_lsas(r1, NUM_ROUTES, timeout_s=1)
    assert origin_count == NUM_ROUTES, (
        "R1 only originated {}/{} external LSAs even after {:.1f}s of "
        "monitoring. This is a redistribution/zebra issue, not a "
        "Hello-starvation problem.".format(
            origin_count, NUM_ROUTES, timeout_s + drain_duration
        )
    )

    # Also verify all LSAs arrived correctly at R2.
    count = _wait_lsas(r2, NUM_ROUTES, timeout_s)
    assert count == NUM_ROUTES, (
        "R1 originated all {} LSAs and the adjacency survived, but only "
        "{}/{} reached R2 within {:.1f}s.".format(
            NUM_ROUTES, count, NUM_ROUTES, timeout_s
        )
    )

    # Cleanup
    _remove_routes(r1)
    _disable_pacing(r1)
    _wait_lsas(r2, 0, timeout_s=20)


# ---------------------------------------------------------------------------
# Test 5: heavy load + ACK blackout — no duplicate paced retransmits
# ---------------------------------------------------------------------------


def test_congested_heavy_load_no_duplicate_retransmits():
    """
    Regression guard for the paced-retransmit duplicate-growth bug and
    the stale-copy purge on ACK (r4_qnode tracking).

    Scenario
    --------
    An ACK blackout makes queue residence exceed the retransmit
    interval — the exact regime where the unfixed code melts down:

    1. Raise dead-interval to 60s on both routers so the blackout does
       not expire the adjacency, and set retransmit-interval to 3s on
       R1 (well below the 10s queue drain time).
    2. Enable pacing with a fixed 500ms gap, one LSA per LSU.
    3. Drop all inbound OSPF on R1 (iptables): R2 still receives and
       ACKs R1's LSUs, but the ACKs never reach R1.
    4. Inject NUM_ROUTES_HEAVY=20 routes, then confirm R1 has actually
       originated all of them before the 13s blackout clock starts.
       This origination step is a redistribution/zebra precondition,
       not part of what's under test: if it were left unverified and
       ran long, it could eat into BLACKOUT_S uncounted, leaving too
       little unacked load built up (or in the worst case none at
       all) for the retransmit timer to ever stress the
       duplicate-suppression path this test exists to exercise --
       while the test still reported a pass. Draining takes ~10s;
       every transmitted LSA stays unacknowledged on R1's
       retransmission list, and the retransmit timer fires 4+ times
       during the 13s blackout. A tripwire just before lifting the
       blackout confirms the retransmission list is actually
       non-empty, so a future regression here fails loudly instead of
       silently passing the convergence check below.
    5. Lift the blackout and measure convergence on R1: the LS
       retransmission list toward R2 must drain to 0 (sustained).

    What the fix changes
    --------------------
    - During the blackout each retransmit pass may re-enqueue an
      unacked LSA only if it has no copy waiting in the paced queue
      (r4_qnode dedup) — the queue stays bounded at one copy per LSA.
    - After the blackout, each arriving ACK purges the LSA's queued
      copy, so no stale copy is transmitted and re-added to the
      retransmission list ("zombie" re-add).

    Without the fix, every 3s retransmit pass enqueues a new generation
    of duplicates for every unacked LSA, and after the blackout each
    stale transmission re-adds an already-ACKed LSA to the
    retransmission list. Convergence then takes far longer than the
    CONVERGE_BUDGET_S asserted here (which the fixed code meets with
    several seconds of margin), and the test fails.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Test 5: heavy load + ACK blackout, no duplicate paced retransmits")

    # -- 1. Survive the blackout: dead-interval 60s on both sides.
    #    Configure R2 first, then R1; the transient hello-parameter
    #    mismatch may bounce the adjacency, so re-wait for Full.
    for rtr in (r2, r1):
        rtr.vtysh_cmd(
            "configure terminal\n"
            "interface eth1\n"
            "ip ospf dead-interval {}\n"
            "end".format(HEAVY_DEAD_S)
        )
    assert _wait_adjacency_full(r1, timeout_s=30), (
        "Adjacency did not return to Full after raising dead-interval "
        "to {}s on both routers.".format(HEAVY_DEAD_S)
    )

    #    The dead-interval change only takes effect on the NEXT accepted
    #    Hello: the already-armed inactivity timer keeps its old 4s
    #    deadline until then. Wait until R1's countdown proves the timer
    #    was re-armed with the new 60s value; only then is it safe to
    #    block inbound Hellos for the blackout.
    assert _wait_dead_timer_above(r1, min_ms=30000, timeout_s=10), (
        "R1's inactivity timer was not re-armed with the new {}s "
        "dead-interval within 10s (needs one accepted Hello after the "
        "config change) — cannot start the ACK blackout safely.".format(HEAVY_DEAD_S)
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf retransmit-interval {}\n"
        "end".format(HEAVY_RXMT_S)
    )

    # -- 2. Fixed-gap pacing: 500ms, one LSA per LSU, adjuster frozen.
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap {gap} max-gap {gap}\n"
        "ip ospf lsa-pacing initial-gap {gap}\n"
        "ip ospf lsa-pacing max-lsas-per-update 1\n"
        "ip ospf lsa-pacing adjust-interval {adjint}\n"
        "end".format(gap=HEAVY_GAP_MS, adjint=ADJINT_MS)
    )

    # -- 3. ACK blackout: drop all inbound OSPF (proto 89) on R1.
    r1.cmd("iptables -A INPUT -i {} -p 89 -j DROP".format(R1_ETH1))

    try:
        # -- 4. Heavy LSA load while ACKs are lost.
        r1.vtysh_cmd(
            "configure terminal\n"
            + "".join("ip route {} null0\n".format(p) for p in HEAVY_PREFIXES)
            + "end"
        )

        # Confirm R1 actually originated all NUM_ROUTES_HEAVY external
        # LSAs before starting the blackout clock. This is a
        # redistribution/zebra precondition, not part of what's under
        # test: if it's slow and eats into BLACKOUT_S uncounted, fewer
        # (or in the worst case zero) LSAs would ever be sent-and-stuck
        # unacked during the remaining blackout window, so the
        # retransmit timer would never see sustained unacked load and
        # the duplicate-suppression path this test exists to exercise
        # would go untested -- with the test still reporting a pass.
        origin_count = _wait_heavy_lsas(r1, NUM_ROUTES_HEAVY, timeout_s=15)
        assert origin_count == NUM_ROUTES_HEAVY, (
            "R1 only originated {}/{} heavy-load external LSAs within "
            "15s of adding the routes. This is a redistribution/zebra "
            "issue, not a pacing/retransmit problem -- the ACK "
            "blackout stress window was never entered.".format(
                origin_count, NUM_ROUTES_HEAVY
            )
        )

        blackout_end = time.time() + BLACKOUT_S
        while time.time() < blackout_end:
            assert _adjacency_is_full(r1), (
                "Adjacency dropped during the {}s ACK blackout despite "
                "dead-interval={}s — blackout setup is wrong.".format(
                    BLACKOUT_S, HEAVY_DEAD_S
                )
            )
            time.sleep(1)

        # Tripwire: confirm the blackout actually produced sustained
        # unacked load before declaring the stress condition exercised.
        # This catches (loudly, here) any future regression that lets
        # LSAs slip through unqueued -- rather than the test silently
        # passing the convergence check below because there was never
        # anything to converge.
        pre_lift_rxmt = _rxmt_list_count(r1)
        assert pre_lift_rxmt > 0, (
            "R1's LS retransmission list toward R2 was empty just "
            "before lifting the ACK blackout -- no unacked load was "
            "ever built up, so the duplicate-suppression path this "
            "test exists to exercise was never actually stressed."
        )
    finally:
        # -- 5. Lift the blackout.
        r1.cmd("iptables -D INPUT -i {} -p 89 -j DROP".format(R1_ETH1))

    # Convergence budget for the FIXED code: at most one queued copy per
    # LSA means <= NUM_ROUTES_HEAVY paced sends remain at unblock
    # (20 * 0.5s = 10s), plus one retransmit interval (3s) for stragglers
    # to be re-selected, plus scheduling margin. The unfixed code has
    # several duplicate generations queued plus zombie re-adds and needs
    # far longer.
    CONVERGE_BUDGET_S = (
        NUM_ROUTES_HEAVY * (HEAVY_GAP_MS / 1000.0) + 2 * HEAVY_RXMT_S + 6
    )

    deadline = time.time() + CONVERGE_BUDGET_S
    zero_streak = 0
    converged_at = None
    while time.time() < deadline:
        count = _rxmt_list_count(r1)
        if count == 0:
            zero_streak += 1
            if zero_streak >= 3:  # sustained: 3 consecutive 1s samples
                converged_at = time.time()
                break
        else:
            zero_streak = 0
        time.sleep(1)

    final_rxmt = _rxmt_list_count(r1)
    assert converged_at is not None, (
        "R1's LS retransmission list toward R2 did not drain to 0 within "
        "{:.0f}s of lifting the ACK blackout (still {} entries). With "
        "duplicate suppression and ACK purge this converges in ~15s; "
        "sustained non-zero indicates duplicate queue growth or stale "
        "queued copies re-adding ACKed LSAs to the retransmission "
        "list.".format(CONVERGE_BUDGET_S, final_rxmt)
    )
    logger.info(
        "rxmt list drained to 0 with %.0fs of budget to spare",
        deadline - converged_at,
    )

    # All LSAs must have reached R2 (R2 received them during the
    # blackout — only the ACKs were dropped).
    count = _count_heavy_lsas(r2)
    assert (
        count == NUM_ROUTES_HEAVY
    ), "Only {}/{} heavy-load LSAs present in R2's LSDB after " "convergence.".format(
        count, NUM_ROUTES_HEAVY
    )

    # Adjacency must have survived the whole exercise.
    assert _adjacency_is_full(r1), "Adjacency not Full after blackout recovery."

    # Cleanup
    r1.vtysh_cmd(
        "configure terminal\n"
        + "".join("no ip route {} null0\n".format(p) for p in HEAVY_PREFIXES)
        + "end"
    )
    _disable_pacing(r1)


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main(["-s", __file__]))
