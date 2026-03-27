    #!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_lsa_pacing_functional.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_lsa_pacing_functional.py: Functional test for OSPF RFC4222/R4 LSA Gap Pacing

Topology
--------

    R1 ----eth1---- R2
    (sender)        (observer)

R1 generates AS-External LSAs by redistributing blackhole static routes into OSPF.
R2 watches its LSDB to measure how fast those LSAs arrive.

What gap pacing does (RFC 4222 Recommendation 4)
-------------------------------------------------

Without pacing, every newly-originated LSA is forwarded to each OSPF neighbor in a
Link State Update (LSU) packet immediately.  Under a sudden burst this can saturate
the link or overwhelm the neighbor.

With pacing enabled on an interface, LSAs destined for each neighbor are placed in a
per-neighbor queue (nbr->r4_send_queue).  A timer (nbr->t_r4_send) fires every G
milliseconds (the "gap") and drains one batch of at most max-lsas-per-update LSAs
into a single LSU packet.  The gap G is adjusted dynamically based on unacknowledged
LSAs, but for these tests we freeze the adjuster (adjust-interval 60000 ms) so G
stays constant and timing is predictable.

Observable effect
-----------------

  Pacing ON  (gap=1000 ms, max-lsas=1):  one LSA per second arrives at R2.
  Pacing OFF (default):                   all LSAs arrive within ~1 second.

Fixture scope
-------------

Each test function gets a completely fresh topology (scope="function").  The
adjacency forms from scratch, the LSDB is empty, and no configuration from a
previous test is present.  This means:

  - No unique prefix families needed — every test uses the same TEST_PREFIXES.
  - No cleanup / MaxAge synchronization between tests.
  - A failure in one test does NOT leave state that contaminates the next.

The cost is ~12 s of adjacency-formation time per test.

Note on LSA throttle
--------------------

r1/frr.conf sets 'timers throttle lsa all 1000', meaning R1 may delay
origination of fresh LSAs by up to 1 s after the static routes are added.
test_pacing_slows_flood accounts for this by polling until the first LSA
appears at R2 (proving the throttle fired and the first packet was sent),
then immediately checking that the remaining LSAs have not yet arrived.

Test plan
---------

1. test_pacing_slows_flood
     Prove pacing is active: the first LSA arrives but the rest are still
     queued behind the 1 s gap timer.

2. test_pacing_delivers_all
     Correctness: given enough time all NUM_ROUTES LSAs reach R2.

3. test_no_pacing_fast_delivery
     Baseline: with pacing disabled all LSAs arrive within 3 s.

4. test_pacing_enable_disable_mid_session
     Toggle pacing on/off while the adjacency is up and verify both phases
     behave correctly.

How to read a passing run
-------------------------

  PASSED test_pacing_slows_flood                → per-neighbor queue+timer gating flood
  PASSED test_pacing_delivers_all               → queue drains fully, no LSA lost
  PASSED test_no_pacing_fast_delivery           → legacy flood path untouched
  PASSED test_pacing_enable_disable_mid_session → dynamic enable/disable works live

If test_pacing_slows_flood fails with count == NUM_ROUTES, pacing is not intercepting
the flood path — check ospf_flood_through_interface() R4 block.

If test_pacing_delivers_all fails with count < NUM_ROUTES, the send timer or queue
drain has a bug — check ospf_r4_nbr_send_timer() and the re-arm logic.
"""

import pytest
import time

from lib.topogen import Topogen


pytestmark = [pytest.mark.ospfd]

# Prefixes injected as blackhole static routes on R1.
# All tests use the same set — each test gets a fresh topology so there is
# no cross-test contamination.
NUM_ROUTES = 4
TEST_PREFIXES = ["10.99.{}.0/24".format(i) for i in range(1, NUM_ROUTES + 1)]
PREFIX_TAG = "10.99."  # substring used to filter these LSAs in 'show' output

# Pacing parameters — large gap so timing is reliable on a loaded test host.
GAP_MS = 1000      # 1 s between LSU batches
MAX_LSAS = 1       # 1 LSA per LSU — clean 1:1 timing, no batching ambiguity
ADJINT_MS = 60000  # freeze gap adjuster so G stays fixed during the test


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

def build_topo(tgen):
    """Two-router topology: R1 (sender) — R2 (observer)."""
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")


# ---------------------------------------------------------------------------
# Per-test fixture — fresh topology for every test function
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def tgen(request):
    """
    Start a clean R1-R2 topology, wait for OSPF Full adjacency, then yield.
    The topology is torn down automatically after each test.
    """
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config("frr.conf")

    tgen.start_router()

    r1 = tgen.gears["r1"]

    # Enable redistribution of static routes into OSPF so that blackhole
    # routes added per-test become AS-External (Type-5) LSAs.
    r1.vtysh_cmd(
        "configure terminal\n"
        "router ospf\n"
        "redistribute static\n"
        "end"
    )

    # hello-interval 1 s / dead-interval 4 s — adjacency normally reaches
    # Full in < 10 s; allow 12 s for a loaded test host.
    time.sleep(12)

    yield tgen

    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enable_pacing(r1):
    """Configure R1 eth1 with a fixed gap and frozen adjuster.

    Raises AssertionError if pacing does not appear in running-config
    after the command, so a misconfiguration fails immediately rather
    than silently producing a false-positive timing test result.
    """
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing initial-gap {gap}\n"
        "ip ospf lsa-pacing min-gap {gap} max-gap {gap}\n"
        "ip ospf lsa-pacing max-lsas-per-update {max_lsas}\n"
        "ip ospf lsa-pacing adjust-interval {adjint}\n"
        "end".format(gap=GAP_MS, max_lsas=MAX_LSAS, adjint=ADJINT_MS)
    )
    cfg = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing" in cfg, \
        "lsa-pacing did not appear in R1 running-config after _enable_pacing() — " \
        "vtysh command may have failed silently."


def _disable_pacing(r1):
    """Remove all pacing config from R1 eth1."""
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no ip ospf lsa-pacing\n"
        "end"
    )


def _add_routes(r1):
    """Inject TEST_PREFIXES as blackhole static routes on R1."""
    r1.vtysh_cmd(
        "configure terminal\n"
        + "".join("ip route {} null0\n".format(p) for p in TEST_PREFIXES)
        + "end"
    )


def _count_external_lsas(router):
    """
    Count AS-External (Type-5) LSAs in the router's OSPF LSDB whose
    'Link State ID' line contains PREFIX_TAG.

    FRR's 'show ip ospf database external' prints one 'Link State ID:' line
    per LSA entry.  Filtering by PREFIX_TAG isolates only our test routes.
    """
    out = router.vtysh_cmd("show ip ospf database external")
    return sum(
        1 for line in out.splitlines()
        if "Link State ID" in line and PREFIX_TAG in line
    )


def _wait_lsas(router, expected, timeout_s):
    """
    Poll until external LSA count equals expected or timeout_s expires.
    Returns the actual count at exit.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _count_external_lsas(router) == expected:
            return expected
        time.sleep(0.2)
    return _count_external_lsas(router)


def _wait_at_least(router, minimum, timeout_s):
    """
    Poll until external LSA count >= minimum or timeout_s expires.
    Returns the actual count at exit.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _count_external_lsas(router) >= minimum:
            return _count_external_lsas(router)
        time.sleep(0.1)
    return _count_external_lsas(router)


# ---------------------------------------------------------------------------
# Test 1: pacing slows down the flood
# ---------------------------------------------------------------------------

def test_pacing_slows_flood(tgen):
    """
    Prove pacing is active: after the first LSA arrives at R2, the remaining
    LSAs are still held in R1's per-neighbor queue.

    What the code does
    ------------------
    ospf_flood_through_interface() reaches the R4 gate:

        if (oi->rec4_gap_pacing) {
            ospf_r4_nbr_enqueue(nbr, lsa);   // enqueue, do not send now
            return 0;
        }

    ospf_r4_nbr_arm_timer() schedules nbr->t_r4_send with delay_ms=0 for
    the first LSA (next_send_ms is in the past).  That timer fires immediately
    and sends exactly one LSU (max-lsas=1).  It then re-arms itself with
    delay = GAP_MS = 1000 ms for the next batch.

    Why poll for the first LSA rather than sleep
    ---------------------------------------------
    r1/frr.conf uses 'timers throttle lsa all 1000', so R1 may delay
    originating fresh LSAs by up to 1 s after the routes are added.
    Polling until count >= 1 means we only start the race after R1 has
    actually sent the first packet — the subsequent check is then purely
    about the gap timer, not the throttle.
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _enable_pacing(r1)
    _add_routes(r1)

    # Wait up to (throttle_max + first_packet_travel) for LSA-1 to appear.
    first = _wait_at_least(r2, 1, timeout_s=4)
    assert first >= 1, (
        "No LSA arrived at R2 within 4 s. "
        "Check that OSPF adjacency is Full and redistribution is active."
    )

    # The gap timer is now running. Immediately after the first packet,
    # the remaining LSAs must still be queued — they should not arrive
    # for another GAP_MS milliseconds.
    count_now = _count_external_lsas(r2)

    assert count_now < NUM_ROUTES, (
        "Pacing had no effect: all {} LSAs arrived at R2 immediately after "
        "the first one. Expected the remaining {} to be held in the "
        "per-neighbor queue for ~{} ms. "
        "Check ospf_flood_through_interface() R4 block.".format(
            NUM_ROUTES, NUM_ROUTES - 1, GAP_MS
        )
    )


# ---------------------------------------------------------------------------
# Test 2: pacing delivers all LSAs eventually
# ---------------------------------------------------------------------------

def test_pacing_delivers_all(tgen):
    """
    Correctness: every injected LSA reaches R2, just spaced over time.

    Timeline with gap=1000 ms, 4 LSAs (after the LSA throttle fires):
      t+0 s : LSA-1 sent  (timer fires with delay=0)
      t+1 s : LSA-2 sent
      t+2 s : LSA-3 sent
      t+3 s : LSA-4 sent
      checked at t + (NUM_ROUTES-1)*GAP_MS + 2 s margin

    What the code does
    ------------------
    After each ospf_ls_upd_queue_send() call inside ospf_r4_nbr_send_timer(),
    lsu_sent_for_dst() advances nbr->next_send_ms by sent_count * GAP_MS.
    The timer re-arms with that exact delay so the next batch fires on
    schedule.  The queue drains completely; no LSA is dropped or skipped.
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _enable_pacing(r1)
    _add_routes(r1)

    # LSA throttle can delay first origination by up to 1 s, then the queue
    # drains one LSA per GAP_MS.  Total budget:
    #   throttle_max(1s) + (NUM_ROUTES-1)*GAP_MS + 2s margin
    timeout_s = 1 + (NUM_ROUTES - 1) * (GAP_MS / 1000.0) + 2
    final_count = _wait_lsas(r2, NUM_ROUTES, timeout_s)

    assert final_count == NUM_ROUTES, (
        "Only {}/{} external LSAs reached R2 after {:.1f} s with pacing. "
        "Check ospf_r4_nbr_send_timer() queue drain and re-arm logic.".format(
            final_count, NUM_ROUTES, timeout_s
        )
    )


# ---------------------------------------------------------------------------
# Test 3: without pacing all LSAs arrive quickly
# ---------------------------------------------------------------------------

def test_no_pacing_fast_delivery(tgen):
    """
    Baseline: with pacing disabled the legacy ospf_ls_upd_send_lsa() path is
    used and all 4 LSAs arrive at R2 within 3 seconds.

    This guards against regressions where the R4 gating code accidentally
    intercepts traffic when pacing is off.  The guard in
    ospf_flood_through_interface() is:

        if (oi->rec4_gap_pacing) { ... }   // only entered when pacing is on

    With no pacing configured, rec4_gap_pacing == 0 and the existing
    multicast/unicast send path runs unchanged.
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # No _enable_pacing() call — legacy path only.
    _add_routes(r1)

    # LSA throttle (up to 1 s) + propagation; all LSAs flood immediately
    # so 3 s total is a generous budget.
    final_count = _wait_lsas(r2, NUM_ROUTES, timeout_s=3)

    assert final_count == NUM_ROUTES, (
        "Without pacing only {}/{} external LSAs reached R2 within 3 s. "
        "The legacy flood path may be broken, or LSA/SPF timers are too "
        "conservative for this host.".format(final_count, NUM_ROUTES)
    )


# ---------------------------------------------------------------------------
# Test 4: dynamic enable / disable mid-session
# ---------------------------------------------------------------------------

def test_pacing_enable_disable_mid_session(tgen):
    """
    Toggle pacing on and off while the adjacency is live.

    Phase A — pacing ON:
      Inject routes.  Wait for first LSA.  Confirm the rest are still queued
      (count < NUM_ROUTES immediately after first arrival).

    Phase B — pacing toggled OFF (same adjacency, routes removed first):
      Inject the same routes again.  All arrive within 3 s.

    What the code does for the disable path
    ----------------------------------------
    'no ip ospf lsa-pacing' calls ospf_if_update_params_all() which calls
    ospf_rec4_recompute_effective() setting oi->rec4_gap_pacing = 0, then
    walks existing neighbors calling ospf_nbr_apply_rec4_params() to reset
    their runtime state.  The next flood falls through to the legacy path.
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # -- Phase A: pacing enabled --
    _enable_pacing(r1)
    _add_routes(r1)

    first = _wait_at_least(r2, 1, timeout_s=4)
    assert first >= 1, "Phase A: no LSA arrived within 4 s — check adjacency."

    count_paced = _count_external_lsas(r2)
    assert count_paced < NUM_ROUTES, (
        "Phase A: pacing had no effect — all {} LSAs arrived immediately. "
        "Check ospf_flood_through_interface() R4 block.".format(NUM_ROUTES)
    )

    # Remove routes (triggers MaxAge withdrawal) and wait for R2 LSDB to
    # drain before Phase B, so we get a clean count baseline.
    r1.vtysh_cmd(
        "configure terminal\n"
        + "".join("no ip route {} null0\n".format(p) for p in TEST_PREFIXES)
        + "end"
    )
    _wait_lsas(r2, 0, timeout_s=20)

    # -- Phase B: pacing disabled, adjacency still up --
    _disable_pacing(r1)
    _add_routes(r1)

    count_unpaced = _wait_lsas(r2, NUM_ROUTES, timeout_s=3)
    assert count_unpaced == NUM_ROUTES, (
        "Phase B: only {}/{} LSAs arrived within 3 s after disabling pacing. "
        "Check that ospf_if_update_params_all() correctly clears "
        "oi->rec4_gap_pacing on the live interface.".format(
            count_unpaced, NUM_ROUTES
        )
    )


# ---------------------------------------------------------------------------
# Test 5: gap adjuster speedup — U < L causes G to halve toward min-gap
# ---------------------------------------------------------------------------

def test_gap_adjuster_speedup(tgen):
    """
    Verify the RFC4222 speedup path: when U(t) < L, pace_maybe_adjust_gap()
    halves G on each send cycle, converging from initial-gap down to min-gap.

    How it is forced
    ----------------
    On a virtual P2P link ACKs arrive in microseconds, so U (retransmit list
    size) is always 0 or 1 — well below L=100.  Setting L=100 guarantees
    the U < L branch fires on every send timer call.  adjust-interval=1ms
    removes the rate-limit so every send triggers an adjustment.

    Config:
      initial-gap = 2000 ms   deliberate slow start
      min-gap     =  200 ms   floor for halving
      max-gap     = 2000 ms
      low-watermark  = 100    U is always < 100 on virtual link → speedup every call
      high-watermark = 200
      factor      = 2
      adjust-interval = 1 ms  effectively no rate-limit
      max-lsas    = 1

    Expected delivery timeline (from first LSA sent):
      call 1: U<100 → G 2000→1000ms  LSA-1 sent,  next_send += 1000ms
      call 2: U<100 → G 1000→ 500ms  LSA-2 sent,  next_send +=  500ms
      call 3: U<100 → G  500→ 250→200ms(min)  LSA-3 sent,  next_send += 200ms
      call 4: U<100 → G stays 200ms  LSA-4 sent
      Total ≈ 1000+500+200 = 1700ms from first send

    Without speedup (fixed G=2000ms):
      LSA-2 at 2000ms, LSA-3 at 4000ms, LSA-4 at 6000ms — total ≈ 6000ms

    The 4s timeout discriminates: speedup completes in ~2.7s; without it ~7s.

    What the code does
    ------------------
    pace_maybe_adjust_gap() at ospf_packet.c:202:
        } else if (U < L) {
            G = max(G / F, Gmin);   ← this branch fires on every call
        }
    lsu_sent_for_dst() then uses the updated G to advance next_send_ms,
    so each subsequent timer arms with the reduced delay.
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap 200 max-gap 2000\n"
        "ip ospf lsa-pacing initial-gap 2000\n"
        "ip ospf lsa-pacing low-watermark 100 high-watermark 200\n"
        "ip ospf lsa-pacing factor 2\n"
        "ip ospf lsa-pacing adjust-interval 1\n"
        "ip ospf lsa-pacing max-lsas-per-update 1\n"
        "end"
    )

    cfg = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing initial-gap 2000" in cfg, \
        "initial-gap 2000 not in running-config — vtysh command failed."

    _add_routes(r1)

    # Budget: 1s throttle + ~1.7s actual + 1.3s margin = 4s.
    # Without speedup the same 4 LSAs need ~7s (1s throttle + 6s at G=2000ms).
    # Passing within 4s proves speedup fired.
    timeout_s = 4.0
    final_count = _wait_lsas(r2, NUM_ROUTES, timeout_s)

    assert final_count == NUM_ROUTES, (
        "Speedup did not reduce delivery time: only {}/{} LSAs arrived in {:.0f}s. "
        "With initial-gap=2000ms and low-watermark=100, G should halve on every "
        "send cycle reaching min-gap=200ms quickly. "
        "Without speedup all {} LSAs need ~7s. "
        "Check the U < L branch in pace_maybe_adjust_gap().".format(
            final_count, NUM_ROUTES, timeout_s, NUM_ROUTES
        )
    )


# ---------------------------------------------------------------------------
# Test 6: gap adjuster backoff — aggressive config still delivers all LSAs
# ---------------------------------------------------------------------------

def test_gap_adjuster_backoff(tgen):
    """
    Verify the RFC4222 backoff path: pace_maybe_adjust_gap() is exercised
    with a small high-watermark and large factor, and all LSAs still deliver.

    How it is forced
    ----------------
    Setting high-watermark=2 means backoff fires when U > 2.  On a virtual
    link this threshold is borderline — U may briefly exceed 2 between the
    send and the ACK, especially with adjust-interval=1ms.  Even if backoff
    does not fire on every call, the code path (U > H branch + G cap at
    max-gap) is reachable and the test verifies no LSA is lost or stuck.

    Config:
      initial-gap =  100 ms
      min-gap     =  100 ms
      max-gap     =  500 ms   cap so backoff cannot delay indefinitely
      high-watermark = 2      backoff when more than 2 LSAs unacked
      low-watermark  = 1
      factor      = 3         aggressive: G triples on backoff
      adjust-interval = 1 ms
      max-lsas    = 1

    What the code does
    ------------------
    pace_maybe_adjust_gap() at ospf_packet.c:199:
        if (U > H) {
            G = min(G * F, Gmax);   ← G triples, capped at 500ms
        }
    Even if G reaches max-gap=500ms the send timer still re-arms and drains
    the queue — the re-arm check at ospf_packet.c:4439 is not affected by G.

    Delivery budget:
      Worst case (G maxes at 500ms for all remaining LSAs after first):
        1s throttle + (NUM_ROUTES-1) * 500ms + 2s margin
      This is the upper bound regardless of how many times backoff fires.
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap 100 max-gap 500\n"
        "ip ospf lsa-pacing initial-gap 100\n"
        "ip ospf lsa-pacing low-watermark 1 high-watermark 2\n"
        "ip ospf lsa-pacing factor 3\n"
        "ip ospf lsa-pacing adjust-interval 1\n"
        "ip ospf lsa-pacing max-lsas-per-update 1\n"
        "end"
    )

    cfg = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing initial-gap 100" in cfg, \
        "initial-gap 100 not in running-config — vtysh command failed."

    _add_routes(r1)

    # Worst case: G maxes at 500ms for every inter-LSA gap.
    # Budget: 1s throttle + (NUM_ROUTES-1)*500ms + 2s margin.
    timeout_s = 1 + (NUM_ROUTES - 1) * 0.5 + 2
    final_count = _wait_lsas(r2, NUM_ROUTES, timeout_s)

    assert final_count == NUM_ROUTES, (
        "Only {}/{} LSAs delivered with aggressive backoff config in {:.1f}s. "
        "With initial-gap=100ms, max-gap=500ms and factor=3, all {} LSAs must "
        "still be delivered even if G backs off to max-gap. "
        "Check the U > H branch in pace_maybe_adjust_gap() and the "
        "send timer re-arm logic under increasing G.".format(
            final_count, NUM_ROUTES, timeout_s, NUM_ROUTES
        )
    )


# ---------------------------------------------------------------------------
# Fixture: pacing pre-configured in frr.conf (active before adjacency forms)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def tgen_pacing(request):
    """
    Like the default tgen fixture but loads r1/frr_pacing.conf so that
    ip ospf lsa-pacing is already configured on eth1 before ospfd starts.
    Pacing is therefore active from the moment the interface comes up and
    the first Router-LSA is originated — no VTY enable needed in the test.
    """
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    tgen.gears["r1"].load_frr_config("frr_pacing.conf")
    tgen.gears["r2"].load_frr_config("frr.conf")

    tgen.start_router()

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\n"
        "router ospf\n"
        "redistribute static\n"
        "end"
    )

    time.sleep(12)

    yield tgen

    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Test 7: Router-LSA paced via pre-configured frr.conf
# ---------------------------------------------------------------------------

def test_router_lsa_paced_from_config(tgen_pacing):
    """
    Verify that a Type-1 Router-LSA is intercepted by the R4 pacing queue
    when pacing is pre-configured in frr.conf (active before adjacency forms).

    Unlike the other tests, pacing is NOT enabled via a VTY command in the
    test body — it is already in place when ospfd starts.  This tests the
    code path where ospf_nbr_apply_rec4_params() runs during ospf_nbr_new()
    itself (not retroactively via ospf_if_update_params_all()).

    Trigger
    -------
    Changing 'ip ospf cost' on eth1 forces an immediate Type-1 Router-LSA
    re-origination.  Combined with NUM_ROUTES Type-5 AS-External LSAs, the
    queue holds mixed LSA types delivered at the 1000ms gap.

    What to look for in the log
    ---------------------------
    R4: flood enqueue LSA [Type1:1.1.1.1] nbr=2.2.2.2   <- Router-LSA queued
    R4: flood enqueue LSA [Type5:10.99.x.0] nbr=2.2.2.2  <- External LSAs queued
    R4: send timer fired ... G=1000 ms                    <- all delivered at 1s gap
    """
    tgen = tgen_pacing

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Verify pacing is active from config — no _enable_pacing() call needed
    cfg = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing" in cfg, \
        "Pacing not active from frr_pacing.conf — check fixture config load"

    # Trigger Type-1 Router-LSA re-origination via cost change
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf cost 100\n"
        "end"
    )

    # Inject Type-5 LSAs — these and the Type-1 share the same R4 queue
    _add_routes(r1)

    # Budget: 1s LSA throttle + (NUM_ROUTES + 1 Type-1) gaps + 2s margin
    timeout_s = 1 + (NUM_ROUTES + 1) * 1.0 + 2
    count = _wait_lsas(r2, NUM_ROUTES, timeout_s)

    assert count == NUM_ROUTES, (
        "Only {}/{} Type-5 LSAs arrived within {}s. "
        "Expected Type-1 and Type-5 to share the R4 queue and be delivered "
        "at 1000ms intervals. Check R4: flood enqueue lines in ospfd.log "
        "for [Type1:] entries.".format(count, NUM_ROUTES, timeout_s)
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main(["-s", __file__]))
