#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_adminshut_periodic_tx.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Sougata Barik <sougatab@nvidia.com>
#

"""
test_bfd_adminshut_periodic_tx.py:

Test BFD Administrative Down transmission (RFC 5880 6.8.16).

After an administrative shutdown, AdminDown must be re-transmitted at the slow
rate for a bounded burst of
    max(BFD_ADMIN_DOWN_TX_MIN, ceil(detect_TO / BFD_DEF_SLOWTX))
packets and then stop. Admin-up must cancel the burst and reset the budget,
and BGP must stay up across shut/no-shut cycles.

Topology:

r1 ----------- r2
  .1    s1   .2
  198.51.100.0/24

Test Cases:
1. test_wait_protocols_convergence: BGP + BFD come up.
2. test_admindown_bgp_stable: r2 reflects the remote AdminDown (BFD down, BGP
   kept up) during and after the burst, BGP is never torn down across the
   shut/no-shut cycle, and the session recovers.
3. test_admindown_cap_detect_below_floor: negotiated detect time 900 ms
   (300 ms x mult-3) < 5 s slow-tx floor. Budget = floor = 5 packets.
4. test_admindown_cap_detect_at_floor: negotiated detect time 5 s
   (1000 ms x mult-5) == 5 s slow-tx floor. Budget = 5 packets (tie).
5. test_admindown_cap_detect_above_floor: negotiated detect time 8 s
   (1000 ms x mult-8) > 5 s slow-tx floor. Budget = 8 packets (RFC-driven).
6. test_admindown_cancel_on_admin_up: rapid shut/no-shut (well under one
   slow-tx interval) cancels the AdminDown transmit timer and resets the
   per-session budget, so a subsequent shut still emits a full fresh burst.
7. test_memory_leak: memory leak detection.

Against the old send-once code the cap tests see a single AdminDown packet
instead of the full burst and fail.
"""

import os
import sys
import time
import pytest
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]

# BFD peer addresses.
R1_PEER = "198.51.100.2"
R2_PEER = "198.51.100.1"

# Must match BFD_ADMIN_DOWN_TX_MIN in bfdd/bfd.h.
ADMINDOWN_MIN = 5

# BFD slow transmit interval (must match BFD_DEF_SLOWTX in bfdd/bfd.h).
SLOW_TX_MS = 1000

# Extra margin past the expected burst duration before sampling.
ADMINDOWN_BURST_MARGIN_S = 3

# Time to wait after the cap window to verify the transmit timer really stopped.
ADMINDOWN_STABLE_WINDOW = 4

# Default per-session BFD timers used by r1/frr.conf and r2/frr.conf.
DEFAULT_RX_MS = 300
DEFAULT_TX_MS = 300
DEFAULT_MULT = 3


def build_topo(tgen):
    """Build the topology: r1 --- s1 --- r2"""
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    """Sets up the pytest environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def _bfd_shutdown(router, peer, iface, shutdown):
    """Administratively shut / no-shut the BFD peer on `router`."""
    router.vtysh_cmd(
        "configure terminal\n"
        "bfd\n"
        " peer {} interface {}\n"
        "  {}shutdown\n"
        " exit\n"
        "exit\n".format(peer, iface, "" if shutdown else "no ")
    )


def _bfd_control_tx_packets(router, peer):
    """
    Return BFD control-packet transmit counter for `peer` (or None).

    Using daemon counters avoids environment-specific tcpdump capture quirks
    while still counting every AdminDown packet sent.
    """
    output = router.vtysh_cmd("show bfd peers counters json", isjson=True)
    for entry in output:
        if entry.get("peer") == peer:
            return entry.get("control-packet-output")
    return None


def _bgp_connections_dropped(router, peer):
    """Return the BGP 'connectionsDropped' counter for `peer` (or None)."""
    output = router.vtysh_cmd(
        "show ip bgp neighbor {} json".format(peer), isjson=True
    )
    if peer in output:
        return output[peer].get("connectionsDropped")
    return None


def _bgp_established(router, peer):
    output = router.vtysh_cmd("show ip bgp summary json", isjson=True)
    expected = {"ipv4Unicast": {"peers": {peer: {"state": "Established"}}}}
    return topotest.json_cmp(output, expected)


def _wait_bfd_up(router, peer, msg_label=None):
    """Block until `router` sees `peer` as up."""

    def _bfd_up():
        output = router.vtysh_cmd("show bfd peers json", isjson=True)
        for entry in output:
            if entry.get("peer") == peer and entry.get("status") == "up":
                return None
        return "BFD peer {} not up on {}".format(peer, router.name)

    _, result = topotest.run_and_expect(partial(_bfd_up), None, count=60, wait=1)
    label = msg_label or "{} -> {}".format(router.name, peer)
    assert result is None, "BFD not up ({})".format(label)


def _configure_bfd_timers(router, peer, iface, rx_ms, tx_ms, mult):
    """Reconfigure receive/transmit interval and detect-multiplier for peer."""
    router.vtysh_cmd(
        "configure terminal\n"
        "bfd\n"
        " peer {} interface {}\n"
        "  receive-interval {}\n"
        "  transmit-interval {}\n"
        "  detect-multiplier {}\n"
        " exit\n"
        "exit\n".format(peer, iface, rx_ms, tx_ms, mult)
    )


def _bfd_detection_timeout_ms(router, peer):
    """Return the currently negotiated detection-timeout (ms) or None."""
    output = router.vtysh_cmd("show bfd peers json", isjson=True)
    for entry in output:
        if entry.get("peer") == peer:
            return entry.get("detection-timeout")
    return None


def _wait_bfd_detect_time(router, peer, expected_ms):
    """Wait until the negotiated detection-timeout on router settles to expected_ms."""

    def _check():
        actual = _bfd_detection_timeout_ms(router, peer)
        if actual == expected_ms:
            return None
        return "{} -> {}: detection-timeout={} expected={}".format(
            router.name, peer, actual, expected_ms
        )

    _, result = topotest.run_and_expect(partial(_check), None, count=30, wait=1)
    assert result is None, (
        "BFD detect time did not converge to {} ms on {} -> {} ({})".format(
            expected_ms, router.name, peer, result
        )
    )


def _expected_admindown_tx(detect_ms):
    """
    Match the bfdd rule:
      max(BFD_ADMIN_DOWN_TX_MIN, ceil(detect_TO / BFD_DEF_SLOWTX))
    detect_ms is the pre-slow-timer detection-timeout in milliseconds.
    """
    if detect_ms is None or detect_ms <= 0:
        return ADMINDOWN_MIN
    detect_pkts = (detect_ms + SLOW_TX_MS - 1) // SLOW_TX_MS
    return max(ADMINDOWN_MIN, detect_pkts)


def test_wait_protocols_convergence():
    """Wait for BGP and BFD to come up on both routers."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Waiting for BGP to converge")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    for router, peer in ((r1, R1_PEER), (r2, R2_PEER)):
        test_func = partial(_bgp_established, router, peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "BGP did not converge on {}".format(router.name)

    step("Waiting for BFD peers to come up")
    for router, peer in ((r1, R1_PEER), (r2, R2_PEER)):
        _wait_bfd_up(router, peer)


def test_admindown_bgp_stable():
    """
    End-to-end AdminDown behaviour with BGP:
      * r2 reflects the remote AdminDown (BFD down, BGP kept up),
      * BGP stays Established during and after the AdminDown burst,
      * neither BGP session is torn down across the shut/no-shut cycle,
      * the session recovers after no-shutdown.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _wait_bfd_up(r1, R1_PEER, msg_label="test start")

    drops_r1_before = _bgp_connections_dropped(r1, R1_PEER)
    drops_r2_before = _bgp_connections_dropped(r2, R2_PEER)

    step("Administratively shut down BFD peer on r1")
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=True)

    step("Verify r2 sees the remote AdminDown and moves BFD to down")

    def _bfd_down_r2():
        output = r2.vtysh_cmd("show bfd peers json", isjson=True)
        for entry in output:
            if entry.get("peer") == R2_PEER and entry.get("status") == "down":
                return None
        return "BFD peer did not go down on r2"

    _, result = topotest.run_and_expect(partial(_bfd_down_r2), None, count=30, wait=1)
    assert result is None, "r2 did not observe the AdminDown from r1"

    burst_wait = (
        _expected_admindown_tx(DEFAULT_MULT * max(DEFAULT_RX_MS, DEFAULT_TX_MS))
        + ADMINDOWN_BURST_MARGIN_S
    )
    step("Wait {}s, past the end of the AdminDown burst".format(burst_wait))
    time.sleep(burst_wait)

    step("Verify BGP stayed Established on both routers (no tear-down)")
    for router, peer in ((r1, R1_PEER), (r2, R2_PEER)):
        assert (
            _bgp_established(router, peer) is None
        ), "BGP left Established on {} during BFD admin-down".format(router.name)

    step("Re-enable BFD peer on r1 and verify recovery")
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=False)
    _wait_bfd_up(r1, R1_PEER, msg_label="recovery after no shutdown")

    step("Verify BGP never reset (connectionsDropped unchanged)")
    drops_r1_after = _bgp_connections_dropped(r1, R1_PEER)
    drops_r2_after = _bgp_connections_dropped(r2, R2_PEER)
    assert drops_r1_after == drops_r1_before, (
        "r1 BGP session dropped during BFD admin-down cycle "
        "({} -> {})".format(drops_r1_before, drops_r1_after)
    )
    assert drops_r2_after == drops_r2_before, (
        "r2 BGP session dropped during BFD admin-down cycle "
        "({} -> {})".format(drops_r2_before, drops_r2_after)
    )


def _run_cap_case(tgen, rx_ms, tx_ms, mult, case_label):
    """
    Reconfigure per-session BFD timers on both routers, verify the resulting
    detect time, admin-shut r1, wait past the expected burst, sample the
    control-packet-output delta on r1 and confirm:
      * exact count matches max(ADMINDOWN_MIN, ceil(detect_ms/SLOW_TX_MS))
      * no further packets in a stable window after the burst
    Un-shut r1 and wait for BFD to recover before returning.
    """
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    expected_detect_ms = mult * max(rx_ms, tx_ms)
    expected_pkts = _expected_admindown_tx(expected_detect_ms)
    burst_wait = expected_pkts + ADMINDOWN_BURST_MARGIN_S

    step(
        "[{}] Reconfigure timers: rx={}ms tx={}ms mult={} -> expected detect "
        "{}ms, expected AdminDown TX {} pkt(s)".format(
            case_label, rx_ms, tx_ms, mult, expected_detect_ms, expected_pkts
        )
    )
    _configure_bfd_timers(r1, R1_PEER, "r1-eth0", rx_ms, tx_ms, mult)
    _configure_bfd_timers(r2, R2_PEER, "r2-eth0", rx_ms, tx_ms, mult)

    _wait_bfd_up(r1, R1_PEER, msg_label=case_label + " r1")
    _wait_bfd_up(r2, R2_PEER, msg_label=case_label + " r2")

    step("[{}] Wait for detect-timeout on r1 to converge".format(case_label))
    _wait_bfd_detect_time(r1, R1_PEER, expected_detect_ms)

    tx_before = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_before is not None, "[{}] Unable to read control TX counters".format(
        case_label
    )

    step("[{}] Administratively shut BFD peer on r1".format(case_label))
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=True)

    step(
        "[{}] Wait {}s (past the ~{}s expected burst)".format(
            case_label, burst_wait, expected_pkts
        )
    )
    time.sleep(burst_wait)
    tx_after_burst = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_after_burst is not None

    step(
        "[{}] Wait extra {}s and confirm transmit timer has stopped".format(
            case_label, ADMINDOWN_STABLE_WINDOW
        )
    )
    time.sleep(ADMINDOWN_STABLE_WINDOW)
    tx_after_stable = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_after_stable is not None

    # Restore before asserting so a failure does not leave the peer shut.
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=False)
    _wait_bfd_up(r1, R1_PEER, msg_label=case_label + " recovery")

    admindown_tx = tx_after_burst - tx_before
    stable_delta = tx_after_stable - tx_after_burst
    logger.info(
        "[%s] detect=%dms expected=%d observed=%d stable_delta=%d",
        case_label,
        expected_detect_ms,
        expected_pkts,
        admindown_tx,
        stable_delta,
    )

    assert admindown_tx == expected_pkts, (
        "[{}] AdminDown burst = {} pkt(s); expected max(BFD_ADMIN_DOWN_TX_MIN={}, "
        "ceil(detect_ms={} / SLOW_TX_MS={})) = {}".format(
            case_label,
            admindown_tx,
            ADMINDOWN_MIN,
            expected_detect_ms,
            SLOW_TX_MS,
            expected_pkts,
        )
    )
    assert stable_delta == 0, (
        "[{}] AdminDown transmit timer did not stop after the burst; {} extra "
        "packet(s) seen over {}s stable window".format(
            case_label, stable_delta, ADMINDOWN_STABLE_WINDOW
        )
    )


def test_admindown_cap_detect_below_floor():
    """
    Detect time (300 ms x mult-3 = 900 ms) < 5 s floor.
    Budget = max(5, 1) = 5 packets (floor wins).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _run_cap_case(tgen, DEFAULT_RX_MS, DEFAULT_TX_MS, DEFAULT_MULT, "detect<floor")


def test_admindown_cap_detect_at_floor():
    """
    Detect time (1000 ms x mult-5 = 5000 ms) == 5 s floor.
    Budget = max(5, 5) = 5 packets (tie).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _run_cap_case(tgen, 1000, 1000, 5, "detect=floor")


def test_admindown_cap_detect_above_floor():
    """
    Detect time (1000 ms x mult-8 = 8000 ms) > 5 s floor.
    Budget = max(5, 8) = 8 packets (RFC-adaptive; satisfies "at least one
    Detection Time" from RFC 5880 Section 6.8.16).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _run_cap_case(tgen, 1000, 1000, 8, "detect>floor")


def test_admindown_cancel_on_admin_up():
    """
    Cancel-on-admin-up: a rapid shut/no-shut (well under one slow-tx interval)
    must cancel the AdminDown transmit timer AND reset the per-session budget,
    so a subsequent shut still emits a full fresh burst sized per the current
    detect time. A leaked counter would show up here as a short second burst.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Restore default aggressive timers so the expected budget is the min
    # floor - simpler baseline for this test than whichever loose timers
    # the previous cap test left behind.
    step("Restore default BFD timers on both routers")
    _configure_bfd_timers(r1, R1_PEER, "r1-eth0", DEFAULT_RX_MS, DEFAULT_TX_MS,
                          DEFAULT_MULT)
    _configure_bfd_timers(r2, R2_PEER, "r2-eth0", DEFAULT_RX_MS, DEFAULT_TX_MS,
                          DEFAULT_MULT)
    _wait_bfd_up(r1, R1_PEER)
    default_detect_ms = DEFAULT_MULT * max(DEFAULT_RX_MS, DEFAULT_TX_MS)
    _wait_bfd_detect_time(r1, R1_PEER, default_detect_ms)

    expected_pkts = _expected_admindown_tx(default_detect_ms)
    burst_wait = expected_pkts + ADMINDOWN_BURST_MARGIN_S

    step("Rapid shut/no-shut before the AdminDown burst can complete")
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=True)
    # Well under BFD_DEF_SLOWTX (1s): only the immediate AdminDown fires,
    # any pending timer slot must be cancelled by no-shutdown.
    time.sleep(0.2)
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=False)

    _wait_bfd_up(r1, R1_PEER, msg_label="post-rapid-cycle")

    step("Shut again and verify a full fresh AdminDown burst is emitted")
    tx_before = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_before is not None
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=True)
    time.sleep(burst_wait)
    tx_after = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_after is not None

    # Restore before asserting so a failing assertion does not leave the peer shut.
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=False)
    _wait_bfd_up(r1, R1_PEER, msg_label="cancel-test recovery")

    admindown_tx = tx_after - tx_before
    logger.info(
        "cancel-test: detect=%dms expected=%d observed=%d",
        default_detect_ms,
        expected_pkts,
        admindown_tx,
    )
    assert admindown_tx == expected_pkts, (
        "Second shutdown emitted {} AdminDown pkt(s); expected a fresh burst "
        "of {}. The transmit budget was not reset by admin-up.".format(
            admindown_tx, expected_pkts
        )
    )


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
