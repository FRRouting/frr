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

Regression test for BFD Administrative Down transmission.
Checks that AdminDown is sent periodically after shutdown (RFC 5880 6.8.16),
and that BGP remains stable during shut/no-shut.

Topology:

    r1 ----------- r2
      .1    s1   .2
        10.0.1.0/24

Test Cases:
1. test_wait_protocols_convergence: BGP + BFD come up.
2. test_periodic_admindown_regression_guard: after admin-shutdown, r1 must emit
   MORE THAN ONE AdminDown Control packet over an observation window. Against
   the old send-once code exactly one (or zero, if it predates the window)
   AdminDown packet is seen and this test FAILS, reproducing the bug.
3. test_fix_periodic_admindown_and_bgp_stable: end-to-end verification that the
   periodic AdminDown keeps flowing, the peer reflects remote AdminDown, BGP is
   never torn down across the shut/no-shut cycle, and the session recovers.
4. test_memory_leak: memory leak detection.
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
R1_PEER = "10.0.1.2"
R2_PEER = "10.0.1.1"

# Observation window for AdminDown retransmissions.
CAPTURE_SECONDS = 4


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
    while still validating periodic transmission during AdminDown.
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


def test_wait_protocols_convergence():
    """Wait for BGP and BFD to come up on both routers."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Waiting for BGP to converge")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge(router, peer):
        output = router.vtysh_cmd("show ip bgp summary json", isjson=True)
        expected = {"ipv4Unicast": {"peers": {peer: {"state": "Established"}}}}
        return topotest.json_cmp(output, expected)

    for router, peer in ((r1, R1_PEER), (r2, R2_PEER)):
        test_func = partial(_bgp_converge, router, peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "BGP did not converge on {}".format(router.name)

    step("Waiting for BFD peers to come up")

    def _bfd_up(router, peer):
        output = router.vtysh_cmd("show bfd peers json", isjson=True)
        for entry in output:
            if entry.get("peer") == peer and entry.get("status") == "up":
                return None
        return "BFD peer {} not up".format(peer)

    for router, peer in ((r1, R1_PEER), (r2, R2_PEER)):
        test_func = partial(_bfd_up, router, peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "BFD did not come up on {}".format(router.name)


def test_periodic_admindown_regression_guard():
    """
    Reproduce the send-once bug: after admin-shutdown, r1 must transmit MORE
    THAN ONE AdminDown Control packet. The old code deleted the transmit timer
    and sent a single AdminDown, so this assertion fails against it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Administratively shut down BFD peer on r1")
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=True)

    step("Confirm r1 BFD session is administratively down")

    def _bfd_admin_down_r1():
        output = r1.vtysh_cmd("show bfd peers json", isjson=True)
        for entry in output:
            if entry.get("peer") == R1_PEER and entry.get("status") == "shutdown":
                return None
        return "BFD peer on r1 not in shutdown state"

    _, result = topotest.run_and_expect(
        partial(_bfd_admin_down_r1), None, count=10, wait=1
    )
    assert result is None, "BFD did not enter admin-down state on r1"

    tx_before = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_before is not None, "Unable to read BFD control TX counters on r1"

    step(
        "Wait {}s in AdminDown and verify control-packet TX counter increases".format(
            CAPTURE_SECONDS
        )
    )
    time.sleep(CAPTURE_SECONDS)

    tx_after = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_after is not None, "Unable to read BFD control TX counters on r1"
    admindown_tx = tx_after - tx_before
    logger.info(
        "r1 transmitted %d AdminDown control packet(s) in the window", admindown_tx
    )

    # Restore before asserting so a failure does not leave the peer shut.
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=False)

    assert admindown_tx >= 2, (
        "BFD sent {} AdminDown packet(s); expected periodic re-transmission "
        "(>=2). The send-once behaviour lets a single lost AdminDown time the "
        "peer out and reset BGP (RFC 5880 6.8.16 SHOULD violation).".format(
            admindown_tx
        )
    )


def test_fix_periodic_admindown_and_bgp_stable():
    """
    End-to-end verification of the fix:
      * r1 keeps re-transmitting AdminDown while shut,
      * r2 reflects the remote AdminDown (BFD down, BGP kept up),
      * neither BGP session is torn down across the shut/no-shut cycle,
      * the session recovers after no-shutdown.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Make sure we start from a healthy, established baseline.
    def _bfd_up_r1():
        output = r1.vtysh_cmd("show bfd peers json", isjson=True)
        for entry in output:
            if entry.get("peer") == R1_PEER and entry.get("status") == "up":
                return None
        return "BFD peer not up on r1"

    _, result = topotest.run_and_expect(partial(_bfd_up_r1), None, count=60, wait=1)
    assert result is None, "BFD not up on r1 at test start"

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

    tx_before = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_before is not None, "Unable to read BFD control TX counters on r1"

    step("Verify AdminDown is re-transmitted periodically while shut")
    time.sleep(CAPTURE_SECONDS)
    tx_after = _bfd_control_tx_packets(r1, R1_PEER)
    assert tx_after is not None, "Unable to read BFD control TX counters on r1"
    admindown_tx = tx_after - tx_before
    logger.info(
        "r1 sustained %d AdminDown control packet(s) while shut", admindown_tx
    )
    assert admindown_tx >= 3, (
        "Expected sustained periodic AdminDown while shut, saw only "
        "{} in {}s".format(admindown_tx, CAPTURE_SECONDS)
    )

    step("Verify BGP stayed Established on both routers (no tear-down)")
    for router, peer in ((r1, R1_PEER), (r2, R2_PEER)):
        output = router.vtysh_cmd("show ip bgp summary json", isjson=True)
        expected = {"ipv4Unicast": {"peers": {peer: {"state": "Established"}}}}
        assert (
            topotest.json_cmp(output, expected) is None
        ), "BGP left Established on {} during BFD admin-down".format(router.name)

    step("Re-enable BFD peer on r1 and verify recovery")
    _bfd_shutdown(r1, R1_PEER, "r1-eth0", shutdown=False)

    _, result = topotest.run_and_expect(partial(_bfd_up_r1), None, count=60, wait=1)
    assert result is None, "BFD did not recover on r1 after no shutdown"

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

    logger.info("SUCCESS: periodic AdminDown maintained and BGP never reset")


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
