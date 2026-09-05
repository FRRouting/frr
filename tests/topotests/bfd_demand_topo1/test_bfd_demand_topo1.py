#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_demand_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
test_bfd_demand_topo1.py: BFD demand mode (RFC 5880 section 6.6).

r1 and r2 run a single hop session.  Demand mode is enabled on r1 only,
so r1 sets the Demand bit and r2 is expected to cease periodic control
packet transmission while keeping the session up.

The session must survive that silence: a system in demand mode does not
run its detection timer, because there is nothing left to time out.
Liveness is verified by Poll Sequence instead, so a path failure is
detected only once a poll is initiated.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bfdd]

R1_ADDR = "192.168.1.1"
R2_ADDR = "192.168.1.2"

# Long enough that a transmitting peer would emit many packets at the
# configured 100ms interval, so a zero delta is unambiguous.
QUIET_SECS = 10

# With no poll outstanding the detection timer is not running, so r1 must
# stay up across this window even though r2 is unreachable.
UNDETECTED_SECS = 5


def build_topo(tgen):
    "Two routers on a single link."
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _peer_entry(entries, peer):
    for entry in entries:
        if entry.get("peer") == peer:
            return entry
    return None


def _check_peer(router, peer, expected):
    output = router.vtysh_cmd("show bfd peers json", isjson=True)
    entry = _peer_entry(output, peer)
    if entry is None:
        return "peer {} not found on {}".format(peer, router.name)
    return topotest.json_cmp(entry, expected)


def _counter(router, peer, name):
    counters = router.vtysh_cmd("show bfd peers counters json", isjson=True)
    entry = _peer_entry(counters, peer)
    assert entry is not None, "peer {} not found on {}".format(peer, router.name)
    return entry.get(name, 0)


def _shutdown(router, peer, enable):
    router.vtysh_cmd(
        "configure terminal\nbfd\npeer {}\n{}shutdown\nend".format(
            peer, "" if enable else "no "
        )
    )


def _wait_quiet(router, peer):
    """
    Block until the router stops sending control packets.

    Poll and Final exchanges keep flowing for a while after a configuration
    change, and how long depends on the negotiated interval, so waiting for
    the counter to stop advancing is more reliable than sleeping a fixed
    time and hoping the exchange has drained.
    """
    state = {"last": None}

    def _moving():
        now = _counter(router, peer, "control-packet-output")
        if state["last"] is not None and now == state["last"]:
            return None
        state["last"] = now
        return "{} is still transmitting".format(router.name)

    _, result = topotest.run_and_expect(_moving, None, count=30, wait=2)
    return result


def _set_demand(router, peer, enable):
    router.vtysh_cmd(
        "configure terminal\nbfd\npeer {}\n{}demand-mode\nend".format(
            peer, "" if enable else "no "
        )
    )


def test_bfd_demand_session_up():
    "Both ends must reach up before demand mode is enabled."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router, peer in ((tgen.gears["r1"], R2_ADDR), (tgen.gears["r2"], R1_ADDR)):
        test_func = partial(_check_peer, router, peer, {"status": "up"})
        _, result = topotest.run_and_expect(test_func, None, count=32, wait=1)
        assert result is None, "{} did not reach up with {}".format(router.name, peer)


def test_bfd_demand_reported():
    "Enabling demand mode must be visible on both ends, differently."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _set_demand(tgen.gears["r1"], R2_ADDR, True)

    # r1 knows it is demanding; r2 knows its peer is.  The two keys report
    # different facts and must not be conflated.
    test_func = partial(
        _check_peer,
        tgen.gears["r1"],
        R2_ADDR,
        {"status": "up", "demand-mode": True, "remote-demand-mode": False},
    )
    _, result = topotest.run_and_expect(test_func, None, count=16, wait=1)
    assert result is None, "r1 does not report itself in demand mode"

    test_func = partial(
        _check_peer,
        tgen.gears["r2"],
        R1_ADDR,
        {"status": "up", "demand-mode": False, "remote-demand-mode": True},
    )
    _, result = topotest.run_and_expect(test_func, None, count=16, wait=1)
    assert result is None, "r2 did not observe r1's Demand bit"


def test_bfd_demand_transmission_ceases():
    "r2 must stop transmitting, r1 must not, and the session must survive."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    assert _wait_quiet(r2, R1_ADDR) is None, "r2 never ceased transmitting"

    # Sampled before the wait: the session was reconfigured during this run,
    # so only deltas are meaningful.
    r1_tx = _counter(r1, R2_ADDR, "control-packet-output")
    r2_tx = _counter(r2, R1_ADDR, "control-packet-output")
    r1_down = _counter(r1, R2_ADDR, "session-down")
    r2_down = _counter(r2, R1_ADDR, "session-down")

    topotest.sleep(QUIET_SECS, "waiting to see whether r2 keeps transmitting")

    for router, peer, before in ((r1, R2_ADDR, r1_down), (r2, R1_ADDR, r2_down)):
        flaps = _counter(router, peer, "session-down") - before
        assert flaps == 0, (
            "{} recorded {} down events with {}: the detection timer is "
            "still running in demand mode".format(router.name, flaps, peer)
        )

    r2_sent = _counter(r2, R1_ADDR, "control-packet-output") - r2_tx
    assert r2_sent == 0, (
        "r2 sent {} control packets while r1 was in demand mode: "
        "the Demand bit is not being honoured".format(r2_sent)
    )

    r1_sent = _counter(r1, R2_ADDR, "control-packet-output") - r1_tx
    assert r1_sent > 0, (
        "r1 stopped transmitting: a system in demand mode ceases only when "
        "its peer asks it to, and r2 is not demanding"
    )


def test_bfd_demand_poll_detects_failure():
    "A failed path is detected once a Poll Sequence is initiated."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    # Break the path silently.  Stopping the router would let r2 signal the
    # session down, which is a different diagnostic than the one under test.
    r2.run("ip link set r2-eth0 down")

    topotest.sleep(UNDETECTED_SECS, "checking that the failure goes unnoticed")

    result = _check_peer(r1, R2_ADDR, {"status": "up"})
    assert result is None, (
        "r1 detected the failure without a Poll Sequence: the detection timer "
        "should not be running while demand mode is active"
    )

    # Changing a negotiated interval forces a Poll Sequence, which is the only
    # in band verification available in demand mode.
    r1.vtysh_cmd(
        "configure terminal\nbfd\npeer {}\ntransmit-interval 300\nend".format(R2_ADDR)
    )

    test_func = partial(
        _check_peer,
        r1,
        R2_ADDR,
        {"status": "down", "diagnostic": "control detection time expired"},
    )
    _, result = topotest.run_and_expect(test_func, None, count=16, wait=1)
    assert result is None, "r1 did not detect the failure after a Poll Sequence"


def test_bfd_demand_disable_restores_detection():
    "Leaving demand mode must restore detection even if the peer is already gone."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    # Bring the session back with the link and demand mode restored, so this
    # test starts from a working demanding session rather than the previous
    # test's leftovers.
    r2.run("ip link set r2-eth0 up")
    _set_demand(r1, R2_ADDR, False)

    test_func = partial(_check_peer, r1, R2_ADDR, {"status": "up"})
    _, result = topotest.run_and_expect(test_func, None, count=32, wait=1)
    assert result is None, "session did not recover before the test"

    _set_demand(r1, R2_ADDR, True)
    test_func = partial(_check_peer, r1, R2_ADDR, {"demand-mode": True})
    _, result = topotest.run_and_expect(test_func, None, count=16, wait=1)
    assert result is None, "r1 did not re-enter demand mode"

    # Confirm r2 has actually ceased before breaking the path: if it is
    # still transmitting, r1's detection timer was never deleted and this
    # test would pass without exercising the restore at all.
    assert _wait_quiet(r2, R1_ADDR) is None, "r2 never ceased transmitting"

    r2_tx = _counter(r2, R1_ADDR, "control-packet-output")
    r1_rx = _counter(r1, R2_ADDR, "control-packet-input")
    topotest.sleep(5, "checking that r2 stays ceased")
    assert _counter(r2, R1_ADDR, "control-packet-output") - r2_tx == 0, (
        "r2 is still transmitting, so r1's detection timer was never deleted "
        "and this test would not exercise the restore"
    )
    assert (
        _counter(r1, R2_ADDR, "control-packet-input") - r1_rx == 0
    ), "r1 is still receiving, so nothing here depends on the timer restore"

    # Break the path while the detection timer is disabled, so nothing will
    # arrive to re-arm it once demand mode is turned off again.
    r2.run("ip link set r2-eth0 down")
    topotest.sleep(3, "letting the failure go unnoticed")

    _set_demand(r1, R2_ADDR, False)

    test_func = partial(
        _check_peer,
        r1,
        R2_ADDR,
        {"status": "down", "diagnostic": "control detection time expired"},
    )
    _, result = topotest.run_and_expect(test_func, None, count=16, wait=1)
    assert result is None, (
        "r1 stayed up after leaving demand mode: the detection timer was not "
        "restored, so a dead path goes unnoticed indefinitely"
    )


def test_bfd_demand_both_ends_disable():
    "Leaving demand mode must reach a peer that is also demanding."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    r2.run("ip link set r2-eth0 up")
    _set_demand(r1, R2_ADDR, False)
    _set_demand(r2, R1_ADDR, False)

    test_func = partial(_check_peer, r1, R2_ADDR, {"status": "up"})
    _, result = topotest.run_and_expect(test_func, None, count=32, wait=1)
    assert result is None, "session did not recover before the test"

    # Both ends demanding. Configure it while the session is down: the
    # Demand bit is only set once both systems are Up, so bringing the
    # session up with both ends already configured lets each learn the
    # other's bit before either has ceased transmitting.
    _shutdown(r1, R2_ADDR, True)
    _shutdown(r2, R1_ADDR, True)
    topotest.sleep(2, "letting both ends go down")
    _set_demand(r1, R2_ADDR, True)
    _set_demand(r2, R1_ADDR, True)
    _shutdown(r1, R2_ADDR, False)
    _shutdown(r2, R1_ADDR, False)

    for router, peer in ((r1, R2_ADDR), (r2, R1_ADDR)):
        test_func = partial(
            _check_peer,
            router,
            peer,
            {"status": "up", "demand-mode": True, "remote-demand-mode": True},
        )
        _, result = topotest.run_and_expect(test_func, None, count=32, wait=1)
        assert result is None, "{} is not mutually demanding".format(router.name)

    down_before = _counter(r1, R2_ADDR, "session-down")

    _set_demand(r1, R2_ADDR, False)

    topotest.sleep(10, "checking that the healthy session survives")

    result = _check_peer(r1, R2_ADDR, {"status": "up", "diagnostic": "ok"})
    assert result is None, (
        "r1 went down after leaving demand mode on a healthy path: its "
        "transmission is still suppressed by the peer's Demand bit"
    )
    flaps = _counter(r1, R2_ADDR, "session-down") - down_before
    assert flaps == 0, "r1 recorded {} down events on a healthy path".format(flaps)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
