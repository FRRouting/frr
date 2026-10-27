#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_echo_sockets_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
test_bfd_echo_sockets_topo1.py: bfdd started from its configuration must
open the echo sockets when any session uses echo, not only when the first
session enabled does.

r1 has two sessions from its configuration: one without echo to r2, and
one with echo to r3 over a link that only appears after bfdd has started.
A VRF's sockets are opened when its first session is enabled, and the echo
sockets only if a session enabled by then uses echo; the echo session,
enabled later when its interface appears, did not open them.  Without the
fix r1 never sends an echo, its echo detection expires, and the r3 session
flaps on "echo function failed".
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

# Echo detection is 3 x 100ms; a missing echo socket fails it well inside.
STABILITY_SECS = 10


def build_topo(tgen):
    "r1 linked to r2; the link to r3 is created by the test."
    for routern in range(1, 4):
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
    output = router.vtysh_cmd("show bfd peers counters json", isjson=True)
    entry = _peer_entry(output, peer)
    assert entry is not None, "peer {} not found on {}".format(peer, router.name)
    return entry.get(name, 0)


def test_bfd_first_session_up():
    "The session without echo comes up, having opened r1's sockets."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    test_func = partial(_check_peer, tgen.gears["r1"], "192.168.1.2", {"status": "up"})
    _, result = topotest.run_and_expect(test_func, None, count=32, wait=1)
    assert result is None, "r1 did not reach up with r2"


def test_late_link():
    "Create the r1-r3 link, which enables the echo sessions."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]
    r1.cmd_raises(
        "ip link add r1-late type veth peer name r3-late netns {}".format(r3.net.pid)
    )
    r1.cmd_raises("ip link set r1-late up")
    r3.cmd_raises("ip link set r3-late up")


def test_bfd_sessions_up():
    "Every session must reach up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, peer in (
        ("r1", "192.168.1.2"),
        ("r1", "192.168.2.3"),
        ("r2", "192.168.1.1"),
        ("r3", "192.168.2.1"),
    ):
        test_func = partial(_check_peer, tgen.gears[rname], peer, {"status": "up"})
        _, result = topotest.run_and_expect(test_func, None, count=32, wait=1)
        assert result is None, "{} did not reach up with {}".format(rname, peer)


def test_bfd_echo_returns():
    "r1 must get its echoes back from r3, so it must be sending them."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _echo_input():
        if _counter(r1, "192.168.2.3", "echo-packet-input") == 0:
            return "r1 has received none of its echoes back from r3"
        return None

    _, result = topotest.run_and_expect(_echo_input, None, count=16, wait=1)
    assert result is None, result


def test_bfd_echo_stability():
    "The echo session must not flap on its echo detection."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    before = _counter(r1, "192.168.2.3", "session-down")

    topotest.sleep(STABILITY_SECS, "waiting for echo detection to expire or not")

    flaps = _counter(r1, "192.168.2.3", "session-down") - before
    assert flaps == 0, (
        "r1 recorded {} down events with r3 while idle: its echoes are "
        "not being sent".format(flaps)
    )
    result = _check_peer(r1, "192.168.2.3", {"status": "up", "diagnostic": "ok"})
    assert result is None, "r1 lost the session with r3"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
