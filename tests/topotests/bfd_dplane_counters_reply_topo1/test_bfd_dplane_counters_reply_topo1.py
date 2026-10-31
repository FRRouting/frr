#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_counters_reply_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test that each session shows the counters the data plane sent for it.

`show bfd peers counters` asks the data plane for every session's
counters and waits for each reply. A data plane can have something else
to say first. The listener here sends ECHO_REQUESTs ahead of every
reply: first one, with a pause before the reply, then five in the same
write as the reply. Every reply carries its own number as control
packets in and the session's discriminator as control packets out. A
session showing a number that does not grow, or another session's
discriminator, was given a stale reply or none.
"""

import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]

DPLANE_PORT = 50700
SESSION_COUNT = 4
ROUNDS = 3


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]

    # The listener is started by the tests, which change its options
    # between phases; bfdd retries its data plane connection until then.
    router.load_frr_config(
        daemons=[
            (TopoRouter.RD_ZEBRA, None),
            (
                TopoRouter.RD_BFD,
                "--dplaneaddr ipv4c:127.0.0.1:{}".format(DPLANE_PORT),
            ),
        ],
    )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    _stop_listener(tgen.gears["r1"])
    tgen.stop_topology()


def _stop_listener(router):
    pid_file = os.path.join(router.gearlogdir, "bfd_dplane_listener.pid")
    if os.path.exists(pid_file):
        with open(pid_file) as f:
            router.run("kill {}".format(f.read().strip()))
        os.unlink(pid_file)
        time.sleep(1)


def _start_listener(router, opts):
    _stop_listener(router)
    # The daemon keeps no inherited output open, or run() waits on it.
    router.run(
        "{} -d {} -p {} -z {} </dev/null >/dev/null 2>&1".format(
            os.path.join(router.net.daemondir, "bfd_dplane_listener"),
            opts,
            DPLANE_PORT,
            os.path.join(router.gearlogdir, "bfd_dplane.data"),
        )
    )


def _listener_dump(router):
    "Ask the listener to write its state out, and return it."
    pid_file = os.path.join(router.gearlogdir, "bfd_dplane_listener.pid")
    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")

    try:
        with open(pid_file) as f:
            pid = f.read().strip()
    except FileNotFoundError:
        return ""

    router.run("kill -SIGUSR1 {}".format(pid))
    time.sleep(0.2)

    try:
        with open(dump_file) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _registered(router):
    """Wait for bfdd to connect to the listener just started and offload
    every session to it. Until then bfdd shows its own counters, and the
    sessions can still look up from before.
    """

    def _check():
        dump = _listener_dump(router)
        return (
            "Connection state: connected" in dump
            and "Sessions registered: {}\n".format(SESSION_COUNT) in dump
        )

    _, result = topotest.run_and_expect(_check, True, count=30, wait=1)
    assert result, "bfdd did not offload the sessions to the listener:\n{}".format(
        _listener_dump(router)
    )


def _sessions_up(router):
    def _up_count():
        peers = router.vtysh_cmd("show bfd peers json", isjson=True)
        if not peers:
            return -1
        return sum(1 for peer in peers if peer.get("status") == "up")

    _, result = topotest.run_and_expect(_up_count, SESSION_COUNT, count=30, wait=1)
    assert result == SESSION_COUNT, "{} of {} sessions came up".format(
        result, SESSION_COUNT
    )


def _counters_fresh(router, what):
    last = {}

    for rnd in range(ROUNDS):
        counters = router.vtysh_cmd("show bfd peers counters json", isjson=True)
        assert len(counters) == SESSION_COUNT, counters

        for c in counters:
            peer, lid = c["peer"], c["id"]
            assert c["control-packet-output"] == lid, (
                "{}, round {}: {} shows the counters sent for discriminator {}, "
                "not its own {}".format(
                    what, rnd, peer, c["control-packet-output"], lid
                )
            )
            assert c["control-packet-input"] > last.get(peer, 0), (
                "{}, round {}: {} still shows reply {}, from before this "
                "round's request".format(what, rnd, peer, c["control-packet-input"])
            )
            last[peer] = c["control-packet-input"]


def test_sessions_reach_up():
    "The listener reports every session up once bfdd offloads it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    _start_listener(router, "-n 1 -g 5")
    _registered(router)
    _sessions_up(router)


def test_counters_after_a_message_and_a_pause():
    "One ECHO_REQUEST, then the reply: bfdd reads the request on its own."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _counters_fresh(tgen.gears["r1"], "one message ahead")


def test_counters_after_messages_in_the_same_read():
    "Five ECHO_REQUESTs and the reply in one write: the loop moves the buffer."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    _start_listener(router, "-n 5")
    # bfdd reconnects on its own and offloads the sessions again.
    _registered(router)
    _sessions_up(router)

    _counters_fresh(router, "five messages in the same read")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
