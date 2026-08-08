#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_counters_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test that reading BFD session counters repeatedly does not tear down the
data plane connection.

`show bfd peers counters` asks the data plane for fresh counters for
every session and reads each reply synchronously. Consumed replies used
to leave their bytes behind in the input buffer, so after enough of them
the buffer looked full, a zero length read was issued, and its zero
return was misread as the data plane closing the connection.

The listener stands in for a data plane. It runs no BFD state machine
and sends no BFD packets, it simply reports each session up once the
daemon registers it, which is enough for the daemon to treat the session
as established.
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd]

DPLANE_PORT = 50700
SESSION_COUNT = 8

# The input buffer holds a little over one hundred replies, so the
# failure needs more than that many to show up. Eight sessions over
# twenty sweeps is a comfortable margin either side of it.
SWEEPS = 20


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")

    # bfdd connects to the listener as a client, so the listener has to
    # be accepting before bfdd starts.
    router.load_config(
        TopoRouter.RD_BFD_DPLANE_LISTENER,
        None,
        "-p {} -z {}".format(DPLANE_PORT, dump_file),
    )
    router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    router.load_config(
        TopoRouter.RD_BFD,
        os.path.join(CWD, "r1/bfdd.conf"),
        "--dplaneaddr ipv4c:127.0.0.1:{}".format(DPLANE_PORT),
    )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


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


def _dump_value(dump, prefix):
    "Pull the integer off a `prefix: value` line, or -1 if absent."
    for line in dump.splitlines():
        if line.startswith(prefix):
            try:
                return int(line.split(":")[1])
            except ValueError:
                return -1
    return -1


def test_dplane_sessions_registered():
    "The data plane should receive every configured session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _registered():
        return _dump_value(_listener_dump(router), "Sessions registered:")

    _, result = topotest.run_and_expect(_registered, SESSION_COUNT, count=30, wait=1)
    assert result == SESSION_COUNT, "data plane received {} of {} sessions".format(
        result, SESSION_COUNT
    )


def test_sessions_reach_up():
    "The data plane reports the sessions up, so the daemon should agree."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _up_count():
        try:
            peers = json.loads(router.vtysh_cmd("show bfd peers json"))
        except ValueError:
            return -1
        return sum(1 for peer in peers if peer.get("status") == "up")

    _, result = topotest.run_and_expect(_up_count, SESSION_COUNT, count=30, wait=1)
    assert result == SESSION_COUNT, "{} of {} sessions came up".format(
        result, SESSION_COUNT
    )


def test_counters_keep_dplane_connected():
    "Reading counters repeatedly must not disconnect the data plane."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    for _ in range(SWEEPS):
        router.vtysh_cmd("show bfd peers counters")

    dump = _listener_dump(router)
    logger.info("listener state after %d sweeps:\n%s", SWEEPS, dump)

    expected = SESSION_COUNT * SWEEPS
    replies = _dump_value(dump, "Counter replies sent:")
    assert replies == expected, (
        "{} of {} counter requests were answered, so the data plane "
        "stopped being asked partway through:\n{}".format(replies, expected, dump)
    )

    assert (
        "Connection state: connected" in dump
    ), "the data plane connection was lost while reading counters:\n{}".format(dump)

    # A reconnect means the connection dropped and bfdd came back, which
    # the state line alone would not catch.
    accepted = _dump_value(dump, "Connections accepted:")
    assert (
        accepted == 1
    ), "bfdd reconnected {} times, so the connection was dropped:\n{}".format(
        accepted - 1, dump
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
