#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_echo_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test the echo interval bfdd hands a data plane (RFC 5880 Section 6.8.9).

Only bfdd sees the peer's Required Min Echo RX, so it negotiates the echo
interval for an offloaded session and sends the result down. A peer that
advertises zero accepts no echo packets, so the data plane must be told
to send none; a peer that advertises more than the local interval gets
its own value.

Each router's listener stands in for a data plane and reports the peer's
Required Min Echo RX: zero on r1, 100 ms on r2. Both sessions ask for
echo at the default 50 ms.
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
PEER_ECHO_RX = {"r1": 0, "r2": 100000}


def build_topo(tgen):
    "Build function"
    for name in PEER_ECHO_RX:
        tgen.add_router(name)
        switch = tgen.add_switch("s-" + name)
        switch.add_link(tgen.gears[name])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name, echo_rx in PEER_ECHO_RX.items():
        router = tgen.gears[name]
        dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")

        # bfdd connects to the listener as a client, so the listener has
        # to be accepting before bfdd starts.
        router.load_frr_config(
            daemons=[
                (
                    TopoRouter.RD_BFD_DPLANE_LISTENER,
                    "-p {} -z {} -e {}".format(DPLANE_PORT, dump_file, echo_rx),
                ),
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


def test_sessions_reach_up():
    "The data plane reports each session up, so bfdd should agree."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for name in PEER_ECHO_RX:
        router = tgen.gears[name]

        def _up():
            peers = router.vtysh_cmd("show bfd peers json", isjson=True)
            return bool(peers) and all(p.get("status") == "up" for p in peers)

        _, result = topotest.run_and_expect(_up, True, count=30, wait=1)
        assert result, "{}: session did not come up".format(name)


def _echo_requested(name, want):
    tgen = get_topogen()
    router = tgen.gears[name]

    def _interval():
        return _dump_value(_listener_dump(router), "Echo interval requested:")

    _, result = topotest.run_and_expect(_interval, want, count=10, wait=1)
    dump = _listener_dump(router)
    assert (
        "Echo requested: yes" in dump
    ), "{}: session not offloaded with echo:\n{}".format(name, dump)
    return result, dump


def test_peer_refusing_echo_gets_none():
    "Required Min Echo RX zero: the data plane must send no echo."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result, dump = _echo_requested("r1", 0)
    assert result == 0, (
        "the peer accepts no echo, but the data plane was asked for echo "
        "every {} us:\n{}".format(result, dump)
    )


def test_peer_interval_wins_when_larger():
    "Required Min Echo RX 100 ms against a local 50 ms: send every 100 ms."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result, dump = _echo_requested("r2", 100000)
    assert (
        result == 100000
    ), "the peer asked for 100000 us, the data plane was asked for {}:\n{}".format(
        result, dump
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
