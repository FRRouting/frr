#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_declined_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey <w453y.me@gmail.com>
#

"""
Test that a session a data plane declines works in bfdd.

r1's bfdd is connected to a data plane that first declares that it
authenticates. r1 has two sessions with r2, which runs plain bfdd: an
authenticated single hop one and a multihop one without authentication.
Both are offloaded and bfdd listens on no BFD port.

The data plane then withdraws the declaration. The authenticated session
comes back to bfdd and has to come up with r2, so bfdd has to listen for
it. The other stays with the data plane, and r2's packets for it, which
now reach bfdd too, must leave it alone. When the data plane goes away,
bfdd stops listening again.

The listener stands in for the data plane. It runs no BFD state machine,
it records what it was sent.
"""

import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]

DPLANE_PORT = 50700

AUTH_PEER = "192.168.1.2"
PLAIN_PEER = "192.168.1.3"
PLAIN_KEY = "{} multihop local-address 192.168.1.1".format(PLAIN_PEER)
# r2's packets for the offloaded session reach bfdd for this long.
OFFLOADED_WATCH = 5


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    dump_file = os.path.join(r1.gearlogdir, "bfd_dplane.data")

    # The listener has to be accepting before bfdd starts, since bfdd
    # connects to it as a client.
    r1.load_frr_config(
        daemons=[
            (
                TopoRouter.RD_BFD_DPLANE_LISTENER,
                "-c 0x1 -p {} -z {}".format(DPLANE_PORT, dump_file),
            ),
            (TopoRouter.RD_ZEBRA, None),
            (
                TopoRouter.RD_BFD,
                "--dplaneaddr ipv4c:127.0.0.1:{}".format(DPLANE_PORT),
            ),
        ],
    )
    tgen.gears["r2"].load_frr_config(
        daemons=[(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BFD, None)]
    )

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _listener_pid():
    router = get_topogen().gears["r1"]
    pid_file = os.path.join(router.gearlogdir, "bfd_dplane_listener.pid")
    try:
        with open(pid_file) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def _listener_dump():
    """Ask the listener to write its state out, and return it.

    The listener rewrites the file on each signal, so wait until it is newer
    than before and complete rather than for a fixed time.
    """
    router = get_topogen().gears["r1"]
    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")

    pid = _listener_pid()
    if pid is None:
        return ""

    try:
        before = os.stat(dump_file).st_mtime_ns
    except FileNotFoundError:
        before = 0

    router.run("kill -SIGUSR1 {}".format(pid))

    dump = ""
    for _ in range(50):
        try:
            if os.stat(dump_file).st_mtime_ns != before:
                with open(dump_file) as f:
                    dump = f.read()
                if dump.rstrip().endswith("===="):
                    return dump
        except FileNotFoundError:
            pass
        topotest.sleep(0.1)
    return dump


def _offloaded():
    "The local discriminators of the sessions the listener holds."
    return {int(x) for x in re.findall(r"^  lid: (\d+)$", _listener_dump(), re.M)}


def _peer(router, key):
    return json.loads(router.vtysh_cmd("show bfd peer {} json".format(key)))


def _lid(key):
    return _peer(get_topogen().gears["r1"], key).get("id")


def _status(router, key):
    return _peer(router, key).get("status")


def _bfd_ports():
    "The BFD control ports bfdd on r1 listens on."
    out = get_topogen().gears["r1"].run("ss -ulnp")
    return sorted(
        {
            int(m.group(1))
            for line in out.splitlines()
            if "bfdd" in line
            for m in [re.search(r":(3784|4784)\s", line)]
            if m
        }
    )


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def _expect(func, want, why):
    _, result = topotest.run_and_expect(func, want, count=30, wait=1)
    assert result == want, "{}: got {}, expected {}".format(why, result, want)


def test_both_sessions_offloaded():
    "With authentication declared, both sessions go to the data plane."
    _skip_on_failure()

    _expect(
        _offloaded,
        {_lid(AUTH_PEER), _lid(PLAIN_KEY)},
        "sessions the data plane holds",
    )
    _expect(_bfd_ports, [], "bfdd listening while the data plane runs everything")


def test_declined_session_comes_up():
    "A session the data plane gives back comes up with bfdd's peer."
    _skip_on_failure()

    r1, r2 = get_topogen().gears["r1"], get_topogen().gears["r2"]
    r1.run("kill -SIGUSR2 {}".format(_listener_pid()))

    _expect(_offloaded, {_lid(PLAIN_KEY)}, "sessions the data plane holds")
    _expect(lambda: _status(r1, AUTH_PEER), "up", "r1's session in bfdd")
    _expect(lambda: _status(r2, "192.168.1.1"), "up", "r2's session")
    _expect(_bfd_ports, [3784, 4784], "bfdd listening for its session")


def test_offloaded_session_left_to_data_plane():
    "r2's packets for the offloaded session do not move it in bfdd."
    _skip_on_failure()

    r1 = get_topogen().gears["r1"]
    # The listener reports every session it holds as Up.
    _expect(lambda: _status(r1, PLAIN_KEY), "up", "the offloaded session")
    for _ in range(OFFLOADED_WATCH):
        topotest.sleep(1)
        assert _status(r1, PLAIN_KEY) == "up", "bfdd ran the offloaded session"
    assert _lid(PLAIN_KEY) in _offloaded(), "the data plane lost the session"


def test_no_data_plane_no_listening():
    "When the data plane goes away, bfdd leaves the ports free again."
    _skip_on_failure()

    r1 = get_topogen().gears["r1"]
    r1.run("kill {}".format(_listener_pid()))

    _expect(_bfd_ports, [], "bfdd listening with no data plane")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
