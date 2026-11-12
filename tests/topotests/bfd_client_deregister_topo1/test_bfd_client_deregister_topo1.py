#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_client_deregister_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey <w453y.me@gmail.com>
#

"""
Test that a client leaving a session the configuration still holds leaves
the session as it is.

r1 offloads its sessions to a data plane listener. Its peer 192.168.1.2 is
configured and a static route is bound to it; 192.168.1.3 exists only for a
second static route. r2 and r3 run plain bfdd, r2 with a static route bound
to its configured peer.

When staticd stops using the configured sessions, they must stay up: in r1
while the data plane still runs the session, and in r2 without going down.
The session only staticd held must go away, from the data plane too.

The listener stands in for a data plane. It runs no BFD state machine, it
reports every session up and records what it was sent.
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

pytestmark = [pytest.mark.bfdd, pytest.mark.staticd]

DPLANE_PORT = 50710

CONFIGURED_PEER = "192.168.1.2"
CLIENT_PEER = "192.168.1.3"
PLAIN_PEER = "192.168.2.3"


def setup_module(mod):
    topodef = {"s1": ("r1",), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    dump_file = os.path.join(r1.gearlogdir, "bfd_dplane.data")

    # The listener has to be accepting before bfdd starts, since bfdd
    # connects to it as a client.
    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        daemons=[
            (
                TopoRouter.RD_BFD_DPLANE_LISTENER,
                "-p {} -z {}".format(DPLANE_PORT, dump_file),
            ),
            (TopoRouter.RD_ZEBRA, None),
            (TopoRouter.RD_STATIC, None),
            (
                TopoRouter.RD_BFD,
                "--dplaneaddr ipv4c:127.0.0.1:{}".format(DPLANE_PORT),
            ),
        ],
    )

    for rname in ("r2", "r3"):
        tgen.gears[rname].load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            daemons=[
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_BFD, None),
            ],
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
    than before and complete rather than for a fixed time. Returns None when
    no complete dump arrives, so a failed read never looks like an empty
    data plane.
    """
    router = get_topogen().gears["r1"]
    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")

    pid = _listener_pid()
    if pid is None:
        return None

    try:
        before = os.stat(dump_file).st_mtime_ns
    except FileNotFoundError:
        before = 0

    router.run("kill -SIGUSR1 {}".format(pid))

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
    return None


def _offloaded():
    """The local discriminators of the sessions the listener holds.

    None when the listener could not be read.
    """
    dump = _listener_dump()
    if dump is None:
        return None
    return {int(x) for x in re.findall(r"^  lid: (\d+)$", dump, re.M)}


def _holds(lid):
    "Whether the listener holds lid, or None when it could not be read."
    held = _offloaded()
    return None if held is None else lid in held


def _peer(rname, peer):
    "The peer's JSON, or {} once bfdd no longer has it."
    out = get_topogen().gears[rname].vtysh_cmd("show bfd peer {} json".format(peer))
    try:
        return json.loads(out)
    except ValueError:
        return {}


def _status(rname, peer):
    return _peer(rname, peer).get("status")


def _counters(rname, peer):
    router = get_topogen().gears[rname]
    out = router.vtysh_cmd("show bfd peer {} counters json".format(peer))
    return json.loads(out) if out.strip() else {}


def _unbind(rname, prefix, nexthop):
    "Keep the static route, without BFD."
    get_topogen().gears[rname].vtysh_cmd(
        """
        configure terminal
        no ip route {0} {1} bfd
        ip route {0} {1}
        end
        """.format(
            prefix, nexthop
        )
    )


def _stays(func, want, seconds):
    "Check func() returns want for the whole time, not only at the end."
    for _ in range(seconds * 2):
        got = func()
        if got != want:
            return got
        topotest.sleep(0.5)
    return want


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def test_sessions_up():
    "Every session comes up, r1's in the data plane."
    _skip_on_failure()

    for rname, peer in (
        ("r1", CONFIGURED_PEER),
        ("r1", CLIENT_PEER),
        ("r2", PLAIN_PEER),
    ):
        _, result = topotest.run_and_expect(
            lambda: _status(rname, peer), "up", count=30, wait=1
        )
        assert result == "up", "{} peer {} is {}".format(rname, peer, result)

    want = {_peer("r1", p)["id"] for p in (CONFIGURED_PEER, CLIENT_PEER)}
    _, result = topotest.run_and_expect(_offloaded, want, count=30, wait=1)
    assert result == want, "data plane holds {}, expected {}".format(
        sorted(result), sorted(want)
    )


def test_offloaded_session_stays_up():
    """A configured session in a data plane stays up when staticd leaves it.

    The data plane is never told anything, so bfdd must not change the
    state it reported.
    """
    _skip_on_failure()

    lid = _peer("r1", CONFIGURED_PEER)["id"]
    _unbind("r1", "10.99.1.0/24", CONFIGURED_PEER)

    result = _stays(lambda: _status("r1", CONFIGURED_PEER), "up", 5)
    assert result == "up", "r1 shows the offloaded session {}".format(result)
    assert _holds(lid) is True, "the data plane no longer holds the session"


def test_client_only_session_is_removed():
    "A session only staticd held goes away, from the data plane too."
    _skip_on_failure()

    lid = _peer("r1", CLIENT_PEER)["id"]
    _unbind("r1", "10.99.2.0/24", CLIENT_PEER)

    _, result = topotest.run_and_expect(
        lambda: _peer("r1", CLIENT_PEER) == {}, True, count=30, wait=1
    )
    assert result, "r1 kept the session: {}".format(_peer("r1", CLIENT_PEER))

    _, result = topotest.run_and_expect(lambda: _holds(lid), False, count=30, wait=1)
    assert (
        result is False
    ), "the data plane still holds the removed session ({})".format(result)


def test_plain_session_does_not_flap():
    "A configured session bfdd runs does not go down when staticd leaves it."
    _skip_on_failure()

    before = _counters("r2", PLAIN_PEER).get("session-up")
    _unbind("r2", "10.99.3.0/24", PLAIN_PEER)

    result = _stays(lambda: _status("r2", PLAIN_PEER), "up", 5)
    assert result == "up", "r2 shows the session {}".format(result)

    after = _counters("r2", PLAIN_PEER).get("session-up")
    assert after == before, "the session went down and up again ({} -> {})".format(
        before, after
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
