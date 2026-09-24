#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_caps_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey <w453y.me@gmail.com>
#

"""
Test that a session is only offloaded to a data plane that declared what the
session needs.

Two sessions are configured, one authenticating and one not. The listener
declares that it authenticates, so both are offloaded. It then withdraws the
declaration, and the authenticating session must come back to bfdd while the
other stays. Last, a key chain is given to the session still offloaded, and
that one must come back too.

The listener stands in for a data plane. It runs no BFD state machine, it
records what it was sent.
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


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")

    # The listener has to be accepting before bfdd starts, since bfdd
    # connects to it as a client.
    router.load_frr_config(
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


def _lid(peer):
    out = get_topogen().gears["r1"].vtysh_cmd("show bfd peer {} json".format(peer))
    return json.loads(out).get("id")


def _capabilities():
    out = get_topogen().gears["r1"].vtysh_cmd("show bfd distributed")
    m = re.search(r"Capabilities: (\S+)", out)
    return m.group(1) if m else None


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def _expect_offloaded(peers, why):
    want = {_lid(p) for p in peers}
    _, result = topotest.run_and_expect(_offloaded, want, count=30, wait=1)
    assert result == want, "{}: data plane holds {}, expected {}".format(
        why, sorted(result), sorted(want)
    )


def test_declared_capabilities_are_shown():
    "bfdd records what the data plane declared."
    _skip_on_failure()

    _, result = topotest.run_and_expect(_capabilities, "0x1", count=30, wait=1)
    assert result == "0x1", "show bfd distributed reports {}".format(result)


def test_both_sessions_offloaded():
    "A data plane that authenticates is given the session that needs it."
    _skip_on_failure()

    _expect_offloaded(
        [AUTH_PEER, PLAIN_PEER], "the authenticating session was not offloaded"
    )


def test_withdrawn_capability_takes_the_session_back():
    """Withdrawing the capability hands the authenticating session back.

    The other session needs nothing and stays where it is.
    """
    _skip_on_failure()

    get_topogen().gears["r1"].run("kill -SIGUSR2 {}".format(_listener_pid()))

    _, result = topotest.run_and_expect(_capabilities, "0", count=30, wait=1)
    assert result == "0", "show bfd distributed reports {}".format(result)

    _expect_offloaded(
        [PLAIN_PEER], "the authenticating session was left with the data plane"
    )


def test_a_key_chain_takes_the_session_back():
    "Configuring a key chain on an offloaded session brings it back."
    _skip_on_failure()

    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
        bfd
        peer {}
        authentication key-chain plain
        end
        """.format(
            PLAIN_PEER
        )
    )

    _expect_offloaded([], "a session that now authenticates was left offloaded")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
