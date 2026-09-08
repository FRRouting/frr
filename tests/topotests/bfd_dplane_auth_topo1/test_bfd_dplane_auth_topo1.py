#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_auth_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey <w453y.me@gmail.com>
#

"""
Test that a session's authentication keys reach the data plane with the
lifetimes that say when each may be used.

The data plane picks the key, not the daemon: it has the packets, so it is
the only side that can tell which key applies to one. That only works if
the periods travel with the keys, so what is checked here is that they do,
and that the overlap a rollover depends on survives the trip.

The listener stands in for a data plane. It runs no BFD state machine, it
records what it was sent.
"""

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

# Three keys are configured: two carrying lifetimes and one without.
KEY_COUNT = 3


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

    # The listener has to be accepting before bfdd starts, since bfdd
    # connects to it as a client.
    router.load_frr_config(
        daemons=[
            (
                TopoRouter.RD_BFD_DPLANE_LISTENER,
                "-p {} -z {}".format(DPLANE_PORT, dump_file),
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


def _listener_dump():
    "Ask the listener to write its state out, and return it."
    router = get_topogen().gears["r1"]
    pid_file = os.path.join(router.gearlogdir, "bfd_dplane_listener.pid")
    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")

    try:
        with open(pid_file) as f:
            pid = f.read().strip()
    except FileNotFoundError:
        return ""

    router.run("kill -SIGUSR1 {}".format(pid))
    topotest.sleep(0.2)

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


def _keys(dump):
    """Every key the listener last recorded, as dictionaries.

    The lifetimes are seconds since the epoch, and the daemon reads them
    from a local time, so nothing here compares them against a fixed
    value. What matters is how they sit relative to one another.
    """
    out = []
    pattern = re.compile(
        r"auth key: id (\d+) type (\d+) len (\d+) "
        r"send (-?\d+) (-?\d+) accept (-?\d+) (-?\d+)"
    )
    for line in dump.splitlines():
        m = pattern.search(line)
        if m:
            n = [int(x) for x in m.groups()]
            out.append(
                {
                    "id": n[0],
                    "type": n[1],
                    "len": n[2],
                    "send_start": n[3],
                    "send_end": n[4],
                    "accept_start": n[5],
                    "accept_end": n[6],
                }
            )
    return out


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def test_session_says_it_authenticates():
    """The session must announce that it authenticates.

    A data plane that cannot handle keys has to be able to tell, or it
    runs the session in the clear while the peer authenticates.
    """
    _skip_on_failure()

    def _flagged():
        return _dump_value(_listener_dump(), "Auth sessions")

    _, result = topotest.run_and_expect(lambda: _flagged() >= 1, True, count=30, wait=1)
    assert result is True, "the data plane was not told the session authenticates"


def test_every_key_reaches_the_dplane():
    "All three keys are sent, not just the one in use."
    _skip_on_failure()

    def _count():
        return _dump_value(_listener_dump(), "Auth last key count")

    _, result = topotest.run_and_expect(_count, KEY_COUNT, count=30, wait=1)
    assert result == KEY_COUNT, "data plane received {} of {} keys".format(
        result, KEY_COUNT
    )


def test_keys_carry_their_lifetimes():
    "The periods must arrive as configured, including the rollover overlap."
    _skip_on_failure()

    keys = _keys(_listener_dump())
    assert len(keys) == KEY_COUNT, "expected {} keys, got {}".format(
        KEY_COUNT, len(keys)
    )

    by_id = {k["id"]: k for k in keys}
    assert sorted(by_id) == [1, 2, 3], "unexpected key ids {}".format(sorted(by_id))

    first, second, third = by_id[1], by_id[2], by_id[3]

    # A key stops being used to transmit before it stops being accepted,
    # so a packet already in flight still verifies.
    assert first["accept_end"] > first["send_end"], (
        "key 1 stops being accepted before it stops being sent, so packets "
        "in flight at the rollover would be refused"
    )

    # The next key becomes acceptable before it starts being sent, which
    # is the other half of the same overlap.
    assert second["accept_start"] < second["send_start"], (
        "key 2 is not accepted until it is already being sent"
    )

    # The keys hand over rather than overlapping on transmit.
    assert first["send_end"] < second["send_start"], (
        "keys 1 and 2 would both be used to transmit at the same time"
    )

    # A key configured without lifetimes carries the sentinel that means
    # always valid, which a data plane has to recognise.
    assert third["send_start"] == 0 and third["accept_start"] == 0, (
        "key 3 has no configured lifetimes and should say so"
    )


def test_a_new_key_is_pushed():
    "Adding a key to the chain sends the set again."
    _skip_on_failure()

    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
        key chain rollover
        key 4
        key-string fourthkey0000004
        cryptographic-algorithm hmac-sha-1
        end
        """
    )

    def _count():
        return _dump_value(_listener_dump(), "Auth last key count")

    _, result = topotest.run_and_expect(_count, KEY_COUNT + 1, count=30, wait=1)
    assert result == KEY_COUNT + 1, (
        "the data plane was not sent the key that was added, it has {}".format(result)
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
