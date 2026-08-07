#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""
RFC 7606 conformance: malformed attributes that must reset the session.

RFC 7606 section 7.11 is the one place the RFC still mandates the heavy
hammer. A malformed MP_REACH_NLRI next-hop length makes the NLRI impossible to
locate, so treat-as-withdraw is not available and the session must be reset.

Only the eBGP peer is used. Section 7.11 draws no distinction between peer
sorts, and since every case ends its own session, running three peers would
mean three interleaved flaps for no extra coverage.

Each case runs in its own ExaBGP lifetime: the test writes the case index into
peer1/, starts ExaBGP, waits for the session to come up, waits for it to go
down again, and checks the NOTIFICATION r1 sent. The case table lives in
cases.py and the case model in ../lib/bgp_rfc7606.py, both copied into peer1/
at setup time so the announced case and the asserted case are one object.
"""

import functools
import json
import os
import shutil
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
# ../lib holds the shared case model, imported by its bare name because
# exa-send.py imports it the same way from inside /etc/exabgp.
sys.path.append(os.path.join(CWD, "../lib"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

from bgp_rfc7606 import EBGP, PEER_ADDR, PEER_NAME

# cases.py is imported through this directory's package rather than by its
# bare name. Every RFC 7606 directory ships a cases.py, and a bare
# `from cases import ...` off a sys.path entry would hand whichever module got
# imported first to all of them when pytest collects the directories together.
from bgp_rfc7606_session_reset.cases import CASES, EXPECTED_NOTIFICATION

pytestmark = [pytest.mark.bgpd]

PEER_DIR = os.path.join(CWD, PEER_NAME[EBGP])
PEER_IP = PEER_ADDR[EBGP]

# Case names where FRR knowingly departs from RFC 7606 section 7.11. Strict,
# so fixing bgpd turns the xpass into a failure here and the entry must go.
KNOWN_DEVIATIONS = {}

SHARED_FILES = (
    os.path.join(CWD, "cases.py"),
    os.path.join(CWD, "../lib/bgp_rfc7606.py"),
)

# Written into peer1/ before each ExaBGP start; TopoExaBGP.start() copies the
# whole peer directory into /etc/exabgp, so this is how exa-send.py learns
# which case it is on.
CASE_INDEX_FILE = os.path.join(PEER_DIR, "case_index")

# True once an ExaBGP has been started at least once in this run, so the
# pre-case cleanup can be skipped while there is nothing to clean up.
PEER_STARTED = False


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)

    peer = tgen.add_exabgp_peer(
        PEER_NAME[EBGP], ip=PEER_IP, defaultRoute="via 10.0.0.1"
    )
    switch.add_link(peer)


def setup_module(mod):
    for src in SHARED_FILES:
        shutil.copy(src, os.path.join(PEER_DIR, os.path.basename(src)))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    router.start()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

    for src in list(SHARED_FILES) + [CASE_INDEX_FILE]:
        copy = os.path.join(PEER_DIR, os.path.basename(src))
        if os.path.exists(copy):
            os.remove(copy)
    shutil.rmtree(os.path.join(PEER_DIR, "__pycache__"), ignore_errors=True)


def _neighbor(r1):
    return json.loads(r1.vtysh_cmd("show bgp neighbors {} json".format(PEER_IP))).get(
        PEER_IP, {}
    )


def _state(r1):
    return _neighbor(r1).get("bgpState")


def _notifications_sent(r1):
    return _neighbor(r1).get("messageStats", {}).get("notificationsSent", 0)


def _stop_peer(tgen):
    """Kill ExaBGP and wait for r1 to notice."""
    peer = tgen.gears[PEER_NAME[EBGP]]
    # TopoExaBGP.stop() kills the pid in the peer's own pidfile. That is the
    # only safe way to do this.
    #
    # Do NOT add a `pkill -f exabgp` fallback here. Topotest gears share the
    # host PID namespace -- only the network namespace is separate -- so
    # peer.run() sees every process on the machine, and `pkill -f` matches the
    # full command line. FRR CI runs pytest out of a virtualenv named
    # /root/pytest_exabgp4, so such a pattern matches the *test runner* and
    # kills it: pytest dies mid-test with no verdict, no summary and no
    # topotests.xml, while passing locally where the venv is named differently.
    # An earlier revision of this file did exactly that.
    peer.stop()

    r1 = tgen.gears["r1"]
    test_func = functools.partial(
        lambda: None if _state(r1) != "Established" else "still Established"
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "session with {} stayed up after killing ExaBGP".format(
        PEER_IP
    )


@pytest.fixture(scope="module")
def tgen_up():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def _params():
    params = []
    for index, case in enumerate(CASES):
        reason = KNOWN_DEVIATIONS.get(case.name)
        marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
        params.append(pytest.param(index, case, id=case.name, marks=marks))
    return params


@pytest.mark.parametrize("index,case", _params())
def test_session_reset(tgen_up, index, case):
    """The malformed attribute must cost the peer its session."""
    global PEER_STARTED

    tgen = tgen_up
    r1 = tgen.gears["r1"]
    peer = tgen.gears[PEER_NAME[EBGP]]

    # Start from a clean slate: no leftover ExaBGP from a previous case, and
    # no half-open session on r1. Skipped until an ExaBGP has actually run,
    # where TopoExaBGP.stop() would only complain about a missing pidfile.
    if PEER_STARTED:
        _stop_peer(tgen)
    r1.vtysh_cmd("clear bgp {}".format(PEER_IP))

    # notificationsSent is sampled here rather than compared against zero, so
    # a case that fails to reset cannot pass on the previous case's
    # NOTIFICATION still being the last one r1 recorded.
    before = _notifications_sent(r1)

    with open(CASE_INDEX_FILE, "w") as fd:
        fd.write("%d\n" % index)

    peer.start(PEER_DIR, os.path.join(CWD, "exabgp.env"))
    PEER_STARTED = True

    test_func = functools.partial(
        lambda: None if _state(r1) == "Established" else _state(r1)
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "case {}: session with {} never came up (state {}), so the case was "
        "never announced".format(case.name, PEER_IP, result)
    )

    # The reset itself: r1 must send a NOTIFICATION it did not send before.
    def _reset():
        sent = _notifications_sent(r1)
        return None if sent > before else "notificationsSent still %d" % sent

    _, result = topotest.run_and_expect(_reset, None, count=60, wait=1)
    assert result is None, (
        "case {}: r1 sent no NOTIFICATION for prefix {} within 60s ({}). {} "
        "requires the session to be reset; check r1/bgpd.log -- if it says "
        "the attribute was treated as a withdrawal, that is a genuine "
        "deviation and belongs in KNOWN_DEVIATIONS, not in a weakened "
        "expectation.".format(case.name, case.prefix(EBGP), result, case.spec)
    )

    neigh = _neighbor(r1)
    expected_code, expected_subcode = EXPECTED_NOTIFICATION[case.name]
    expected = "%02X%02X" % (expected_code, expected_subcode)

    got = neigh.get("lastErrorCodeSubcode")
    assert got is not None, (
        "case {}: r1 recorded a NOTIFICATION but `show bgp neighbors {} json` "
        "has no lastErrorCodeSubcode; lastResetDueTo={!r}, "
        "lastNotificationReason={!r}".format(
            case.name,
            PEER_IP,
            neigh.get("lastResetDueTo"),
            neigh.get("lastNotificationReason"),
        )
    )
    assert got.upper() == expected, (
        "case {}: r1 sent NOTIFICATION {} ({}), expected {} (code {}, subcode "
        "{}) per {}".format(
            case.name,
            got,
            neigh.get("lastNotificationReason"),
            expected,
            expected_code,
            expected_subcode,
            case.spec,
        )
    )

    _stop_peer(tgen)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
