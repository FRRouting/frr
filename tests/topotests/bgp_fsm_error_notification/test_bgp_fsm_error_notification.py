#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Minghan Chan <mhchann082@gmail.com>

"""
RFC 6608 conformance: the Data field of a Finite State Machine Error.

RFC 6608 section 4 says that a BGP speaker which receives an unexpected
message in OpenSent or OpenConfirm MUST send a NOTIFICATION with the Finite
State Machine Error code and the subcode for that state, and that "the Data
field is a 1-octet, unsigned integer that indicates the type of the
unexpected message".

bgpd raises this error from four places: the FSM table, for a KEEPALIVE or a
NOTIFICATION in OpenSent, and the UPDATE, ROUTE-REFRESH and CAPABILITY
receive handlers, for any state short of Established. Each case reaches one
of them on a fresh connection and checks the NOTIFICATION as it arrives on
the wire, which is the only place the Data field can be seen.

The peer is a hand-written speaker, since it has to send messages a real BGP
implementation never sends in these states. The case table lives in
rawpeer.py and is imported here, so the case that is run and the case that is
asserted are one object.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

# Imported through this directory's package rather than off a sys.path entry:
# a bare `import rawpeer` would hand whichever module got imported first to
# every directory that ships one, once pytest collects them together.
from bgp_fsm_error_notification.rawpeer import CASES, LOCAL_IP

pytestmark = [pytest.mark.bgpd]

PEER_NAME = "peer1"
PEER_SCRIPT = os.path.join(CWD, "rawpeer.py")


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)

    peer = tgen.add_host(PEER_NAME, "%s/24" % LOCAL_IP, "via 10.0.0.1")
    switch.add_link(peer)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    router.start()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

    shutil.rmtree(os.path.join(CWD, "__pycache__"), ignore_errors=True)


def _peer_log(text):
    # The speaker reports its progress on stderr; it is what makes a failed
    # case diagnosable, so keep it in the test log.
    for line in text.splitlines():
        logger.info(line)


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_fsm_error_data(case):
    """The FSM Error must carry the unexpected message type as its Data."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    peer = tgen.gears[PEER_NAME]
    proc = peer.popen(["python3", PEER_SCRIPT, case.name])
    try:
        out, err = proc.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    _peer_log(err)

    assert proc.returncode == 0, "case %s did not get as far as a NOTIFICATION:\n%s" % (
        case.name,
        err,
    )

    result = json.loads(out)
    assert result == case.expected, (
        "case %s: the router answered %s, but %s requires %s. Matching code "
        "and subcode with empty data means the unexpected message type was "
        "left out of the Data field." % (case.name, result, case.spec, case.expected)
    )


def test_session_establishes_afterwards():
    """After every error above, an ordinary session must still come up.

    Guards the teardown that follows each FSM Error: a router left in a state
    that refuses the peer would fail here, not in the cases above.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    peer = tgen.gears[PEER_NAME]
    proc = peer.popen(["python3", PEER_SCRIPT, "establish"])

    def _established():
        output = json.loads(r1.vtysh_cmd("show bgp neighbors %s json" % LOCAL_IP))
        state = output.get(LOCAL_IP, {}).get("bgpState")
        # A missing neighbor must keep the poll going, so never return None
        # for it.
        return None if state == "Established" else "state %s" % state

    try:
        _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    finally:
        proc.terminate()
        _, err = proc.communicate()
        _peer_log(err)

    assert result is None, (
        "session with %s did not reach Established (%s) after the FSM error "
        "cases" % (LOCAL_IP, result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
