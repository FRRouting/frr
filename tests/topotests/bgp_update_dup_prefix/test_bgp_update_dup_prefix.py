#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""
RFC 4271 conformance: a prefix repeated in WITHDRAWN ROUTES and NLRI.

RFC 4271 section 4.3 allows an UPDATE to carry the same prefix in both the
WITHDRAWN ROUTES and the Network Layer Reachability Information fields, and
says a receiver SHOULD treat such an UPDATE as though WITHDRAWN ROUTES did not
contain the prefix. The reachable NLRI wins; the duplicate withdrawal is
ignored.

bgp_update_receive() walks nlris[] in enum order, so the enum decides which
half of the UPDATE is applied last. Withdrawals sort first, which leaves the
route installed as the RFC asks. Announcing first and withdrawing second would
leave the opposite state and is what this test exists to catch.

The peer is a hand-written speaker rather than ExaBGP, which composes its own
UPDATEs and cannot be made to emit this encoding. The case table lives in
rawpeer.py and is imported by both sides, so the announced case and the
asserted case are one object.
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
from bgp_update_dup_prefix.rawpeer import CASES, LOCAL_IP, SENTINEL

pytestmark = [pytest.mark.bgpd, pytest.mark.freebsd]

PEER_NAME = "peer1"
PEER_SCRIPT = os.path.join(CWD, "rawpeer.py")

# The running speaker, so teardown can reap it.
PEER_PROCESS = None


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)

    peer = tgen.add_host(PEER_NAME, "%s/24" % LOCAL_IP, "via 10.0.0.1")
    switch.add_link(peer)


def setup_module(mod):
    global PEER_PROCESS

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    router.start()

    peer = tgen.gears[PEER_NAME]
    logfile = os.path.join(peer.logdir, PEER_NAME, "rawpeer.log")
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    # The speaker writes its progress to stderr; keeping it next to the
    # router logs is what makes a failed run diagnosable.
    PEER_PROCESS = peer.popen(
        ["python3", PEER_SCRIPT],
        stdout=open(logfile, "w"),
        stderr=subprocess.STDOUT,
    )


def teardown_module(mod):
    tgen = get_topogen()

    if PEER_PROCESS is not None:
        PEER_PROCESS.terminate()
        PEER_PROCESS.wait()

    tgen.stop_topology()

    shutil.rmtree(os.path.join(CWD, "__pycache__"), ignore_errors=True)


def _routes(r1):
    output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
    return output.get("routes", {})


@pytest.fixture(scope="module")
def sequence_done():
    """Block until every UPDATE in the sequence has been parsed.

    The sentinel is announced after the last case, so its arrival -- not a
    fixed sleep -- is what says the sequence is complete. It says nothing
    about the RIB having settled: bgp_rib_withdraw() only flags the path and
    queues the dest, so a withdrawn prefix is still listed for a moment
    afterwards. The per-case checks poll for that.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _established():
        output = json.loads(r1.vtysh_cmd("show bgp neighbors %s json" % LOCAL_IP))
        state = output.get(LOCAL_IP, {}).get("bgpState")
        return None if state == "Established" else state

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, (
        "session with %s never came up (state %s), so no case was announced; "
        "check the peer log in the %s log directory" % (LOCAL_IP, result, PEER_NAME)
    )

    def _sentinel():
        return None if SENTINEL in _routes(r1) else "sentinel %s absent" % SENTINEL

    _, result = topotest.run_and_expect(_sentinel, None, count=60, wait=1)
    assert result is None, (
        "sentinel %s never arrived (%s); the UPDATE sequence did not run to "
        "completion, so the per-case results below would be meaningless"
        % (SENTINEL, result)
    )

    logger.info("RIB once the sequence was parsed: %s", sorted(_routes(r1)))
    return r1


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_update_dup_prefix(sequence_done, case):
    """The UPDATE sequence must leave exactly the state the case declares."""
    r1 = sequence_done

    def _settled():
        rib = _routes(r1)
        missing = [prefix for prefix in case.present if prefix not in rib]
        extra = [prefix for prefix in case.absent if prefix in rib]
        if not missing and not extra:
            return None
        return {"missing": missing, "still present": extra, "rib": sorted(rib)}

    _, result = topotest.run_and_expect(_settled, None, count=30, wait=1)
    assert result is None, (
        "case %s did not reach the state %s requires: %s. A prefix under "
        "'missing' means the duplicate withdrawal won over the reachable "
        "NLRI, which is the ordering bug; a prefix under 'still present' "
        "means an ordinary withdrawal stopped taking effect."
        % (case.name, case.spec, result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
