#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by NVIDIA Corporation
# Riccardo Ravaioli
#
"""A route notification read back from the FPM peer must not overflow zebra,
and malformed FPM frame headers must be rejected cleanly.

zebra -M dplane_fpm_nl reads route notifications from its FPM peer through the
same parser that handles kernel netlink (netlink_route_read_unicast_ctx). The
parser used to copy RTA_GATEWAY / RTA_PREFSRC into a 20-byte struct ipaddr
using the attribute's own length, with no check against the 4 or 16 bytes the
family allows. The FPM session has no authentication, so a hostile peer, or
anyone on its path, could smash zebra's stack with one frame. fpm_read() also
accepted a frame whose version or msg_type was wrong (the header check was &&
rather than ||) and dereferenced a netlink header the frame was too short to
hold.

A hostile peer (badfpm.py) drives both paths across a sequence of
connections. The first connection carries a well-formed IPv6 route, a frame
too short for a netlink header (which must be skipped, not dereferenced), the
good route again (proving the skip left the stream in sync), a route with a
40000-byte gateway (which must be rejected, not copied over the stack), and a
frame with a bad FPM version. The next connections carry a bad msg_type and an
inner length that exceeds the frame. The last connection is a steady-state
good route. The test checks that zebra logged each rejection, never crashed,
reconnected exactly for the frames that should reset the session (and not for
the ones that should be skipped), and recovered to a healthy session.
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Imported through this directory's package rather than off a sys.path entry so
# that a peer script of the same name in another test's directory is not picked
# up by mistake.
from zebra_fpm_bad_route.badfpm import OVERSIZE, BAD_MSG_TYPE, BAD_VERSION

pytestmark = [pytest.mark.fpm]

PEER_SCRIPT = os.path.join(CWD, "badfpm.py")

# The exact substring the parser fix logs when it rejects an address attribute
# of the wrong length (zebra/rt_netlink.c).
REJECT_LOG = "carries an address attribute of invalid length"

# The substrings fpm_read() logs for each malformed frame header
# (zebra/dplane_fpm_nl.c).
SHORT_FRAME_LOG = "cannot hold a netlink header"
INNER_LEN_LOG = "greater than the fpm total length"
BAD_HDR_LOG = "version/msg_type %d/%d, expected 1/1"

# The good halves of the two bad-header frames the peer sends: one carries a
# bad version with a valid msg_type, the other a bad msg_type with a valid
# version.
FPM_VERSION_GOOD = 1
FPM_MSG_TYPE_GOOD = 1

# badfpm.py scripts one batch per connection; only the frames that should tear
# the session down end a connection, so zebra must reconnect exactly this many
# times.
EXPECTED_CONNECTIONS = 4

peer_proc = None
progress_file = None
done_file = None


def build_topo(tgen):
    "A single router; the FPM peer runs in its namespace on the loopback."
    tgen.add_router("r1")


def setup_module(module):
    global peer_proc, progress_file, done_file

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]

    # The peer has to be listening before zebra tries to connect, otherwise
    # zebra backs off for 3 seconds before retrying.
    progress_file = os.path.join(router.gearlogdir, "badfpm.progress")
    done_file = os.path.join(router.gearlogdir, "badfpm.done")
    peer_proc = router.popen(["python3", PEER_SCRIPT, progress_file, done_file])

    router.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, "r1/zebra.conf"),
        "-M dplane_fpm_nl",
    )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()

    if peer_proc is not None:
        peer_proc.terminate()
        try:
            _, err = peer_proc.communicate(timeout=30)
        except Exception:  # pylint: disable=broad-except
            err = b""
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        # The peer narrates what it put on the wire; that is what makes a
        # failure here readable, so keep it in the test log.
        for line in err.splitlines():
            logger.info("badfpm: %s", line)

    tgen.stop_topology()


def _require_peer_alive():
    if peer_proc.poll() is not None:
        pytest.fail("the FPM peer exited early with %s" % peer_proc.returncode)


def _fpm_connected(router):
    output = router.vtysh_cmd("show fpm status json", isjson=True)
    return output.get("connected") is True


def _zebra_log(router):
    try:
        with open(os.path.join(router.gearlogdir, "zebra.log")) as handle:
            return handle.read()
    except OSError:
        return ""


def _connection_count():
    "How many times the peer has accepted a connection from zebra."
    try:
        with open(progress_file) as handle:
            return sum(1 for line in handle if line.startswith("ACCEPT "))
    except OSError:
        return 0


def test_peer_connected():
    "zebra connects to the FPM peer."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    _, result = topotest.run_and_expect(
        lambda: _fpm_connected(router), True, count=60, wait=1
    )
    assert result is True, "zebra never connected to the FPM peer"


def test_frames_sent():
    "The peer gets through its whole script."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _done():
        _require_peer_alive()
        return os.path.exists(done_file)

    _, result = topotest.run_and_expect(_done, True, count=90, wait=1)
    assert result is True, "the FPM peer did not finish its script"


def test_zebra_survived_bad_route():
    "The malformed gateway is rejected, not copied over zebra's stack."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # zebra parses the frames on its dplane thread; give the rejection a
    # moment to reach the log. Exactly one frame (the malformed one) is
    # rejected by the parser, and it must be rejected for the oversized gateway.
    def _rejected():
        return _zebra_log(router).count(REJECT_LOG)

    _, count = topotest.run_and_expect(_rejected, 1, count=30, wait=1)
    log = _zebra_log(router)
    assert count == 1, (
        "expected exactly one parser-rejected FPM route (the malformed one), "
        "found %s occurrences of %r.\nzebra.log tail:\n%s"
        % (count, REJECT_LOG, log[-2000:])
    )
    assert "gateway 40000" in log and "expected 16" in log, (
        "the rejection did not name the 40000-byte gateway against the "
        "expected 16 bytes.\nzebra.log tail:\n%s" % log[-2000:]
    )

    # The whole point: zebra is still alive after the oversized gateway.
    status = router.check_router_running()
    assert status == "", (
        "zebra is not running after the %d-byte gateway frame "
        "(a stack overflow would crash it here): %s" % (OVERSIZE, status)
    )


def test_malformed_frame_headers_rejected():
    "fpm_read() rejects each malformed frame header and keeps the stream sane."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # By the time the peer is DONE every malformed frame has been written; wait
    # for the matching log lines to land.
    def _all_logged():
        log = _zebra_log(router)
        return all(
            s in log
            for s in (
                SHORT_FRAME_LOG,
                INNER_LEN_LOG,
                BAD_HDR_LOG % (BAD_VERSION, FPM_MSG_TYPE_GOOD),
                BAD_HDR_LOG % (FPM_VERSION_GOOD, BAD_MSG_TYPE),
            )
        )

    _, ok = topotest.run_and_expect(_all_logged, True, count=30, wait=1)
    log = _zebra_log(router)
    assert ok, (
        "zebra did not log every malformed frame header rejection.\n"
        "zebra.log tail:\n%s" % log[-3000:]
    )

    # The short frame is skipped, not dereferenced, and leaves the stream in
    # sync: the good route that follows it is still accepted, so the parser
    # rejection count stays at the single oversized gateway.
    assert log.count(REJECT_LOG) == 1, (
        "the short frame perturbed the stream; the following good route was "
        "not parsed cleanly.\nzebra.log tail:\n%s" % log[-2000:]
    )


def test_fpm_session_reconnected_and_recovered():
    "zebra reconnects only for the resetting frames and ends up healthy."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # Only the three header-rejecting frames end a connection; the skipped and
    # parser-rejected frames must not. So the peer accepts exactly one
    # connection per batch and no more.
    count = _connection_count()
    assert count == EXPECTED_CONNECTIONS, (
        "zebra reconnected %d times, expected %d: a frame that should have been "
        "skipped (short frame or oversized gateway) reset the session instead"
        % (count, EXPECTED_CONNECTIONS)
    )

    # And the steady-state session is back up.
    _, result = topotest.run_and_expect(
        lambda: _fpm_connected(router), True, count=30, wait=1
    )
    assert result is True, "zebra did not recover a healthy FPM session"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
