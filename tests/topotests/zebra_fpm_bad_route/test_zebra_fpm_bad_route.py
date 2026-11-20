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
40000-byte gateway and one with a 40000-byte prefsrc (which must be rejected,
not copied over the stack), an IPv6 route with a 4-byte gateway and an IPv4
route with a 16-byte one (the kernel sends neither, both must be rejected),
an IPv4 route with an IPv6 nexthop in RTA_VIA (the way the kernel does send
it, which must be accepted), and a frame with a bad FPM version. The next
connections carry a bad msg_type and an inner length that exceeds the frame.
The last connection is a steady-state good route. The test checks that zebra
logged each rejection, parsed every well-formed route, never crashed,
reconnected exactly for the frames that should reset the session (and not for
the ones that should be skipped), and recovered to a healthy session.
"""

import os
import sys
from time import sleep

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

# Imported through this directory's package rather than off a sys.path entry so
# that a peer script of the same name in another test's directory is not picked
# up by mistake.
from zebra_fpm_bad_route.badfpm import (
    OVERSIZE,
    BAD_MSG_TYPE,
    BAD_VERSION,
    GOOD_PREFIX,
    VIA_PREFIX,
    BAD_V4_PREFIX,
    BAD_V6_PREFIX,
    BAD_PREFSRC_PREFIX,
)

pytestmark = [pytest.mark.fpm]

PEER_SCRIPT = os.path.join(CWD, "badfpm.py")

# The exact substring the parser fix logs when it rejects an address attribute
# of the wrong length (zebra/rt_netlink.c).
REJECT_LOG = "carries an address attribute of invalid length"

# The routes the parser must reject: the oversized gateway, the oversized
# prefsrc, the IPv6 route with a 4-byte gateway and the IPv4 route with a
# 16-byte one. Every other route the peer sends, the IPv4 route with an
# RTA_VIA nexthop included, is well-formed and must not add to this.
EXPECTED_REJECTS = 4

# A route that parses is handed to zebra's main thread as a notification about
# a route zebra installed. zebra installed none of these, so with "debug zebra
# dplane" it logs once per route, with the route's prefix, that it has no
# entry to update (rib_process_dplane_notify() in zebra/zebra_rib.c). A
# rejected route never gets that far.
NOTIFY_LOG = "process dplane notification"

# The peer sends the well-formed IPv6 route three times: before and after the
# short frame on the first connection, and on the steady-state one.
GOOD_ROUTES = 3

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
# the session down end a connection, so zebra must connect exactly this many
# times. The peer keeps accepting past its script, so one more would show.
EXPECTED_CONNECTIONS = 4

# zebra retries a lost FPM session after 3 seconds; wait longer than that
# before concluding that it did not.
FPM_RECONNECT_WAIT = 5

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

    router.load_frr_config(daemons=[("zebra", "-M dplane_fpm_nl")])

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


def _notified(log, prefix):
    "How many routes to prefix zebra's main thread was handed."
    return sum(1 for line in log.splitlines() if NOTIFY_LOG in line and prefix in line)


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
    "An oversized gateway or prefsrc is rejected, not copied over zebra's stack."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # zebra parses the frames on its dplane thread; give the rejections a
    # moment to reach the log. Only the malformed routes are rejected by the
    # parser, one of them for the oversized gateway and one for the oversized
    # prefsrc.
    def _rejected():
        return _zebra_log(router).count(REJECT_LOG)

    _, count = topotest.run_and_expect(_rejected, EXPECTED_REJECTS, count=30, wait=1)
    log = _zebra_log(router)
    assert count == EXPECTED_REJECTS, (
        "expected exactly %d parser-rejected FPM routes (the malformed ones), "
        "found %s occurrences of %r.\nzebra.log tail:\n%s"
        % (EXPECTED_REJECTS, count, REJECT_LOG, log[-2000:])
    )
    for expected in (
        "gateway %d, expected 16" % OVERSIZE,
        "prefsrc %d gateway 0, expected 16" % OVERSIZE,
    ):
        assert expected in log, (
            "no route was rejected for %r, against the expected 16 bytes.\n"
            "zebra.log tail:\n%s" % (expected, log[-2000:])
        )
    assert _notified(log, BAD_PREFSRC_PREFIX) == 0, (
        "the route with the oversized prefsrc was parsed and handed to zebra.\n"
        "zebra.log tail:\n%s" % log[-2000:]
    )

    # The whole point: zebra is still alive after the oversized gateway.
    status = router.check_router_running()
    assert status == "", (
        "zebra is not running after the %d-byte gateway frame "
        "(a stack overflow would crash it here): %s" % (OVERSIZE, status)
    )


def test_cross_family_gateways():
    "A gateway of the other family is rejected in RTA_GATEWAY, accepted in RTA_VIA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # RTA_GATEWAY is always of the route's family: the kernel allows an IPv4
    # route with an IPv6 nexthop but sends it as RTA_VIA, and does not allow
    # an IPv6 route with an IPv4 nexthop at all. So a 4-byte gateway on an
    # IPv6 route and a 16-byte one on an IPv4 route are both malformed, while
    # the IPv4 route with its IPv6 nexthop in RTA_VIA is one the kernel sends.
    rejections = ("gateway 4, expected 16", "gateway 16, expected 4")

    def _all_logged():
        log = _zebra_log(router)
        return all(s in log for s in rejections) and _notified(log, VIA_PREFIX) == 1

    _, ok = topotest.run_and_expect(_all_logged, True, count=90, wait=1)
    log = _zebra_log(router)
    for expected in rejections:
        assert expected in log, "no route was rejected for %r.\nzebra.log tail:\n%s" % (
            expected,
            log[-2000:],
        )

    # The rejected routes stop in the parser...
    for prefix in (BAD_V6_PREFIX, BAD_V4_PREFIX):
        assert _notified(log, prefix) == 0, (
            "the malformed route to %s was parsed and handed to zebra.\n"
            "zebra.log tail:\n%s" % (prefix, log[-2000:])
        )

    # ...and the RTA_VIA one is parsed and handed to zebra, not rejected.
    assert ok and _notified(log, VIA_PREFIX) == 1, (
        "the IPv4 route to %s with an RTA_VIA nexthop was not accepted.\n"
        "zebra.log tail:\n%s" % (VIA_PREFIX, log[-2000:])
    )
    assert (
        log.count(REJECT_LOG) == EXPECTED_REJECTS
    ), "expected %d parser-rejected routes, found %d.\nzebra.log tail:\n%s" % (
        EXPECTED_REJECTS,
        log.count(REJECT_LOG),
        log[-2000:],
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
    # sync: the good route that follows it is still parsed, as is every other
    # copy of it, and the parser rejection count stays at the malformed routes.
    _, good = topotest.run_and_expect(
        lambda: _notified(_zebra_log(router), GOOD_PREFIX),
        GOOD_ROUTES,
        count=30,
        wait=1,
    )
    log = _zebra_log(router)
    assert good == GOOD_ROUTES and log.count(REJECT_LOG) == EXPECTED_REJECTS, (
        "the short frame perturbed the stream; %d of the %d good routes were "
        "parsed.\nzebra.log tail:\n%s" % (good, GOOD_ROUTES, log[-2000:])
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
        "zebra connected %d times, expected %d: a frame that should have been "
        "skipped or rejected by the parser reset the session instead"
        % (count, EXPECTED_CONNECTIONS)
    )

    # And the steady-state session is back up...
    _, result = topotest.run_and_expect(
        lambda: _fpm_connected(router), True, count=30, wait=1
    )
    assert result is True, "zebra did not recover a healthy FPM session"

    # ...and stays up: the well-formed route sent on it does not make zebra
    # drop it and connect again.
    sleep(FPM_RECONNECT_WAIT)
    count = _connection_count()
    assert count == EXPECTED_CONNECTIONS and _fpm_connected(router), (
        "zebra did not stay on the steady-state session: it connected %d "
        "times, expected %d" % (count, EXPECTED_CONNECTIONS)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
