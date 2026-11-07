#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# test_ospf6_maxage_double_remove.py
# Part of the FRRouting test suite.
#
# Copyright (c) 6WIND 2026
#

"""
test_ospf6_maxage_double_remove.py: OSPFv3 MaxAge-update duplicate remove-hook
regression test.

When an LSDB holds a non-MaxAge LSA and a same-key MaxAge update replaces
it, ospf6_lsdb_add() ran the remove hook twice in a row: once for the old
copy (the necessary withdrawal) and once for the new MaxAge copy.  The
MaxAge copy never went through the add hook, so the second remove found
nothing and only redid the consumer's scan work (route lookups, and for
Intra-Prefix a full re-walk of the LSA body).

The test triggers the path with a plain configuration action: r2
redistributes one loopback prefix, then stops redistributing it, which
makes r2 flush its AS-External-LSA with a MaxAge update (RFC 2328 14.1).
On r1 the withdrawal must run the remove hook exactly once.  The gdb-based
call counts are the primary observable; the test skips when gdb or the
relevant symbols are unavailable.  The debug log line counts are the
secondary observable and run everywhere.
"""

import json
import os
import re
import shlex
import sys
import time

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib import topotest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospf6d]

R2_RID = "2.2.2.2"
FEED_PREFIX = "2001:db8:feed::/64"
FEED_ADDRESS = "2001:db8:feed::1/64"
# A second redistributed prefix that is never flushed: it keeps r2 an ASBR
# for the whole test, so no router-LSA E-bit change and no border-router
# table event can add remove-hook calls to the measurement.
KEEP_PREFIX = "2001:db8:feed:1::/64"

GDB_SCRIPT = """set pagination off
set confirm off
handle SIGINT stop print nopass
set $old = 0
set $cons = 0
break ospf6d/ospf6_lsdb.c:127
commands
  silent
  set $old = $old + 1
  continue
end
break ospf6_asbr_lsa_remove
commands
  silent
  set $cons = $cons + 1
  continue
end
continue
printf "O6A2_COUNTS old=%d cons=%d\\n", $old, $cons
detach
quit
"""


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_link(r1, r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _vty_json(router, command):
    return json.loads(router.vtysh_cmd(command))


def _nbr_full(router, rid):
    try:
        data = _vty_json(router, "show ipv6 ospf6 neighbor json")
    except (json.JSONDecodeError, ValueError):
        return False

    def search(value):
        if isinstance(value, dict):
            if value.get("neighborId") == rid:
                return value.get("state") == "Full"
            for child in value.values():
                if search(child):
                    return True
        elif isinstance(value, list):
            for child in value:
                if search(child):
                    return True
        return False

    return search(data)


def _external_route_present(router, prefix=FEED_PREFIX):
    try:
        data = _vty_json(router, "show ipv6 ospf6 route json")
    except (json.JSONDecodeError, ValueError):
        return False
    return prefix in json.dumps(data)


def _feed_lsa_id(router):
    """LS ID of the AS-External-LSA carrying FEED_PREFIX, as seen by
    `router`."""
    try:
        data = _vty_json(router, "show ipv6 ospf6 database as-external json")
    except (json.JSONDecodeError, ValueError):
        return None

    def search(value):
        if isinstance(value, dict):
            if (
                value.get("advRouter") == R2_RID
                and value.get("payload") == FEED_PREFIX
                and int(value.get("age", 0)) < 3600
            ):
                return value.get("lsId")
            for child in value.values():
                found = search(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = search(child)
                if found is not None:
                    return found
        return None

    return search(data)


def _wait_until(predicate, timeout_s=30, interval=0.5):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _gdb_breakpoints_resolve(router):
    for spec in ("break ospf6d/ospf6_lsdb.c:127", "break ospf6_asbr_lsa_remove"):
        out = router.cmd(
            "gdb -q -batch -ex '%s' -ex 'info breakpoints' "
            "/usr/lib/frr/ospf6d 2>&1 || true" % spec
        )
        if "Breakpoint 1 at" not in out:
            return False
    return True


def _ospf6d_pid(router):
    # pidof is ambiguous: all routers share the pid namespace and run
    # identical ospf6d cmdlines.  The pid file lives in the router's own
    # mount namespace and names exactly this router's ospf6d.
    return router.cmd("cat /var/run/frr/ospf6d.pid").strip().splitlines()[-1]


def _gdb_count_start(router, logdir):
    script = os.path.join(logdir, "o6a2_count.gdb")
    log = os.path.join(logdir, "o6a2_count.log")
    with open(script, "w") as fp:
        fp.write(GDB_SCRIPT)
    router.cmd("rm -f %s" % shlex.quote(log))
    pid = router.cmd(
        "nohup gdb -q -batch -x %s -p %s > %s 2>&1 </dev/null & echo $!"
        % (shlex.quote(script), _ospf6d_pid(router), shlex.quote(log))
    ).strip()
    pid = pid.splitlines()[-1]
    assert pid.isdigit(), "gdb did not start on %s (pid %r)" % (router.name, pid)
    assert _wait_until(
        lambda: os.path.exists(log)
        and "Breakpoint 2 at" in open(log, errors="replace").read()
    ), "gdb breakpoints not ready on %s" % router.name
    return pid, log


def _gdb_count_stop(router, pid, log):
    router.cmd("kill -INT %s >/dev/null 2>&1 || true" % pid)

    def _counts():
        if not os.path.exists(log):
            return None
        match = re.search(
            r"O6A2_COUNTS old=(\d+) cons=(\d+)",
            open(log, errors="replace").read(),
        )
        return (int(match.group(1)), int(match.group(2))) if match else None

    assert _wait_until(lambda: _counts() is not None, timeout_s=15), (
        "gdb did not report counts on %s" % router.name
    )
    # Safety net: never leave the daemon stopped.
    router.cmd("kill -CONT %s 2>/dev/null || true" % _ospf6d_pid(router))
    return _counts()


def _log_marker_counts(router, feed_lsa_id):
    """Cumulative counts of the two observable debug lines for the feed
    LSA in r1's log."""
    logfile = "{}/{}".format(router.gearlogdir, "ospf6d.log")
    withdraw = re.compile(
        r"Withdraw AS-External route for \[AS-External Id:"
        + re.escape(feed_lsa_id)
    )
    notfound = re.compile(
        r"AS-External route " + re.escape(FEED_PREFIX) + r" not found"
    )
    try:
        with open(logfile, errors="replace") as fp:
            text = fp.read()
    except FileNotFoundError:
        return 0, 0
    return len(withdraw.findall(text)), len(notfound.findall(text))


def _flush_feed_lsa(r2):
    r2.cmd_raises(
        'vtysh -c "configure terminal" -c "interface lo" '
        '-c "no ipv6 address %s"' % FEED_ADDRESS
    )


def _restore_feed_lsa(r2):
    r2.cmd_raises(
        'vtysh -c "configure terminal" -c "interface lo" '
        '-c "ipv6 address %s"' % FEED_ADDRESS
    )


def _route_absent():
    return not _external_route_present(get_topogen().gears["r1"])


def _route_present():
    return _external_route_present(get_topogen().gears["r1"])


def test_ospf6_converge():
    "Adjacency up and r1 installed the redistributed external route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    assert _wait_until(lambda: _nbr_full(r1, R2_RID), timeout_s=90), (
        "adjacency did not reach Full"
    )
    ok, _ = topotest.run_and_expect(_route_present, True, count=60, wait=1)
    assert ok, "external route not installed on r1"
    assert _feed_lsa_id(r1) is not None, "r1 does not see r2's AS-External-LSA"


def test_ospf6_maxage_double_remove():
    "One MaxAge withdrawal runs the remove hook exactly once."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    if not _gdb_breakpoints_resolve(r1):
        pytest.skip("gdb or the hook symbols are unavailable")

    feed_lsa_id = _feed_lsa_id(r1)
    assert feed_lsa_id is not None

    r1.vtysh_cmd("debug ospf6 lsa as-external examine")
    withdraw_before, notfound_before = _log_marker_counts(r1, feed_lsa_id)
    gdb_pid, gdb_log = _gdb_count_start(r1, tgen.logdir)
    try:
        _flush_feed_lsa(r2)
        ok, _ = topotest.run_and_expect(_route_absent, True, count=30, wait=1)
        assert ok, "external route not withdrawn on r1"
        time.sleep(1)
        old, cons = _gdb_count_stop(r1, gdb_pid, gdb_log)
    finally:
        router_pid = _ospf6d_pid(r1)
        r1.cmd("kill -INT %s >/dev/null 2>&1 || true" % gdb_pid)
        r1.cmd("kill -CONT %s >/dev/null 2>&1 || true" % router_pid)

    logger.info("remove-hook counts: old=%d cons=%d", old, cons)
    assert old == 1, (
        "expected exactly one install-time remove of the old copy, got %d" % old
    )
    assert cons == 1, (
        "remove hook ran %d times for one MaxAge withdrawal "
        "(duplicate remove on the MaxAge copy)" % cons
    )

    withdraw_after, notfound_after = _log_marker_counts(r1, feed_lsa_id)
    assert withdraw_after - withdraw_before == 1, (
        "expected one 'Withdraw AS-External route' log line, got %d"
        % (withdraw_after - withdraw_before)
    )
    assert notfound_after - notfound_before == 0, (
        "second remove found nothing to do (redundant consumer work)"
    )
    assert _external_route_present(r1, KEEP_PREFIX), (
        "control prefix %s must stay installed (r2 remains ASBR)" % KEEP_PREFIX
    )


def test_ospf6_maxage_double_remove_second_cycle():
    "Re-adding and flushing again still runs the remove hook exactly once."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    if not _gdb_breakpoints_resolve(r1):
        pytest.skip("gdb or the hook symbols are unavailable")

    _restore_feed_lsa(r2)
    ok, _ = topotest.run_and_expect(_route_present, True, count=30, wait=1)
    assert ok, "external route not re-installed on r1"

    feed_lsa_id = _feed_lsa_id(r1)
    assert feed_lsa_id is not None

    withdraw_before, notfound_before = _log_marker_counts(r1, feed_lsa_id)
    gdb_pid, gdb_log = _gdb_count_start(r1, tgen.logdir)
    try:
        _flush_feed_lsa(r2)
        ok, _ = topotest.run_and_expect(_route_absent, True, count=30, wait=1)
        assert ok, "external route not withdrawn on r1 in cycle 2"
        time.sleep(1)
        old, cons = _gdb_count_stop(r1, gdb_pid, gdb_log)
    finally:
        router_pid = _ospf6d_pid(r1)
        r1.cmd("kill -INT %s >/dev/null 2>&1 || true" % gdb_pid)
        r1.cmd("kill -CONT %s >/dev/null 2>&1 || true" % router_pid)

    logger.info("cycle 2 remove-hook counts: old=%d cons=%d", old, cons)
    assert old == 1, (
        "cycle 2: expected exactly one install-time remove of the old copy, "
        "got %d" % old
    )
    assert cons == 1, (
        "cycle 2: remove hook ran %d times for one MaxAge withdrawal" % cons
    )

    withdraw_after, notfound_after = _log_marker_counts(r1, feed_lsa_id)
    assert withdraw_after - withdraw_before == 1, (
        "cycle 2: expected one 'Withdraw AS-External route' log line, got %d"
        % (withdraw_after - withdraw_before)
    )
    assert notfound_after - notfound_before == 0, (
        "cycle 2: second remove found nothing to do (redundant consumer work)"
    )
    assert _external_route_present(r1, KEEP_PREFIX), (
        "cycle 2: control prefix %s must stay installed" % KEEP_PREFIX
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
