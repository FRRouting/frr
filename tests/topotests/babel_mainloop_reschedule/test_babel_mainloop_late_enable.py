#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_babel_mainloop_late_enable.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_babel_mainloop_late_enable.py: enabling a Babel interface long after
startup must promptly reschedule the babeld main loop.

Topology:

    r1-eth1 (stub 10.1.1.0/24)          r2-eth1 (stub 10.1.2.0/24)
       |                                   |
    [ r1 ] --- r1-eth0 --- sw1 --- r2-eth0 --- [ r2 ]

Both routers start with `router babel` but no `network`, so their main
loops fall asleep on a far-future wakeup (expiry_time, 22-37 s after
routing-process creation).  Enabling both interfaces at once then leaves
the wire silent on the unguarded build until the first loop wakeup - no
peer hello can arrive to flush the buffered hellos/requests through the
receive path - so both stubs converge tens of seconds late.  The guarded
build reschedules the loop at `network` time and converges within a few
seconds.

The 12 s sleep before enabling interfaces does two things: it keeps the
test clear of the 200 ms babel_init_routing_process timer, so this
scenario exercises the reschedule path only (the init race is covered by
the sibling startup_init test); and it lets the main-loop cycling
triggered by the startup config noise (interface/address notifications
arming flush timeouts, initial resends) drain, so that by `network` time
the loop is genuinely asleep on the far-future wakeup.  On the unguarded
build the first possible wakeup is then expiry_time, 22-37 s after
routing-process creation, i.e. never sooner than 10 s after `network`;
the guarded build reschedules the loop at `network` time and converges
within a few seconds.

The startup config deliberately carries no `babel hello-interval`: that
command arms the interface hello timer at config time, and since
send_hello_noupdate() re-arms it unconditionally the main loop keeps
cycling roughly once per hello interval even while no interface is
enabled.  The loop would then flush the buffered hellos within a second
or two even without the reschedule, hiding the bug.  With the default
intervals untouched, no per-interface timer is armed before `network`,
and the loop truly sleeps on the far-future wakeup.
"""

import os
import sys
import time
import pytest

pytestmark = [pytest.mark.babeld]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

R1_PREFIX = "10.1.1.0/24"
R2_PREFIX = "10.1.2.0/24"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Babel link: r1-eth0 <-> r2-eth0
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    # Stubs carrying the originated prefixes
    sw2 = tgen.add_switch("sw2")
    sw2.add_link(tgen.gears["r1"])
    sw3 = tgen.add_switch("sw3")
    sw3.add_link(tgen.gears["r2"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "late_enable/{}/zebra.conf".format(rname)),
        )
        router.load_config(
            TopoRouter.RD_BABEL,
            os.path.join(CWD, "late_enable/{}/babeld.conf".format(rname)),
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _forwarding_nexthops(router, prefix):
    """Return the list of active forwarding nexthops for prefix on router.

    A retracted/unreachable route stays in the RIB with a reject
    ("unreachable") nexthop and no gateway, so it is not counted here.
    """
    output = router.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
    if not output or prefix not in output:
        return []
    fwd = []
    for entry in output[prefix]:
        if entry.get("protocol") != "babel":
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("unreachable") or nh.get("reject") or nh.get("blackhole"):
                continue
            if nh.get("ip"):
                fwd.append(nh)
    return fwd


def _prefix_reachable(router, prefix):
    "Return None when prefix is installed via babel with a forwarding nexthop."
    if _forwarding_nexthops(router, prefix):
        return None
    return "{} is not reachable via babel on {}".format(prefix, router.name)


def _reachable_within(router, prefix, seconds):
    "True when prefix becomes reachable via babel within seconds of wall time."
    deadline = time.time() + seconds
    while True:
        if _prefix_reachable(router, prefix) is None:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(1)


def test_late_enable_converges_promptly():
    "Enabling both babel interfaces after startup must converge both stubs fast."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Both daemons read `router babel` at startup and their init has
    # completed by now (200 ms timer); the main loops are asleep on a
    # far-future wakeup with no enabled interface.
    time.sleep(12)
    logger.info("Enabling babel on r1-eth0 and r2-eth0 after startup")
    r1.vtysh_cmd("configure terminal\nrouter babel\nnetwork r1-eth0\n")
    r2.vtysh_cmd("configure terminal\nrouter babel\nnetwork r2-eth0\n")

    # Unguarded builds stay silent until the expiry wakeup, which cannot
    # come sooner than 10 s after `network` (expiry_time is 22-37 s after
    # routing-process creation, and we slept 12 s).  8 s is unreachable
    # for them but comfortable for the rescheduled loop (~2-4 s).  Poll
    # against the wall clock, not run_and_expect's count: each vtysh
    # round-trip costs ~2-3 s, so count=8 would span ~24 s.
    assert _reachable_within(r2, R1_PREFIX, 8), (
        "r2 did not learn a reachable {} promptly after late enable".format(R1_PREFIX)
    )

    assert _reachable_within(r1, R2_PREFIX, 8), (
        "r1 did not learn a reachable {} promptly after late enable".format(R2_PREFIX)
    )


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        router.stop()
        for daemon in ["babeld", "zebra"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
