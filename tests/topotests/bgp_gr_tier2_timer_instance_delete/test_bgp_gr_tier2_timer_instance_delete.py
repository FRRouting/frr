#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nick Bouliane <nbouliane@coreweave.com>
#

"""
bgpd must stop the tier-2 selection deferral timer of a BGP instance that it
deletes.

r1 starts with graceful restart and defers its path selection. It has a
directly connected peer, r2, and a multihop peer, so it does this in two
stages: once r2 is done, it starts the tier-2 selection deferral timer and
waits for the End-of-RIB of the multihop peer.

There is no router at the address of the multihop peer, so the tier-2 timer
runs until it expires, after 20 seconds. The test deletes the BGP instance
while the timer is running, in two ways:

- it terminates bgpd. bgpd writes the memory that it did not free at exit to
  its stderr, which must be empty. Without the fix it has the argument of the
  timer:

    bgpd: memstats:  Temporary memory              :      1 * (variably sized)

- it removes the instance from the configuration, and waits until the timer
  has expired. bgpd must still be running. Without the fix the timer is still
  there and bgpd crashes in bgp_graceful_deferral_timer_expire().
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

R2_IP = "192.168.1.2"

# "bgp graceful-restart select-defer-time" of r1
SELECT_DEFER_TIME = 20


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _has_key(node, key):
    "Tell if key is somewhere in the JSON output node."
    if isinstance(node, dict):
        return key in node or any(_has_key(value, key) for value in node.values())
    if isinstance(node, list):
        return any(_has_key(value, key) for value in node)
    return False


def _wait_tier2_timer(router):
    "Wait until router has started the tier-2 selection deferral timer."

    def _tier2_timer_running():
        try:
            output = json.loads(
                router.vtysh_cmd(
                    "show bgp neighbors {} graceful-restart json".format(R2_IP)
                )
            )
        except ValueError:
            return "bgpd does not answer"
        if not _has_key(output, "selectionDeferralTier2TimerRemaining"):
            return "the tier-2 selection deferral timer is not running"
        return None

    _, result = topotest.run_and_expect(_tier2_timer_running, None, count=60, wait=1)
    assert result is None, result


def _bgpd_pid(router):
    pid = router.cmd("cat /var/run/frr/bgpd.pid").strip()
    assert pid.isdigit(), "no pid for bgpd on {}: {!r}".format(router.name, pid)
    return pid


def _process_running(router, pid):
    # A process that exited and that nobody waited for is still in /proc
    status = router.cmd("cat /proc/{}/status 2>/dev/null || true".format(pid))
    state = [
        line.split()[1] for line in status.splitlines() if line.startswith("State:")
    ]
    return state not in ([], ["Z"])


def test_nothing_left_at_exit():
    "bgpd frees everything when it exits while the tier-2 timer is running."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    _wait_tier2_timer(r1)

    pid = _bgpd_pid(r1)
    r1.cmd("kill -TERM {}".format(pid))

    def _bgpd_gone():
        return "bgpd is still running" if _process_running(r1, pid) else None

    _, result = topotest.run_and_expect(_bgpd_gone, None, count=60, wait=1)
    assert result is None, result

    left = [
        line
        for line in r1.net.getStdErr("bgpd").splitlines()
        if "memstats:" in line or "showing active allocations" in line
    ]

    # The next test needs bgpd, with its configuration
    r1.cmd("rm -f /var/run/frr/bgpd.pid")
    r1.startDaemons(["bgpd"])

    assert not left, "bgpd did not free everything at exit:\n{}".format(
        "\n".join(left)
    )


def test_instance_deleted():
    "bgpd keeps running when its instance is deleted with the tier-2 timer running."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    _wait_tier2_timer(r1)

    pid = _bgpd_pid(r1)
    r1.vtysh_cmd(
        """
        configure terminal
        no router bgp 65001
        """
    )

    topotest.sleep(
        SELECT_DEFER_TIME + 2, "waiting for the tier-2 selection deferral timer"
    )

    assert _process_running(r1, pid), "bgpd is not running anymore"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
