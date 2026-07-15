#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Verify that a graceful-restart "restarting speaker" does NOT advertise its
End-of-RIB marker to a helper before it has relearned/re-advertised routes
from its other (upstream) peers.

Topology:

    r1 (65001) ---- r2 (65002) ---- r3 (65003)
    upstream        restarting       helper
    origin          speaker (DUT)

r1 originates 172.16.255.1/32 and feeds it to r2, which advertises it to r3.

Reproduction:
  1. Everything converges; r3 has 172.16.255.1/32 via r2.
  2. r1 (the upstream) is stopped, so once r2 restarts it has no way to
     relearn the route. While r1 is down, r2 retains the route and keeps
     advertising it to r3.
  3. bgpd on r2 is killed and started again. r3 becomes a helper for
     r2 and retains 172.16.255.1/32 as stale.
  4. r2 re-establishes with r3 (but not with the down r1). A correct
     restarting speaker must defer its End-of-RIB to r3 until it has relearned
     routes (or select-defer-time elapses). If it instead emits the EoR right
     away, r3 flushes the stale route immediately.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    step,
    stop_router,
    kill_router_daemons,
    start_router_daemons,
)

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # r1 <-> r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r2 <-> r3
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_gr_premature_eor():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    PREFIX = "172.16.255.1/32"

    def _r3_has_prefix():
        output = json.loads(r3.vtysh_cmd(f"show bgp ipv4 unicast {PREFIX} json"))
        expected = {"paths": [{"nexthops": [{"ip": "192.168.23.2"}]}]}
        return topotest.json_cmp(output, expected)

    def _r2r3_established():
        output = json.loads(r2.vtysh_cmd(f"show bgp ipv4 neighbors 192.168.23.3 json"))
        expected = {"192.168.23.3": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    step("Initial convergence: r3 learns 172.16.255.1/32 via r2")
    test_func = functools.partial(_r3_has_prefix)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"r3 did not learn {PREFIX} from r2"

    step("Stop upstream r1 so r2 cannot relearn the route after it restarts")
    stop_router(tgen, "r1")

    step("r2 (helper for r1) keeps advertising the route to r3 while r1 is down")
    test_func = functools.partial(_r3_has_prefix)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"r3 lost {PREFIX} before r2 was even restarted"

    step("Restart bgpd on r2 (plain restart, no -K)")
    kill_router_daemons(tgen, "r2", ["bgpd"])
    start_router_daemons(tgen, "r2", ["bgpd"])
    # With the integrated (mgmtd-held) config, a bgpd-only restart does not
    # restore the BGP config on its own, so re-apply it explicitly.
    r2.cmd("vtysh -f {}".format(os.path.join(CWD, "r2/frr.conf")))

    step("Wait for the r2<->r3 session to re-establish")
    test_func = functools.partial(_r2r3_established)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2<->r3 did not re-establish after r2 restart"

    step(
        f"r3 must retain {PREFIX}: r2 must not emit End-of-RIB before relearning routes"
    )

    # r3 (the helper) retains the route as *stale* while it waits for r2's
    # End-of-RIB. Correct behaviour holds the EoR for up to select-defer-time
    # (120s here), so the route stays present and stale the whole time. On the
    # buggy code r2 emits the EoR right after re-establishing (before relearning
    # from the down r1); the first observable effect on r3 is the stale flag
    # being cleared, immediately followed by the route being flushed (r1 is down,
    # so nothing refreshes it). Asserting on the stale flag rather than mere
    # presence catches that un-staling deterministically, before/without racing
    # the delete. Poll for 20s and require route+stale on *every* poll.
    def _r3_keeps_prefix_stable():
        for _ in range(20):
            output = json.loads(r3.vtysh_cmd(f"show bgp ipv4 unicast {PREFIX} json"))
            paths = output.get("paths")
            if not paths:
                return False  # route flushed
            if not paths[0].get("stale"):
                return False  # stale flag cleared => r2 sent EoR prematurely
            time.sleep(1)
        return True

    assert _r3_keeps_prefix_stable(), (
        f"r2 advertised End-of-RIB before relearning routes: "
        f"r3 un-staled/flushed {PREFIX} prematurely"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
