#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_nhg_delete_race.py
#
# Copyright (c) 2026 by
# Alibaba Inc.
# Yuqing Zhao
#

"""
test_zebra_nhg_delete_race.py:

Verify that zebra correctly tolerates a race where the kernel has already
removed a Nexthop Group (NHG) by the time zebra issues RTM_DELNEXTHOP.
The kernel responds with ENOENT/ESRCH; without the fix that error is
propagated as ZEBRA_DPLANE_REQUEST_FAILURE, which causes
dplane_thread_loop() to remove the ctx from the work_list and never hand
it to the FPM provider. The result is a permanently leaked NHG entry on
the FPM side.

Topology:
    r1 ---eth0--- s1 --- r2
    r1 ---eth1--- s2 --- r3

r1 has 10 ECMP static routes (10.0.0.0/24 .. 10.0.9.0/24) each with two
nexthops (192.168.1.2 via r1-eth0 and 192.168.2.2 via r1-eth1).  All
routes share a single NHG in both zebra and the kernel.

Race scenario:
  1. Remove all static routes -> NHG refcnt drops to 0 -> zebra starts
     KEEP_AROUND timer (configured to 1 second via `nexthop-group keep 1`).
  2. At the same time, bring interfaces down -> kernel GCs the NHG.
  3. When the timer expires, zebra calls dplane_nexthop_delete() which
     sends RTM_DELNEXTHOP to kernel.  If kernel has already GC'd the
     NHG by then, it responds with ENOENT -- this is the race.

The ENOENT outcome cannot be reliably reproduced because the dplane
thread and kernel GC race on very tight timing.  The test exercises the
same code path (route withdrawal -> KEEP_AROUND timer ->
dplane_nexthop_delete -> RTM_DELNEXTHOP) and verifies no spurious
errors are produced.
"""

import os
import sys
import json
import pytest
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        if rname == "r1":
            router.load_frr_config(
                os.path.join(CWD, "{}/frr.conf".format(rname)),
                daemons=[
                    (TopoRouter.RD_ZEBRA, ""),
                    (TopoRouter.RD_STATIC, ""),
                ],
            )
        else:
            router.load_frr_config(
                os.path.join(CWD, "{}/frr.conf".format(rname)),
                daemons=[(TopoRouter.RD_ZEBRA, "")],
            )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _zebra_log_path(tgen):
    return os.path.join(tgen.logdir, "r1", "zebra.log")


def _count_zebra_log(tgen, needle):
    path = _zebra_log_path(tgen)
    if not os.path.isfile(path):
        return 0
    with open(path) as f:
        return sum(1 for line in f if needle in line)


def test_route_and_nhg_installed():
    "Static ECMP routes are installed in zebra and kernel"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Wait for ECMP route to be FIB-installed with 2 nexthops")

    def _check_installed():
        output = r1.vtysh_cmd("show ip route 10.0.0.0/24 json")
        try:
            rj = json.loads(output)
        except json.JSONDecodeError:
            return "json decode error"
        if "10.0.0.0/24" not in rj:
            return "route not present"
        route = rj["10.0.0.0/24"][0]
        if not route.get("installed", False):
            return "route not installed"
        fib = [nh for nh in route.get("nexthops", []) if nh.get("fib", False)]
        if len(fib) != 2:
            return "expected 2 fib nexthops, got {}".format(len(fib))
        return None

    _, result = topotest.run_and_expect(_check_installed, None, count=30, wait=1)
    assert result is None, "ECMP route not installed: {}".format(result)


def test_nhg_delete_race_with_kernel_cleanup():
    """
    Exercise the race condition scenario:
    - Remove all routes (NHG refcnt -> 0, KEEP_AROUND timer starts)
    - Bring interfaces down at timer expiry (kernel GCs NHG)
    - Timer expires -> dplane_nexthop_delete() -> RTM_DELNEXTHOP
    - Race: dplane send vs kernel GC completion
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    err_before = _count_zebra_log(tgen, "Failed to uninstall Nexthop ID")

    step("Remove all static routes (NHG refcnt -> 0, KEEP_AROUND timer starts)")
    cfg_lines = ["conf"]
    for i in range(10):
        cfg_lines.append("no ip route 10.0.{}.0/24 192.168.1.2".format(i))
        cfg_lines.append("no ip route 10.0.{}.0/24 192.168.2.2".format(i))
    r1.vtysh_cmd("\n".join(cfg_lines))

    step("Bring interfaces down at ~1s (kernel GCs NHG, races with timer expiry)")
    r1.run("(sleep 1 && ip link set dev r1-eth0 down && ip link set dev r1-eth1 down) &")

    step("Wait for KEEP_AROUND timer expiry + dplane processing")
    time.sleep(3)

    step("Verify no 'Failed to uninstall Nexthop ID' errors")
    # NOTE: The ENOENT outcome cannot be reliably reproduced due to tight
    # timing between the dplane thread and kernel GC.
    # This assertion catches it when the race is reproduced on unfixed code.
    err_after = _count_zebra_log(tgen, "Failed to uninstall Nexthop ID")
    assert err_after == err_before, (
        "Found {} new 'Failed to uninstall Nexthop ID' errors in zebra.log "
        "(before={} after={}); the kernel ENOENT/ESRCH on RTM_DELNEXTHOP "
        "is not being treated as success.".format(
            err_after - err_before, err_before, err_after
        )
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
