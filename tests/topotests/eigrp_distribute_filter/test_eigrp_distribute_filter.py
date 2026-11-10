#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# test_eigrp_distribute_filter.py
#
# Copyright (c) 2026 by Chenlang Li
#
"""
Regression test for the uint32_t overflow in eigrp_calculate_total_metrics().

When eigrpd starts with a per-interface inbound distribute-list that denies all
routes, the filtering code sets the route delay to EIGRP_MAX_METRIC (0xffffffff).
Before the fix, adding the interface delay wrapped the value in 32-bit arithmetic,
producing a distance just below the feasibility-condition threshold.  DUAL then
dispatched EIGRP_FSM_EVENT_NQ_FCN and asserted because no successor existed.

The bug triggered via the ten-second graceful-restart timer that fires after a
distribute-list is applied.  This test waits past that deadline and asserts that
eigrpd is still running and that the denied route does not appear in the RIB.
"""

import os
import sys
import pytest

pytestmark = [pytest.mark.eigrpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    """
    r1 --[sw1]-- r2

    r2 advertises 10.1.5.0/24 (loopback) into EIGRP AS 1.
    r1 has a per-interface inbound distribute-list that denies everything on r1-eth0.
    """
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_EIGRP, os.path.join(CWD, "{}/eigrpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_eigrp_distribute_filter_no_crash():
    """
    Wait 25 seconds past startup so the ten-second distribute-list GR timer
    fires at least once.  Assert that eigrpd on r1 is still alive and that
    the denied prefix 10.1.5.0/24 is absent from the RIB.

    Before the fix eigrpd aborted with:
        eigrpd/eigrp_fsm.c:426: eigrp_fsm_event_nq_fcn(): assertion (successors) failed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Waiting 25 s for the distribute-list GR timer to fire (fires at ~10 s)"
    )
    topotest.sleep(25, "Waiting for EIGRP distribute-list GR timer")

    r1 = tgen.gears["r1"]

    # eigrpd must still be running — any crash shows up as a router failure
    assert not tgen.routers_have_failure(), (
        "eigrpd crashed after distribute-list GR timer fired: {}".format(tgen.errors)
    )

    # 10.1.5.0/24 must be absent from r1's RIB; the filter denies it inbound
    rib = r1.vtysh_cmd("show ip route json", isjson=True)
    assert "10.1.5.0/24" not in rib, (
        "10.1.5.0/24 should be filtered by the inbound distribute-list on r1 "
        "but it appears in the RIB: {}".format(rib.get("10.1.5.0/24"))
    )

    logger.info(
        "PASS: eigrpd survived the GR timer and 10.1.5.0/24 is correctly filtered"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
