#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nexthop AI
# Authored by Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#
"""
A helper starts LLGR for a peer whose graceful restart time is 0.

Topology: r1 --- r2, eBGP over IPv4 and over IPv6. r1 advertises
172.16.1.1/32 and 2001:db8:1::1/128 with "bgp graceful-restart restart-time
0" and a long-lived stale time, so when its bgpd dies r2 should skip the GR
window and mark both routes llgr-stale at once.

Killing r1 drops both sessions together. When r2's io thread reads both
socket closes before the next bgp_process_conn_error() pass, it clears them
as one batch: each session's GR restart timer is armed for 0 seconds, and
with a RIB this small the batch finishes in the same pass and queues
Clearing_Completed ahead of the expired timers -- the flush in
bgp_clearing_completed() must not drop them. Every kill/restart round must
end with both routes stale and carrying llgr-stale regardless of whether
that race lines up, and the marking must clear once r1 is back.

The race needs both session errors handled in the same bgp_process_conn_error()
pass, which depends on when the I/O thread reads each socket's close. Rounds
where it does not line up still check the LLGR outcome; the number of rounds
that hit the race is logged from r2's bgpd.log rather than asserted.
"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import kill_router_daemons, start_router_daemons, step

pytestmark = [pytest.mark.bgpd]

ROUTES = {
    "ipv4": ("172.16.1.1/32", "192.168.1.1"),
    "ipv6": ("2001:db8:1::1/128", "2001:db8:12::1"),
}
ROUNDS = 5
# zlog_debug under "debug bgp neighbor-events"; r2/bgpd.conf must keep it on,
# or the race count below reads 0 regardless.
REARM_LOG = "graceful restart timer re-armed after event flush"


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _route_fresh(router, afi, prefix, nexthop):
    output = json.loads(
        router.vtysh_cmd("show bgp {} unicast {} json".format(afi, prefix))
    )
    expected = {
        "paths": [
            {
                "valid": True,
                "stale": None,
                "community": None,
                "peer": {"peerId": nexthop},
            }
        ]
    }
    return topotest.json_cmp(output, expected)


def _route_llgr_stale(router, afi, prefix):
    output = json.loads(
        router.vtysh_cmd("show bgp {} unicast {} json".format(afi, prefix))
    )
    expected = {"paths": [{"stale": True, "community": {"string": "llgr-stale"}}]}
    return topotest.json_cmp(output, expected)


def _rearm_count(tgen):
    try:
        with open(os.path.join(tgen.logdir, "r2", "bgpd.log"), errors="replace") as f:
            return sum(REARM_LOG in line for line in f)
    except OSError:
        return 0


def _check_fresh(router, rnd):
    for afi, (prefix, peer) in ROUTES.items():
        step("Round {}: {} from r1 on r2, not stale".format(rnd, prefix))
        test_func = functools.partial(_route_fresh, router, afi, prefix, peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "Round {}: {} not learned fresh from r1: {}".format(
            rnd, prefix, result
        )


def test_bgp_llgr_restart_time_zero():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    raced = 0

    for rnd in range(1, ROUNDS + 1):
        _check_fresh(r2, rnd)
        rearmed_before = _rearm_count(tgen)

        step("Round {}: kill bgpd on r1".format(rnd))
        result = kill_router_daemons(tgen, "r1", ["bgpd"])
        assert not result, "Round {}: killing bgpd on r1 failed: {}".format(rnd, result)

        # With restart-time 0 there is no GR window to wait out; if r2 loses its
        # restart timer the routes stay plain stale until the stalepath timer.
        for afi, (prefix, _) in ROUTES.items():
            step("Round {}: {} is stale with llgr-stale on r2".format(rnd, prefix))
            test_func = functools.partial(_route_llgr_stale, r2, afi, prefix)
            _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
            assert (
                result is None
            ), "Round {}: {} not llgr-stale after r1 died: {}".format(
                rnd, prefix, result
            )

        if _rearm_count(tgen) > rearmed_before:
            raced += 1

        step("Round {}: start bgpd on r1".format(rnd))
        result = start_router_daemons(tgen, "r1", ["bgpd"])
        assert not result, "Round {}: starting bgpd on r1 failed: {}".format(
            rnd, result
        )

    _check_fresh(r2, "final")

    if raced:
        logger.info(
            "GR restart timer re-armed after the event flush in %d/%d rounds",
            raced,
            ROUNDS,
        )
    else:
        logger.warning(
            "GR restart timer re-arm race not hit in any of %d rounds; "
            "the event-flush re-arm path was not exercised",
            ROUNDS,
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
