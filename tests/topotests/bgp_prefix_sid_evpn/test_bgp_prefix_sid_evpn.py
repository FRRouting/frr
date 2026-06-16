#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2026 6WIND S.A.

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        daemons = [
            (TopoRouter.RD_ZEBRA, None),
            (TopoRouter.RD_STATIC, None),
        ]

        if rname != "r1":
            daemons.append((TopoRouter.RD_BGP, None))

        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)), daemons)

    tgen.start_router()

    r1_path = os.path.join(CWD, "r1")
    log_dir = os.path.join(tgen.logdir, "r1")
    tgen.gears["r1"].cmd("chmod u+x {}/bgp_injector.py".format(r1_path))
    tgen.gears["r1"].run("{}/bgp_injector.py {}".format(r1_path, log_dir))


def teardown_module(mod):
    tgen = get_topogen()

    log_dir = os.path.join(tgen.logdir, "r1")
    pid_file = os.path.join(log_dir, "bgp_injector.pid")

    logger.info("r1: sending SIGTERM to bgp_injector")
    tgen.gears["r1"].cmd("kill $(cat {})".format(pid_file))
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Waiting for BGP convergence")

    # Wait for BGP sessions to establish
    for rname, router in tgen.routers().items():
        if rname == "r1":
            continue

        expected_file = os.path.join(CWD, rname, "show_bgp_summary.json")
        expected = json.load(open(expected_file))

        logger.info("Checking BGP convergence on {}".format(rname))
        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            "show bgp summary json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assertmsg = '"{}" BGP convergence failure'.format(rname)
        assert result is None, assertmsg


def test_show_bgp_evpn_route_detail():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking EVPN global table")

    # Wait for BGP sessions to establish
    for rname, router in tgen.routers().items():
        if rname == "r1":
            continue

        expected_file = os.path.join(CWD, rname, "show_bgp_l2vpn_evpn_route_detail.json")
        expected = json.load(open(expected_file))

        logger.info("Checking EVPN global table on {}".format(rname))
        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            "show bgp l2vpn evpn route detail json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assertmsg = '"{}" BGP EVPN global table failure'.format(rname)
        assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
