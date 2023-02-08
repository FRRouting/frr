#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_ipv6_rtadv.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by 6WIND
#

"""
 test_bgp_ipv6_rtadv.py: Test the FRR BGP daemon with BGP IPv6 interface
 with route advertisements on a separate netns.
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 2 routers.
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv4 routing tables.
    logger.info("Checking IPv4 routes for convergence")
    for router in tgen.routers().values():
        json_file = "{}/{}/ipv4_routes.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info("skipping file {}".format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip route json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=160, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # Check IPv6 routing tables.
    logger.info("Checking IPv6 routes for convergence")
    for router in tgen.routers().values():
        json_file = "{}/{}/ipv6_routes.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info("skipping file {}".format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ipv6 route json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=160, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
