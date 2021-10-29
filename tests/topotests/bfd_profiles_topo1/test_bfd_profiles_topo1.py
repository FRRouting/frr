#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_profiles_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_bfd_profiles_topo1.py: Test the FRR BFD profile protocol integration.
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

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd, pytest.mark.isisd, pytest.mark.ospfd]


def setup_module(mod):
    "Sets up the pytest environment"

    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r2", "r3"),
        "s3": ("r3", "r4"),
        "s4": ("r4", "r5"),
        "s5": ("r1", "r6"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        daemon_file = "{}/{}/mgmtd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_MGMTD, daemon_file)

        daemon_file = "{}/{}/bfdd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BFD, daemon_file)

        daemon_file = "{}/{}/bgpd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BGP, daemon_file)

        daemon_file = "{}/{}/isisd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ISIS, daemon_file)

        daemon_file = "{}/{}/ospfd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_OSPF, daemon_file)

        daemon_file = "{}/{}/ospf6d.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_OSPF6, daemon_file)

        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_wait_protocols_convergence():
    "Wait for all protocols to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_loopback_route(router, iptype, route, proto):
        "Wait until route is present on RIB for protocol."
        logger.info("waiting route {} in {}".format(route, router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show {} route json".format(iptype),
            {route: [{"protocol": proto}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" OSPF convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for R1 <-> R6 convergence.
    expect_loopback_route("r1", "ip", "10.254.254.6/32", "ospf")

    # Wait for R6 <-> R1 convergence.
    expect_loopback_route("r6", "ip", "10.254.254.1/32", "ospf")

    # Wait for R2 <-> R3 convergence.
    expect_loopback_route("r2", "ip", "10.254.254.3/32", "bgp")

    # Wait for R3 <-> R2 convergence.
    expect_loopback_route("r3", "ip", "10.254.254.2/32", "bgp")

    # Wait for R3 <-> R4 convergence.
    expect_loopback_route("r3", "ipv6", "2001:db8:3::/64", "isis")

    # Wait for R4 <-> R3 convergence.
    expect_loopback_route("r4", "ipv6", "2001:db8:1::/64", "isis")

    # Wait for R4 <-> R5 convergence.
    expect_loopback_route("r4", "ipv6", "2001:db8:3::/64", "ospf6")

    # Wait for R5 <-> R4 convergence.
    expect_loopback_route("r5", "ipv6", "2001:db8:2::/64", "ospf6")


def test_bfd_profile_values():
    "Assert that the BFD peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bfd peers to go up and checking profile values")

    for router in tgen.routers().values():
        json_file = "{}/{}/bfd-peers-initial.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show bfd peers json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=12, wait=0.5)
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
