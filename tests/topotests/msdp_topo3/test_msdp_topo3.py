#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_msdp_topo3.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2024 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_msdp_topo3.py: Test the FRR PIM MSDP peer.
"""

import os
import sys
import json
from functools import partial
import re
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

app_helper = McastTesterHelper()


def build_topo(tgen):
    """
    +----+     +----+     +----+     +----+
    | h1 | <-> | r1 | <-> | r2 | <-> | h2 |
    +----+     +----+     +----+     +----+

          -------------------------->

    Multicast traffic SG(192.168.100.100, 229.1.1.1)
    """

    # Create 2 routers
    for routern in range(1, 3):
        tgen.add_router(f"r{routern}")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Create a host connected and direct at r1:
    switch = tgen.add_switch("s2")
    tgen.add_host("h1", "192.168.100.100/24", "via 192.168.100.1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # Create a host connected and direct at r2:
    switch = tgen.add_switch("s3")
    tgen.add_host("h2", "192.168.101.100/24", "via 192.168.101.1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, f"{router.name}/frr.conf"))

    # Initialize all routers.
    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def test_bgp_convergence():
    "Wait for BGP protocol convergence"
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
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for R1
    expect_loopback_route("r1", "ip", "10.254.254.2/32", "bgp")

    # Wait for R2
    expect_loopback_route("r2", "ip", "10.254.254.1/32", "bgp")


def test_sa_learn():
    """
    Test that the learned SA uses the configured originator ID instead
    of the configured RP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    MCAST_ADDRESS = "229.1.1.1"
    app_helper.run("h1", ["--send=0.7", MCAST_ADDRESS, "h1-eth0"])
    app_helper.run("h2", [MCAST_ADDRESS, "h2-eth0"])

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r2"],
        "show ip msdp sa json",
        {
            "229.1.1.1": {
                "192.168.100.100": {
                    "rp": "10.254.254.1",
                    "local": "no",
                }
            }
        }
    )
    _, result = topotest.run_and_expect(test_func, None, count=100, wait=1)
    assert result is None, 'r2 SA convergence failure'


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
