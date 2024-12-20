#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_msdp_topo4.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2024 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_msdp_topo4.py: Test the FRR PIM MSDP peer.
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
    h1----r1----r2----r4----h2
          |    /
          |   /
          |  /
           r3
    """

    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router(f"r{routern}")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s5")
    tgen.add_host("h1", "192.168.10.100/24", "via 192.168.10.1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s6")
    tgen.add_host("h2", "192.168.20.100/24", "via 192.168.20.1")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["h2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        file = f"{CWD}/{router.name}/frr.conf"
        router.load_frr_config(file)

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
        logger.info(f"waiting route {route} in {router}")
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            f"show {iptype} route json",
            {route: [{"protocol": proto}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = f'"{router}" convergence failure'
        assert result is None, assertmsg

    # Wait for R1
    expect_loopback_route("r1", "ip", "10.254.254.2/32", "bgp")
    expect_loopback_route("r1", "ip", "10.254.254.3/32", "bgp")
    expect_loopback_route("r1", "ip", "10.254.254.4/32", "bgp")

    # Wait for R2
    expect_loopback_route("r2", "ip", "10.254.254.1/32", "bgp")
    expect_loopback_route("r2", "ip", "10.254.254.3/32", "bgp")
    expect_loopback_route("r2", "ip", "10.254.254.4/32", "bgp")

    # Wait for R3
    expect_loopback_route("r3", "ip", "10.254.254.1/32", "bgp")
    expect_loopback_route("r3", "ip", "10.254.254.2/32", "bgp")
    expect_loopback_route("r3", "ip", "10.254.254.4/32", "bgp")

    # Wait for R4
    expect_loopback_route("r4", "ip", "10.254.254.1/32", "bgp")
    expect_loopback_route("r4", "ip", "10.254.254.2/32", "bgp")
    expect_loopback_route("r4", "ip", "10.254.254.3/32", "bgp")


def test_msdp_sa_check():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    MCAST_ADDRESS = "229.1.2.3"
    app_helper.run("h1", ["--send=0.7", MCAST_ADDRESS, "h1-eth0"])
    app_helper.run("h2", [MCAST_ADDRESS, "h2-eth0"])

    def test_r2_mroute():
        r2_expect = {
            "229.1.2.3": {
                "192.168.10.100": {
                    "rp": "10.254.254.1",
                    "local": "no",
                }
            }
        }
        out = tgen.gears["r2"].vtysh_cmd("show ip msdp sa json", isjson=True)
        return topotest.json_cmp(out, r2_expect)

    logger.info("Waiting for R2 multicast routes")
    _, val = topotest.run_and_expect(test_r2_mroute, None, count=55, wait=2)
    assert val is None, "multicast route convergence failure"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
