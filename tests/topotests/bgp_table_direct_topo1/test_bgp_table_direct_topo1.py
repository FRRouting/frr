#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_table_direct_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_bgp_table_direct_topo1.py: Test the FRR PIM MSDP peer.
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
    +----+     +----+
    | r1 | <-> | r2 |
    +----+     +----+
       |
       |       +----+
       --------| r3 |
               +----+
    """

    # Create 3 routers
    for routern in range(1, 4):
        tgen.add_router(f"r{routern}")

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
    for _, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, f"{router.name}/frr.conf"))

    tgen.gears["r1"].run("ip link add blue type vrf table 10")
    tgen.gears["r1"].run("ip link set blue up")
    tgen.gears["r1"].run("ip link set r1-eth1 master blue")

    # Initialize all routers.
    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def expect_bgp_route(router, iptype, route, missing=False):
    "Wait until route is present on RIB for protocol."
    if missing:
        logger.info("waiting route {} go missing in {}".format(route, router))
    else:
        logger.info("waiting route {} in {}".format(route, router))

    tgen = get_topogen()
    expected_output = {route: [{"protocol": "bgp"}]}
    wait_time = 130
    if missing:
        expected_output = {route: None}
        wait_time = 5

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show {} route json".format(iptype),
        expected_output
    )

    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assertmsg = f'"{router}" convergence failure'
    assert result is None, assertmsg


def test_bgp_convergence():
    "Wait for BGP protocol convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    # Wait for R2
    expect_bgp_route("r2", "ip", "10.254.254.1/32")
    expect_bgp_route("r2", "ip", "10.254.254.2/32")
    expect_bgp_route("r2", "ip", "10.254.254.3/32")

    # Wait for R3
    expect_bgp_route("r3", "ip", "10.254.254.1/32")
    expect_bgp_route("r3", "ip", "10.254.254.2/32")
    expect_bgp_route("r3", "ip", "10.254.254.3/32")


def test_route_change_convergence():
    "Change routes in table 2000 to test zebra redistribution."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd("""
        configure terminal
        no ip route 10.254.254.2/32 lo table 2000
        ip route 10.254.254.10/32 lo table 2000
    """)

    # Check R2
    expect_bgp_route("r2", "ip", "10.254.254.2/32", missing=True)
    expect_bgp_route("r2", "ip", "10.254.254.10/32")

    # Check R3
    expect_bgp_route("r3", "ip", "10.254.254.2/32", missing=True)
    expect_bgp_route("r3", "ip", "10.254.254.10/32")


def test_configuration_removal_convergence():
    "Remove table direct configuration and check if routes went missing."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd("""
        configure terminal
        router bgp 65001
         address-family ipv4 unicast
          no redistribute table-direct 2000
         exit-address-family
        exit

        router bgp 65001 vrf blue
         address-family ipv4 unicast
          no redistribute table-direct 2000
         exit-address-family
        exit
    """)

    # Check R2
    expect_bgp_route("r2", "ip", "10.254.254.1/32", missing=True)
    expect_bgp_route("r2", "ip", "10.254.254.3/32", missing=True)
    expect_bgp_route("r2", "ip", "10.254.254.10/32", missing=True)

    # Check R3
    expect_bgp_route("r3", "ip", "10.254.254.1/32", missing=True)
    expect_bgp_route("r3", "ip", "10.254.254.3/32", missing=True)
    expect_bgp_route("r3", "ip", "10.254.254.10/32", missing=True)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
