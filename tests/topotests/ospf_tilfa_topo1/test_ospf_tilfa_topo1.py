#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_tilfa_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_tilfa_topo1.py:

This topology is intentionally kept simple, its main purpose is to verify that
generated backup label stacks are inserted correctly into the RIB. For fancy
topologies please use the unit test framework provided in `/tests/ospfd`.


                             +---------+                     +---------+
                             |         |                     |         |
       10.0.1.0/24    eth+rt1|   RT2   |eth+rt4       eth+rt2|   RT2   |
       +---------------------+ 2.2.2.2 +---------------------+ 4.4.4.4 |
       |                     |         |     10.0.3.0/24     |         |
       |eth+rt2              +---------+                     +---------+
  +---------+                                              eth+rt5|
  |         |                                                     |
  |   RT1   |                                          10.0.5.0/24|
  | 1.1.1.1 |                                                     |
  |         |                                                     |
  +---------+                                              eth+rt4|
       |eth+rt3              +---------+                     +---------+
       |                     |         |     10.0.4.0/24     |         |
       +---------------------+   RT3   +---------------------+   RT5   |
       10.0.2.0/24    eth+rt1| 3.3.3.3 |eth+rt5       eth-rt3| 5.5.5.5 |
                             |         |                     |         |
                             +---------+                     +---------+
"""

import os
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt3")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def router_compare_json_output(rname, command, reference):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def test_ospf_initial_convergence_step1():
    logger.info("Test (step 1): check initial convergence")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt1",
        "show ip route json",
        "step1/show_ip_route_initial.ref",
    )


def test_ospf_link_protection_step2():
    logger.info("Test (step 2): check OSPF link protection")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # enable TI-LFA link protection on all interfaces
    tgen.net["rt1"].cmd('vtysh -c "conf t" -c "router ospf" -c "fast-reroute ti-lfa"')

    router_compare_json_output(
        "rt1",
        "show ip route json",
        "step2/show_ip_route_link_protection.ref",
    )

    # disable TI-LFA link protection on all interfaces
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "no fast-reroute ti-lfa"'
    )

    # check if we got back to the initial route table
    router_compare_json_output(
        "rt1",
        "show ip route json",
        "step2/show_ip_route_initial.ref",
    )


def test_ospf_node_protection_step3():
    logger.info("Test (step 3): check OSPF node protection")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # enable TI-LFA node protection on all interfaces
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "fast-reroute ti-lfa node-protection"'
    )

    router_compare_json_output(
        "rt1",
        "show ip route json",
        "step3/show_ip_route_node_protection.ref",
    )

    # disable TI-LFA node protection on all interfaces
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "no fast-reroute ti-lfa node-protection"'
    )

    # check if we got back to the initial route table
    router_compare_json_output(
        "rt1",
        "show ip route json",
        "step3/show_ip_route_initial.ref",
    )


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
