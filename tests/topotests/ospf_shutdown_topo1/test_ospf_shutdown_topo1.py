#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_shutdown_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2023 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_shutdown_topo1.py:

             +---------+
             |   RT1   |
             | 1.1.1.1 |
             +---------+
                  |eth-rt2
                  |
                  |10.0.1.0/24
                  |
                  |eth-rt1
             +---------+
             |   RT2   |
             | 2.2.2.2 |
             +---------+
          eth-rt3|  |eth-rt4
                 |  |
     10.0.2.0/24 |  |  10.0.3.0/24
       +---------+  +--------+
       |                     |
       |eth-rt2              |eth-rt2
  +---------+           +---------+
  |   RT3   |           |   RT4   |
  | 3.3.3.3 |           | 4.4.4.4 |
  +---------+           +---------+

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
    for router in ["rt1", "rt2", "rt3", "rt4"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt3")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt2")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2")


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
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def print_cmd_result(rname, command):
    print(get_topogen().gears[rname].vtysh_cmd(command, isjson=False))


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


#
# OSPFv2: Step 1
#
# Test initial network convergence
#
def test_ospfv2_step1():
    logger.info("OSPFv2 test (step 1): test initial network convergence")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf interface json", "step1/show_ip_ospf_interface.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf neighbor json", "step1/show_ip_ospf_neighbor.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf route json", "step1/show_ip_ospf_route.ref"
        )


#
# OSPFv2: Step 2
#
# Action(s):
# -rt2: disable the OSPF instance
#
# Expected changes:
# -rt2: all interface should be disabled
# -rt*: all adjacencies should go down
# -rt*: all learned routes should be removed
#
def test_ospfv2_step2():
    logger.info("OSPFv2 test (step 2): disable the OSPF instance")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling the OSPFv2 instance on rt2")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "shutdown"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf interface json", "step2/show_ip_ospf_interface.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf neighbor json", "step2/show_ip_ospf_neighbor.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf route json", "step2/show_ip_ospf_route.ref"
        )


#
# OSPFv2: Step 3
#
# Action(s):
# -rt2: reenable the OSPF instance
#
# Expected changes:
# -rt2: all interface should be reenabled
# -rt*: all adjacencies should come back up
# -rt*: all routes that were previously uninstalled should be installed again
#
def test_ospfv2_step3():
    logger.info("OSPFv2 test (step 3): reenable the OSPF instance")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Reenabling the OSPFv2 instance on rt2")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "no shutdown"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf interface json", "step1/show_ip_ospf_interface.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf neighbor json", "step1/show_ip_ospf_neighbor.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf route json", "step1/show_ip_ospf_route.ref"
        )


#
# OSPFv3: Step 1
#
# Test initial network convergence
#
def test_ospfv3_step1():
    logger.info("OSPFv3 test (step 1): test initial network convergence")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ipv6 ospf6 interface json", "step1/show_ipv6_ospf6_interface.ref"
        )
        router_compare_json_output(
            rname, "show ipv6 ospf6 neighbor json", "step1/show_ipv6_ospf6_neighbor.ref"
        )
        router_compare_json_output(
            rname, "show ipv6 ospf6 route json", "step1/show_ipv6_ospf6_route.ref"
        )


#
# OSPFv3: Step 2
#
# Action(s):
# -rt2: disable the OSPF instance
#
# Expected changes:
# -rt2: all interface should be disabled
# -rt*: all adjacencies should go down
# -rt*: all learned routes should be removed
#
def test_ospfv3_step2():
    logger.info("OSPFv3 test (step 2): disable the OSPF instance")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling the OSPFv3 instance on rt2")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router ospf6" -c "shutdown"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ipv6 ospf6 interface json", "step2/show_ipv6_ospf6_interface.ref"
        )
        router_compare_json_output(
            rname, "show ipv6 ospf6 neighbor json", "step2/show_ipv6_ospf6_neighbor.ref"
        )
        router_compare_json_output(
            rname, "show ipv6 ospf6 route json", "step2/show_ipv6_ospf6_route.ref"
        )


#
# OSPFv3: Step 3
#
# Action(s):
# -rt2: reenable the OSPF instance
#
# Expected changes:
# -rt2: all interface should be reenabled
# -rt*: all adjacencies should come back up
# -rt*: all routes that were previously uninstalled should be installed again
#
def test_ospfv3_step3():
    logger.info("OSPFv3 test (step 3): reenable the OSPF instance")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Reenabling the OSPFv3 instance on rt2")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router ospf6" -c "no shutdown"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ipv6 ospf6 interface json", "step1/show_ipv6_ospf6_interface.ref"
        )
        router_compare_json_output(
            rname, "show ipv6 ospf6 neighbor json", "step1/show_ipv6_ospf6_neighbor.ref"
        )
        router_compare_json_output(
            rname, "show ipv6 ospf6 route json", "step1/show_ipv6_ospf6_route.ref"
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
