#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_nssa_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2023 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_nssa_topo1.py:

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
# Step 1
#
# Test initial network convergence
#
def test_rib_step1():
    logger.info("Test (step 1): test initial network convergence")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step1/show_ip_ospf_route.ref"
        )


#
# Step 2
#
# Action(s):
# -rt3: configure an NSSA default route
#
# Expected changes:
# -rt2: add NSSA default route pointing to rt3
#
def test_rib_step2():
    logger.info("Test (step 2): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding NSSA default on rt4")
    tgen.net["rt3"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "area 1 nssa default-information-originate"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step2/show_ip_ospf_route.ref"
        )


#
# Step 3
#
# Action(s):
# -rt3: remove NSSA default route
#
# Expected changes:
# -rt2: remove NSSA default route
#
def test_rib_step3():
    logger.info("Test (step 3): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing NSSA default on rt4")
    tgen.net["rt3"].cmd('vtysh -c "conf t" -c "router ospf" -c "area 1 nssa"')

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step3/show_ip_ospf_route.ref"
        )


#
# Step 4
#
# Action(s):
# -rt2: configure an NSSA range for 172.16.1.0/24
#
# Expected changes:
# -rt1: the 172.16.1.1/32 and 172.16.1.2/32 routes should be removed
# -rt1: the 172.16.1.0/24 route should be added
#
def test_rib_step4():
    logger.info("Test (step 4): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring NSSA range on rt2")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "area 1 nssa range 172.16.1.0/24"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step4/show_ip_ospf_route.ref"
        )


#
# Step 5
#
# Action(s):
# -rt4: remove the 172.16.1.1/32 static route
#
# Expected changes:
# -None (the 172.16.1.0/24 range is still active because of 172.16.1.2/32)
#
def test_rib_step5():
    logger.info("Test (step 5): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing first static route in rt4")
    tgen.net["rt4"].cmd('vtysh -c "conf t" -c "no ip route 172.16.1.1/32 Null0"')

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step5/show_ip_ospf_route.ref"
        )


#
# Step 6
#
# Action(s):
# -rt4: remove the 172.16.1.2/32 static route
#
# Expected changes:
# -rt1: remove the 172.16.1.0/24 route since the NSSA range is no longer active
#
def test_rib_step6():
    logger.info("Test (step 6): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing second static route in rt4")
    tgen.net["rt4"].cmd('vtysh -c "conf t" -c "no ip route 172.16.1.2/32 Null0"')

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step6/show_ip_ospf_route.ref"
        )


#
# Step 7
#
# Action(s):
# -rt4: readd the 172.16.1.1/32 and 172.16.1.2/32 static routes
#
# Expected changes:
# -rt1: readd the 172.16.1.0/24 route since the NSSA range is active again
#
def test_rib_step7():
    logger.info("Test (step 7): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Readding static routes in rt4")
    tgen.net["rt4"].cmd('vtysh -c "conf t" -c "ip route 172.16.1.1/32 Null0"')
    tgen.net["rt4"].cmd('vtysh -c "conf t" -c "ip route 172.16.1.2/32 Null0"')

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step7/show_ip_ospf_route.ref"
        )


#
# Step 8
#
# Action(s):
# -rt2: update the NSSA range with a static cost
#
# Expected changes:
# -rt1: update the metric of the 172.16.1.0/24 route from 20 to 1000
#
def test_rib_step8():
    logger.info("Test (step 8): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Updating the NSSA range cost on rt2")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "area 1 nssa range 172.16.1.0/24 cost 1000"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step8/show_ip_ospf_route.ref"
        )


#
# Step 9
#
# Action(s):
# -rt2: update the NSSA range to not advertise itself
#
# Expected changes:
# -rt1: the 172.16.1.0/24 route should be removed
#
def test_rib_step9():
    logger.info("Test (step 9): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Updating the NSSA range to not advertise itself")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "area 1 nssa range 172.16.1.0/24 not-advertise"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step9/show_ip_ospf_route.ref"
        )


#
# Step 10
#
# Action(s):
# -rt2: remove the NSSA range
#
# Expected changes:
# -rt1: the 172.16.1.1/32 and 172.16.1.2/32 routes should be added
#
def test_rib_step10():
    logger.info("Test (step 10): verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing NSSA range on rt2")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "no area 1 nssa range 172.16.1.0/24"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "step10/show_ip_ospf_route.ref"
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
