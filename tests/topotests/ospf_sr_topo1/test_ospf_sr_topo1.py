#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_sr_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_sr_topo1.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+
         |         |                     |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |
         |         |eth-rt5       eth-rt4|         |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
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
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-1")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-2")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")


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
    logger.info("Test (step 1): verify RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step1/show_ip_route.ref"
        )


def test_mpls_lib_step1():
    logger.info("Test (step 1): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step1/show_mpls_table.ref"
        )


#
# Step 2
#
# Action(s):
# -Disable OSPF on the eth-rt5 interface on rt4
#
# Expected changes:
# -rt4 should uninstall the Adj-SIDs pointing to rt5
# -rt5 should uninstall the Adj-SIDs pointing to rt4
# -rt2 should reinstall rt5's Prefix-SIDs (2 nexthops deleted)
# -rt3 should reinstall rt4's Prefix-SIDs (2 nexthops deleted)
# -rt4 should reinstall rt3's Prefix-SIDs (1 nexthop deleted)
# -rt4 should reinstall rt5's Prefix-SIDs (1 nexthop changed)
# -rt5 should reinstall rt2's Prefix-SIDs (1 nexthop deleted)
# -rt5 should reinstall rt4's Prefix-SIDs (1 nexthop changed)
#
def test_rib_ipv4_step2():
    logger.info("Test (step 2): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling OSPF on the eth-rt5 interface on rt4")
    tgen.net["rt4"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt5" -c "no ip ospf network point-to-point"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step2/show_ip_route.ref"
        )


def test_mpls_lib_step2():
    logger.info("Test (step 2): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step2/show_mpls_table.ref"
        )


#
# Step 3
#
# Action(s):
# -Shut down the eth-rt4 interface on rt6
# -Shut down the eth-rt5 interface on rt6
#
# Expected changes:
# -All routers should uninstall rt6's Prefix-SIDs
# -rt4 and rt5 should uninstall the Adj-SIDs pointing to rt6
# -rt4 should reconverge rt5's Prefix-SIDs through rt2 using ECMP
# -rt5 should reconverge rt4's Prefix-SIDs through rt3 using ECMP
# -rt6 should uninstall all its IS-IS routes, Prefix-SIDs and Adj-SIDs
#
def test_rib_ipv4_step3():
    logger.info("Test (step 3): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Shutting down the eth-rt4 interface on rt6")
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "interface eth-rt4" -c "shutdown"')
    logger.info("Shutting down the eth-rt5 interface on rt6")
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "interface eth-rt5" -c "shutdown"')

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step3/show_ip_route.ref"
        )


def test_mpls_lib_step3():
    logger.info("Test (step 3): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step3/show_mpls_table.ref"
        )


#
# Step 4
#
# Action(s):
# -Bring up the eth-rt4 interface on rt6
# -Bring up the eth-rt5 interface on rt6
# -Change rt6's SRGB
#
# Expected changes:
# -All routers should install rt6's Prefix-SIDs
# -rt4 and rt5 should install Adj-SIDs for rt6
# -rt4 should reconverge rt5's Prefix-SIDs through rt6 using the new SRGB
# -rt5 should reconverge rt4's Prefix-SIDs through rt6 using the new SRGB
# -rt6 should reinstall all IS-IS routes and Prefix-SIDs from the network, and Adj-SIDs for rt4 and rt5
#
def test_rib_ipv4_step4():
    logger.info("Test (step 4): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Bringing up the eth-rt4 interface on rt6")
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "interface eth-rt4" -c "no shutdown"')
    logger.info("Bringing up the eth-rt5 interface on rt6")
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "interface eth-rt5" -c "no shutdown"')
    logger.info("Changing rt6's SRGB")
    tgen.net["rt6"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing global-block 18000 25999"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step4/show_ip_route.ref"
        )


def test_mpls_lib_step4():
    logger.info("Test (step 4): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step4/show_mpls_table.ref"
        )


#
# Step 5
#
# Action(s):
# -Disable SR on rt6
#
# Expected changes:
# -All routers should uninstall rt6's Prefix-SIDs
# -rt4 should uninstall rt5's Prefix-SIDs since the nexthop router hasn't SR enabled anymore
# -rt5 should uninstall rt4's Prefix-SIDs since the nexthop router hasn't SR enabled anymore
# -rt6 should uninstall all Prefix-SIDs from the network, and the Adj-SIDs for rt4 and rt5
#
def test_rib_ipv4_step5():
    logger.info("Test (step 5): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling SR on rt6")
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "router ospf" -c "no segment-routing on"')

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step5/show_ip_route.ref"
        )


def test_mpls_lib_step5():
    logger.info("Test (step 5): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step5/show_mpls_table.ref"
        )


#
# Step 6
#
# Action(s):
# -Enable SR on rt6
#
# Expected changes:
# -All routers should install rt6's Prefix-SIDs
# -rt4 should install rt5's Prefix-SIDs through rt6
# -rt5 should install rt4's Prefix-SIDs through rt6
# -rt6 should install all Prefix-SIDs from the network, and Adj-SIDs for rt4 and rt5
#
def test_rib_ipv4_step6():
    logger.info("Test (step 6): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling SR on rt6")
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "router ospf" -c "segment-routing on"')

    # FIXME: This is currently necessary because the CLI is not yet yang based.
    logger.info("Re-do rt6's SR prefix-sid config")
    tgen.net["rt6"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing prefix 6.6.6.6/32 index 60 explicit-null"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step6/show_ip_route.ref"
        )


def test_mpls_lib_step6():
    logger.info("Test (step 6): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step6/show_mpls_table.ref"
        )


#
# Step 7
#
# Action(s):
# -Delete rt1's Prefix-SIDs
#
# Expected changes:
# -All routers should uninstall rt1's Prefix-SIDs
#
def test_rib_ipv4_step7():
    logger.info("Test (step 7): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Deleting rt1's Prefix-SIDs")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "no segment-routing prefix 1.1.1.1/32 index 10"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step7/show_ip_route.ref"
        )


def test_mpls_lib_step7():
    logger.info("Test (step 7): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step7/show_mpls_table.ref"
        )


#
# Step 8
#
# Action(s):
# -Re-add rt1's Prefix-SIDs
#
# Expected changes:
# -All routers should install rt1's Prefix-SIDs
#
def test_rib_ipv4_step8():
    logger.info("Test (step 8): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Re-adding rt1's Prefix-SIDs")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing prefix 1.1.1.1/32 index 10"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step8/show_ip_route.ref"
        )


def test_mpls_lib_step8():
    logger.info("Test (step 8): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step8/show_mpls_table.ref"
        )


#
# Step 9
#
# Action(s):
# -Change rt1's Prefix-SIDs to use the no-php option
# -Change rt6's Prefix-SIDs to stop using the explicit-null option
#
# Expected changes:
# -rt2 and rt3 should reinstall rt1's Prefix-SIDs accordingly
# -rt4 and rt5 should reinstall rt6's Prefix-SIDs accordingly
#
def test_rib_ipv4_step9():
    logger.info("Test (step 9): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Changing rt1's Prefix-SIDs to use the no-php option")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing prefix 1.1.1.1/32 index 10 no-php-flag"'
    )

    logger.info("Change rt6's Prefix-SIDs to stop using the explicit-null option")
    tgen.net["rt6"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing prefix 6.6.6.6/32 index 60"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step9/show_ip_route.ref"
        )


def test_mpls_lib_step9():
    logger.info("Test (step 9): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step9/show_mpls_table.ref"
        )


#
# Step 10
#
# Action(s):
# -Remove the IPv4 address from rt4's eth-rt2-1 interface
#
# Expected changes:
# -rt2 should uninstall the IPv4 Adj-SIDs attached to the eth-rt4-1 interface
# -rt2 should reinstall all IPv4 Prefix-SIDs whose nexthop router is rt4 (ECMP shouldn't be used anymore)
# -rt4 should reinstall all IPv4 Prefix-SIDs whose nexthop router is rt2 (ECMP shouldn't be used anymore)
#
def test_rib_ipv4_step10():
    logger.info("Test (step 10): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing the IPv4 address from rt4's eth-rt2-1 interface")
    tgen.net["rt4"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2-1" -c "no ip address 10.0.2.4/24"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route ospf json", "step10/show_ip_route.ref"
        )


def test_mpls_lib_step10():
    logger.info("Test (step 10): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", "step10/show_mpls_table.ref"
        )


# FIXME: These tests don't work yet, this should be fixed with the
# switchover to a yang based CLI.
#
# Step 11
#
# Action(s):
# -Enter invalid SR configuration
#
# Expected changes:
# -All commands should be rejected
#
# def test_ospf_invalid_config_step11():
#    logger.info("Test (step 11): check if invalid configuration is rejected")
#    tgen = get_topogen()
#
#    # Skip if previous fatal error condition is raised
#    if tgen.routers_have_failure():
#        pytest.skip(tgen.errors)
#
#    logger.info("Entering invalid Segment Routing configuration...")
#    ret = tgen.net["rt1"].cmd(
#        'vtysh -c "conf t" -c "router ospf" -c "segment-routing prefix 1.1.1.1/32 index 10000"'
#    )
#    assert (
#        re.search("Configuration failed", ret) is not None
#    ), "Invalid SR configuration wasn't rejected"
#    ret = tgen.net["rt1"].cmd(
#        'vtysh -c "conf t" -c "router ospf" -c "segment-routing global-block 16000 14999"'
#    )
#    assert (
#        re.search("Configuration failed", ret) is not None
#    ), "Invalid SR configuration wasn't rejected"
#    ret = tgen.net["rt1"].cmd(
#        'vtysh -c "conf t" -c "router ospf" -c "segment-routing global-block 16000 16001"'
#    )
#    assert (
#        re.search("Configuration failed", ret) is not None
#    ), "Invalid SR configuration wasn't rejected"


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
