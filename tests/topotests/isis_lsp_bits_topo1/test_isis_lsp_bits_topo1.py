#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_lsp_bits_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by  Volta Networks
#

"""
test_isis_lsp_bits_topo1.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |   L1    |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |  L1|L2  |     10.0.1.0/24     |  L1|L2  |
         +---------+                     +---------+
      eth-rt4|                         eth-rt5|
             |                                |
  10.0.2.0/24|                                |10.0.4.0/24
             |                                |
      eth-rt2|                         eth-rt3|
         +---------+                     +---------+
         |         |                     |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |
         |  L1|L2  |eth-rt5       eth-rt4|  L1|L2  |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|   L1    |eth-rt5
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

pytestmark = [pytest.mark.isisd]


# Global multi-dimensional dictionary containing all expected outputs
outputs = {}


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
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3")

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
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
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


#
# Step 1
#
# Test initial network convergence
# Attach-bit defaults to on, so expect default route pointing to L1|L2 router
#
def test_isis_adjacencies_step1():
    logger.info("Test (step 1): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step1/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step1():
    logger.info("Test (step 1): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step1/show_ip_route.ref"
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step1/show_ipv6_route.ref"
        )


#
# Step 2
#
# Action(s):
# -Disable sending Attach bit on RT2 and RT4
#
# Expected changes:
# -RT1 should remove the default route pointing to RT2
# -RT6 should remove the default route pointing to RT4
#
def test_rib_ipv4_step2():
    logger.info("Test (step 2): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling setting the attached-bit on RT2 and RT4")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no attached-bit send"'
    )
    tgen.net["rt4"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no attached-bit send"'
    )

    for rname in ["rt1", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step2/show_ip_route.ref"
        )


def test_rib_ipv6_step2():
    logger.info("Test (step 2): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step2/show_ipv6_route.ref"
        )


#
# Step 3
#
# Action(s):
# -restore attach-bit, enable sending attach-bit
# -disble processing a LSP with attach bit set
#
# Expected changes:
# -RT1 and RT6 should not install a default route
#
def test_rib_ipv4_step3():
    logger.info("Test (step 3): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enable setting the attached-bit on RT2 and RT4")
    tgen.net["rt2"].cmd('vtysh -c "conf t" -c "router isis 1" -c "attached-bit send"')
    tgen.net["rt4"].cmd('vtysh -c "conf t" -c "router isis 1" -c "attached-bit send"')

    logger.info("Disable processing received attached-bit in LSP on RT1 and RT6")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "attached-bit receive ignore"'
    )
    tgen.net["rt6"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "attached-bit receive ignore"'
    )

    for rname in ["rt1", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step3/show_ip_route.ref"
        )


def test_rib_ipv6_step3():
    logger.info("Test (step 3): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step3/show_ipv6_route.ref"
        )


#
# Step 4
#
# Action(s):
# -restore back to default attach-bit config
#
# Expected changes:
# -RT1 and RT6 should add default route
# -no changes on other routers
#
def test_rib_ipv4_step4():
    logger.info("Test (step 4): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "restore default processing on received attached-bit in LSP on RT1 and RT6"
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no attached-bit receive ignore"'
    )
    tgen.net["rt6"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no attached-bit receive ignore"'
    )

    for rname in ["rt1", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step4/show_ip_route.ref"
        )


def test_rib_ipv6_step4():
    logger.info("Test (step 4): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step4/show_ipv6_route.ref"
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
