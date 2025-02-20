#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_tilfa_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_isis_lfa_topo1.py:

                                       +---------+
                                       |         |
      +--------------------------------+   RT1   +-------------------------------+
      |                  +-------------+         +-------------+                 |
      |                  |             |         |             |                 |
      |                  |             +----+----+             |                 |
      |                  |                  |                  |20               |
      |                  |                  |                  |                 |
      |                  |                  |                  |                 |
 +----+----+        +----+----+        +----+----+        +----+----+       +----+----+
 |         |        |         |        |         |        |         |       |         |
 |   RT2   |   5    |   RT3   |        |   RT4   |        |   RT5   |       |   RT6   |
 |         +--------+         |        |         |        |         |       |         |
 |         |        |         |        |         |        |         |       |         |
 +----+----+        +----+----+        +----+----+        +----+----+       +----+----+
      |                  |                  |                  |                 |
      |                  |                  |15                |                 |
      |5                 |                  |                  |                 |
      |                  |             +----+----+             |                 |
      |                  |             |         |             |                 |
      |                  +-------------+   RT7   +-------------+                 |
      +--------------------------------+         +-------------------------------+
                                       |         |
                                       +---------+
"""

import os
import sys
import pytest
import json
import tempfile
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
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7"]:
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
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt3")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt1")
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt4")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt1")
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt1")
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt1")
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt7")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt2")
    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt7")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt3")
    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt7")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt4")
    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt7")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt5")
    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt7")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt6")

    #
    # Populate multi-dimensional dictionary containing all expected outputs
    #
    files = ["show_ipv6_route.ref", "show_yang_interface_isis_adjacencies.ref"]
    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7"]:
        outputs[rname] = {}
        for step in range(1, 16 + 1):
            outputs[rname][step] = {}
            for file in files:
                if step == 1:
                    # Get snapshots relative to the expected initial network convergence
                    filename = "{}/{}/step{}/{}".format(CWD, rname, step, file)
                    outputs[rname][step][file] = open(filename).read()
                else:
                    if rname != "rt1":
                        continue
                    if file == "show_yang_interface_isis_adjacencies.ref":
                        continue

                    # Get diff relative to the previous step
                    filename = "{}/{}/step{}/{}.diff".format(CWD, rname, step, file)

                    # Create temporary files in order to apply the diff
                    f_in = tempfile.NamedTemporaryFile(mode="w")
                    f_in.write(outputs[rname][step - 1][file])
                    f_in.flush()
                    f_out = tempfile.NamedTemporaryFile(mode="r")
                    os.system(
                        "patch -s -o %s %s %s" % (f_out.name, f_in.name, filename)
                    )

                    # Store the updated snapshot and remove the temporary files
                    outputs[rname][step][file] = open(f_out.name).read()
                    f_in.close()
                    f_out.close()


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
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "/dev/null".format(rname))
        )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def router_compare_json_output(rname, command, reference, wait=0.5, count=120):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    expected = json.loads(reference)

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


#
# Step 1
#
# Test initial network convergence
#
def test_isis_adjacencies_step1():
    logger.info("Test (step 1): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            outputs[rname][1]["show_yang_interface_isis_adjacencies.ref"],
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][1]["show_ipv6_route.ref"]
        )


#
# Step 2
#
# Action(s):
# -Disable LFA protection on all interfaces
#
# Expected changes:
# -rt1 should uninstall all backup nexthops from all routes
#
def test_rib_ipv6_step2():
    logger.info("Test (step 2): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling LFA protection on all rt1 interfaces")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2" -c "no isis fast-reroute lfa"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt3" -c "no isis fast-reroute lfa"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt4" -c "no isis fast-reroute lfa"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt5" -c "no isis fast-reroute lfa"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt6" -c "no isis fast-reroute lfa"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][2]["show_ipv6_route.ref"]
        )


#
# Step 3
#
# Action(s):
# -Re-enable LFA protection on all interfaces
#
# Expected changes:
# -Revert changes from the previous step
#
def test_rib_ipv6_step3():
    logger.info("Test (step 3): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Re-enabling LFA protection on all rt1 interfaces")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2" -c "isis fast-reroute lfa"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt3" -c "isis fast-reroute lfa"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt4" -c "isis fast-reroute lfa"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt5" -c "isis fast-reroute lfa"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt6" -c "isis fast-reroute lfa"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][3]["show_ipv6_route.ref"]
        )


#
# Step 4
#
# Action(s):
# -Disable LFA load-sharing
#
# Expected changes:
# -rt1 should use at most one backup nexthop for each route
#
def test_rib_ipv6_step4():
    logger.info("Test (step 4): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling LFA load-sharing on rt1")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "fast-reroute load-sharing disable"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][4]["show_ipv6_route.ref"]
        )


#
# Step 5
#
# Action(s):
# -Re-enable LFA load-sharing
#
# Expected changes:
# -Revert changes from the previous step
#
def test_rib_ipv6_step5():
    logger.info("Test (step 5): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Re-enabling LFA load-sharing on rt1")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no fast-reroute load-sharing disable"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][5]["show_ipv6_route.ref"]
        )


#
# Step 6
#
# Action(s):
# -Limit backup computation to critical priority prefixes only
#
# Expected changes:
# -rt1 should uninstall all backup nexthops from all routes
#
def test_rib_ipv6_step6():
    logger.info("Test (step 6): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Limiting backup computation to critical priority prefixes only")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "fast-reroute priority-limit critical"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][6]["show_ipv6_route.ref"]
        )


#
# Step 7
#
# Action(s):
# -Configure a prefix priority list to classify rt7's loopback as a
#  critical-priority prefix
#
# Expected changes:
# -rt1 should install backup nexthops for rt7's loopback route.
#
def test_rib_ipv6_step7():
    logger.info("Test (step 7): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring a prefix priority list")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "spf prefix-priority critical CRITICAL_DESTINATIONS"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "ipv6 access-list CRITICAL_DESTINATIONS seq 5 permit 2001:db8:1000::7/128"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][7]["show_ipv6_route.ref"]
        )


#
# Step 8
#
# Action(s):
# -Revert previous changes related to prefix priorities
#
# Expected changes:
# -Revert changes from the previous two steps
#
def test_rib_ipv6_step8():
    logger.info("Test (step 8): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Reverting previous changes related to prefix priorities")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "no ipv6 access-list CRITICAL_DESTINATIONS seq 5 permit 2001:db8:1000::7/128"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no fast-reroute priority-limit critical"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no spf prefix-priority critical CRITICAL_DESTINATIONS"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][8]["show_ipv6_route.ref"]
        )


#
# Step 9
#
# Action(s):
# -Exclude eth-rt6 from LFA computation for eth-rt2's failure
#
# Expected changes:
# -Uninstall the eth-rt2 protecting backup nexthops that go through eth-rt6
#
def test_rib_ipv6_step9():
    logger.info("Test (step 9): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Excluding eth-rt6 from LFA computation for eth-rt2's failure")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2" -c "isis fast-reroute lfa exclude interface eth-rt6"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][9]["show_ipv6_route.ref"]
        )


#
# Step 10
#
# Action(s):
# -Remove exclusion of eth-rt6 from LFA computation for eth-rt2's failure
#
# Expected changes:
# -Revert changes from the previous step
#
def test_rib_ipv6_step10():
    logger.info("Test (step 10): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Removing exclusion of eth-rt6 from LFA computation for eth-rt2's failure"
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2" -c "no isis fast-reroute lfa exclude interface eth-rt6"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][10]["show_ipv6_route.ref"],
        )


#
# Step 11
#
# Action(s):
# -Add LFA tiebreaker: prefer node protecting backup path
#
# Expected changes:
# -rt1 should prefer backup nexthops that provide node protection
#
def test_rib_ipv6_step11():
    logger.info("Test (step 11): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding LFA tiebreaker: prefer node protecting backup path")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "fast-reroute lfa tiebreaker node-protecting index 10"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][11]["show_ipv6_route.ref"],
        )


#
# Step 12
#
# Action(s):
# -Add LFA tiebreaker: prefer backup path via downstream node
#
# Expected changes:
# -rt1 should prefer backup nexthops that satisfy the downstream condition
#
def test_rib_ipv6_step12():
    logger.info("Test (step 12): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding LFA tiebreaker: prefer backup path via downstream node")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "fast-reroute lfa tiebreaker downstream index 20"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][12]["show_ipv6_route.ref"],
        )


#
# Step 13
#
# Action(s):
# -Add LFA tiebreaker: prefer backup path with lowest total metric
#
# Expected changes:
# -rt1 should prefer backup nexthops that have the best metric
#
def test_rib_ipv6_step13():
    logger.info("Test (step 13): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding LFA tiebreaker: prefer backup path with lowest total metric")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "fast-reroute lfa tiebreaker lowest-backup-metric index 30"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][13]["show_ipv6_route.ref"],
        )


#
# Step 14
#
# Action(s):
# - Setting spf-delay-ietf init-delay of 15s
#
# Expected changes:
# - No routing table change
# - At the end of test, SPF reacts to a failure in 15s
#
def test_rib_ipv6_step14():
    logger.info("Test (step 14): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Setting spf-delay-ietf init-delay of 15s")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "spf-delay-ietf init-delay 15000 short-delay 0 long-delay 0 holddown 0 time-to-learn 0"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][14]["show_ipv6_route.ref"],
        )


#
# Step 15
#
# Action(s):
# - shut the eth-rt2 interface on rt1
#
# Expected changes:
# - Route switchover of routes via eth-rt2
#
def test_rib_ipv6_step15():
    logger.info("Test (step 15): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Shut the interface to rt2 from the switch side and check fast-reroute")
    tgen.net.cmd_raises("ip link set %s down" % tgen.net["s1"].intfs[0])

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][15]["show_ipv6_route.ref"],
            count=10,
            wait=0.5,
        )


#
# Step 16
#
# Action(s): wait for the convergence and SPF computation on rt1
#
# Expected changes:
# - convergence of IPv6 RIB
#
def test_rib_ipv6_step16():
    logger.info("Test (step 16): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check SPF convergence")

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][16]["show_ipv6_route.ref"],
        )


#
# Step 17
#
# Action(s):
# - Unshut the interface to rt2 from the switch sid
#
# Expected changes:
# - The routing table converges
#
def test_rib_ipv6_step17():
    logger.info("Test (step 17): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "rt1"

    logger.info("Unsetting spf-delay-ietf init-delay of 15s")
    tgen.net[rname].cmd('vtysh -c "conf t" -c "router isis 1" -c "no spf-delay-ietf"')

    logger.info(
        "Unshut the interface to rt2 from the switch side and check fast-reroute"
    )
    tgen.net.cmd_raises("ip link set %s up" % tgen.net["s1"].intfs[0])

    logger.info("Setting spf-delay-ietf init-delay of 15s")
    tgen.net[rname].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "spf-delay-ietf init-delay 15000 short-delay 0 long-delay 0 holddown 0 time-to-learn 0"'
    )

    router_compare_json_output(
        rname,
        "show ipv6 route isis json",
        outputs[rname][14]["show_ipv6_route.ref"],
    )


#
# Step 18
#
# Action(s):
# - drop traffic between rt1 and rt2 by shutting down the bridge between
#   the routers. Interfaces on rt1 and rt2 stay up.
#
#
# Expected changes:
# - Route switchover of routes via eth-rt2
#
def test_rib_ipv6_step18():
    def _rt2_neigh_down(router):
        output = json.loads(router.vtysh_cmd("show isis neighbor rt2 json"))

        """
        Previous output was:
        {
          "areas":[
            {
              "area":"1",
              "circuits":[
                {
                  "circuit":0,
                  "adj":"rt2",
                  "interface":{
                    "name":"eth-rt2",
                    "state":"Up",
                    "adj-flaps":1,
                    "last-ago":"21s",
                    "circuit-type":"L1",
                    "speaks":"IPv6",
                    "topologies":{
                      "topo-0":"ipv6-unicast"
                    },
                    "snpa":"2020.2020.2020",
                    "area-address":{
                      "isonet":"49.0000"
                    },
                    "ipv6-link-local":{
                      "ipv6":"fe80::ac19:a8ff:fee5:f48f"
                    },
                    "adj-sid":{
                    }
                  },
                  "level":1,
                  "expires-in":"2s"
                },
                {
                  "circuit":0
                },
                {
                  "circuit":0
                },
                {
                  "circuit":0
                },
                {
                  "circuit":0
                },
                {
                  "circuit":0
                }
              ]
            }
          ]
        """

        expected = {
            "areas": [
                {
                    "area": "1",
                    "circuits": [
                        {"circuit": 0},
                        {"circuit": 0},
                        {"circuit": 0},
                        {"circuit": 0},
                        {"circuit": 0},
                        {"circuit": 0},
                    ],
                }
            ]
        }

        return topotest.json_cmp(output, expected, exact=True)

    logger.info("Test (step 18): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Drop traffic between rt1 and rt2")
    tgen.net.cmd_raises("ip link set s1 down")

    rname = "rt1"
    router = tgen.gears[rname]
    test_func = partial(_rt2_neigh_down, router)
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.05)
    assert result is None, 'rt2 neighbor is still present on "{}"'.format(router)

    router_compare_json_output(
        rname,
        "show ipv6 route isis json",
        outputs[rname][15]["show_ipv6_route.ref"],
        count=10,
        wait=0.5,
    )


#
# Step 19
#
# Action(s): wait for the convergence and SPF computation on rt1
#
# Expected changes:
# - convergence of IPv6 RIB
#
def test_rib_ipv6_step19():
    logger.info("Test (step 19): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check SPF convergence")

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][16]["show_ipv6_route.ref"],
        )


#
# Step 20
#
# Action(s):
# - Unshut the switch from rt1 to rt2
#
# Expected changes:
# - The routing table goes back to the nominal state
#
def test_rib_ipv6_step20():
    logger.info("Test (step 20): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "rt1"

    logger.info("Unsetting spf-delay-ietf init-delay of 15s")
    tgen.net[rname].cmd('vtysh -c "conf t" -c "router isis 1" -c "no spf-delay-ietf"')

    logger.info(
        "Unshut the interface to rt2 from the switch side and check fast-reroute"
    )
    tgen.net.cmd_raises("ip link set s1 up")

    logger.info("Setting spf-delay-ietf init-delay of 15s")
    tgen.net[rname].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "spf-delay-ietf init-delay 15000 short-delay 0 long-delay 0 holddown 0 time-to-learn 0"'
    )

    router_compare_json_output(
        rname,
        "show ipv6 route isis json",
        outputs[rname][14]["show_ipv6_route.ref"],
    )


#
# Step 21
#
# Action(s):
# - clear the rt2 ISIS neighbor on rt1
#
# Expected changes:
# - Route switchover of routes via eth-rt2
#
def test_rib_ipv6_step21():
    logger.info("Test (step 21): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "rt1"

    logger.info("Clear the rt2 ISIS neighbor on rt1 and check fast-reroute")
    tgen.gears[rname].vtysh_cmd("clear isis neighbor rt2")

    router_compare_json_output(
        rname,
        "show ipv6 route isis json",
        outputs[rname][15]["show_ipv6_route.ref"],
        count=10,
        wait=0.5,
    )


#
# Step 22
#
# Action(s): wait for the convergence and SPF computation on rt1
#
# Expected changes:
# - convergence of IPv6 RIB
#
def test_rib_ipv6_step22():
    logger.info("Test (step 22): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check SPF convergence")

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][16]["show_ipv6_route.ref"],
        )


#
# Step 23
#
# Action(s):
# - Setting BFD
#
# Expected changes:
# - No routing table change
# - BFD comes up
#
def test_rib_ipv6_step23():
    logger.info("Test (step 23): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Setup BFD on rt1 and rt2")
    for rname in ["rt1", "rt2"]:
        conf_file = os.path.join(CWD, "{}/bfdd.conf".format(rname))
        tgen.net[rname].cmd("vtysh -f {}".format(conf_file))

    logger.info("Set ISIS BFD")
    tgen.net["rt1"].cmd('vtysh -c "conf t" -c "int eth-rt2" -c "isis bfd"')
    tgen.net["rt2"].cmd('vtysh -c "conf t" -c "int eth-rt1" -c "isis bfd"')

    rname = "rt1"
    expect = '[{"multihop":false,"interface":"eth-rt2","status":"up"}]'
    router_compare_json_output(rname, "show bfd peers json", expect)

    router_compare_json_output(
        rname,
        "show ipv6 route isis json",
        outputs[rname][14]["show_ipv6_route.ref"],
    )


#
# Step 24
#
# Action(s):
# - drop traffic between rt1 and rt2 by shutting down the bridge between
#   the routers. Interfaces on rt1 and rt2 stay up.
#
# Expected changes:
# - BFD comes down before IS-IS
# - Route switchover of routes via eth-rt2
#
def test_rib_ipv6_step24():
    def _bfd_down(router):
        output = json.loads(router.vtysh_cmd("show bfd peers json"))
        expected = []
        return topotest.json_cmp(output, expected, exact=True)

    logger.info("Test (step 24): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Shut the interface to rt2 from the switch side and check fast-reroute")
    tgen.net.cmd_raises("ip link set s1 down")

    rname = "rt1"
    router = tgen.gears[rname]
    test_func = partial(_bfd_down, router)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.3)
    assert result is None, 'BFD session is still up on "{}"'.format(router)

    router_compare_json_output(
        rname,
        "show ipv6 route isis json",
        outputs[rname][15]["show_ipv6_route.ref"],
        count=10,
    )


#
# Step 25
#
# Action(s): wait for the convergence and SPF computation on rt1
#
# Expected changes:
# - convergence of IPv6 RIB
#
def test_rib_ipv6_step25():
    logger.info("Test (step 25): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check SPF convergence")

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][16]["show_ipv6_route.ref"],
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
