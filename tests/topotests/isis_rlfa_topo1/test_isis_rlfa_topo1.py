#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_rlfa_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_isis_rlfa_topo1.py:

 +---------+                     +---------+
 |         |                     |         |
 |   RT1   |                     |   RT2   |
 |         +---------------------+         |
 |         |                     |         |
 +---+-----+                     +------+--+
     |                                  |
     |                                  |
     |                                  |
 +---+-----+                     +------+--+
 |         |                     |         |
 |   RT3   |                     |   RT4   |
 |         |                     |         |
 |         |                     |         |
 +---+-----+                     +------+--+
     |                                  |
     |                                  |
     |                                  |
 +---+-----+                     +------+--+
 |         |                     |         |
 |   RT5   |                     |   RT6   |
 |         |                     |         |
 |         |                     |         |
 +---+-----+                     +------+--+
     |                                  |
     |                                  |
     |                                  |
 +---+-----+                     +------+--+
 |         |                     |         |
 |   RT7   |                     |   RT8   |
 |         +---------------------+         |
 |         |                     |         |
 +---------+                     +---------+
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

pytestmark = [pytest.mark.isisd, pytest.mark.ldpd]

# Global multi-dimensional dictionary containing all expected outputs
outputs = {}


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7", "rt8"]:
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
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt7")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt5")
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt8")
    switch.add_link(tgen.gears["rt8"], nodeif="eth-rt6")
    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt8")
    switch.add_link(tgen.gears["rt8"], nodeif="eth-rt7")

    #
    # Populate multi-dimensional dictionary containing all expected outputs
    #
    files = [
        "show_ip_route.ref",
        "show_ipv6_route.ref",
        "show_yang_interface_isis_adjacencies.ref",
    ]
    for rname in ["rt1"]:
        outputs[rname] = {}
        for step in range(1, 10 + 1):
            outputs[rname][step] = {}
            for file in files:
                if step == 1:
                    # Get snapshots relative to the expected initial network convergence
                    filename = "{}/{}/step{}/{}".format(CWD, rname, step, file)
                    outputs[rname][step][file] = open(filename).read()
                else:
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
            TopoRouter.RD_LDP, os.path.join(CWD, "{}/ldpd.conf".format(rname))
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
    expected = json.loads(reference)

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
def test_isis_adjacencies_step1():
    logger.info("Test (step 1): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            outputs[rname][1]["show_yang_interface_isis_adjacencies.ref"],
        )


def test_rib_ipv4_step1():
    logger.info("Test (step 1): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][1]["show_ip_route.ref"]
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][1]["show_ipv6_route.ref"]
        )


#
# Step 2
#
# Action(s):
# -Configure rt8 (rt1's PQ router) to not accept targeted hello messages
#
# Expected changes:
# -All rt1 backup routes should be uninstalled
#
def test_rib_ipv4_step2():
    logger.info("Test (step 2): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring rt8 to not accept targeted hello messages")
    tgen.net["rt8"].cmd(
        'vtysh -c "conf t" -c "mpls ldp" -c "address-family ipv4" -c "no discovery targeted-hello accept"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][2]["show_ip_route.ref"]
        )


def test_rib_ipv6_step2():
    logger.info("Test (step 2): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][2]["show_ipv6_route.ref"]
        )


#
# Step 3
#
# Action(s):
# -Configure rt8 (rt1's PQ router) to accept targeted hello messages
#
# Expected changes:
# -All rt1 previously uninstalled backup routes should be reinstalled
#
def test_rib_ipv4_step3():
    logger.info("Test (step 3): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring rt8 to accept targeted hello messages")
    tgen.net["rt8"].cmd(
        'vtysh -c "conf t" -c "mpls ldp" -c "address-family ipv4" -c "discovery targeted-hello accept"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][3]["show_ip_route.ref"]
        )


def test_rib_ipv6_step3():
    logger.info("Test (step 3): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][3]["show_ipv6_route.ref"]
        )


#
# Step 4
#
# Action(s):
# -Disable RLFA on rt1's eth-rt2 interface
#
# Expected changes:
# -All non-ECMP routes whose primary nexthop is eth-rt2 should lose their backup nexthops
#
def test_rib_ipv4_step4():
    logger.info("Test (step 4): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling RLFA on rt1's eth-rt2 interface")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2" -c "no isis fast-reroute remote-lfa tunnel mpls-ldp"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][4]["show_ip_route.ref"]
        )


def test_rib_ipv6_step4():
    logger.info("Test (step 4): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][4]["show_ipv6_route.ref"]
        )


#
# Step 5
#
# Action(s):
# -Disable RLFA on rt1's eth-rt3 interface
#
# Expected changes:
# -All non-ECMP routes whose primary nexthop is eth-rt3 should lose their backup nexthops
#
def test_rib_ipv4_step5():
    logger.info("Test (step 5): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling RLFA on rt1's eth-rt3 interface")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt3" -c "no isis fast-reroute remote-lfa tunnel mpls-ldp"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][5]["show_ip_route.ref"]
        )


def test_rib_ipv6_step5():
    logger.info("Test (step 5): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][5]["show_ipv6_route.ref"]
        )


#
# Step 6
#
# Action(s):
# -Re-enable RLFA on rt1's eth-rt2 and eth-rt3 interfaces
#
# Expected changes:
# -Revert changes from the previous two steps (reinstall all backup routes)
#
def test_rib_ipv4_step6():
    logger.info("Test (step 6): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Re-enabling RLFA on rt1's eth-rt2 and eth-rt3 interfaces")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2" -c "isis fast-reroute remote-lfa tunnel mpls-ldp"'
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt3" -c "isis fast-reroute remote-lfa tunnel mpls-ldp"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][6]["show_ip_route.ref"]
        )


def test_rib_ipv6_step6():
    logger.info("Test (step 6): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][6]["show_ipv6_route.ref"]
        )


#
# Step 7
#
# Action(s):
# -Configure a PQ node prefix-list filter
#
# Expected changes:
# -All backup routes should be uninstalled
#
def test_rib_ipv4_step7():
    logger.info("Test (step 7): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring a PQ node prefix-list filter")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "fast-reroute remote-lfa prefix-list PLIST"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][7]["show_ip_route.ref"]
        )


def test_rib_ipv6_step7():
    logger.info("Test (step 7): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][7]["show_ipv6_route.ref"]
        )


#
# Step 8
#
# Action(s):
# -Configure a prefix-list allowing rt8 as a PQ node
#
# Expected changes:
# -All backup routes should be installed again
#
def test_rib_ipv4_step8():
    logger.info("Test (step 8): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring a prefix-list allowing rt8 as a PQ node")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "ip prefix-list PLIST seq 5 permit 10.0.255.8/32"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][8]["show_ip_route.ref"]
        )


def test_rib_ipv6_step8():
    logger.info("Test (step 8): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][8]["show_ipv6_route.ref"]
        )


#
# Step 9
#
# Action(s):
# -Change the maximum metric up to the PQ node to 30 on the eth-rt2 interface
#
# Expected changes:
# -All non-ECMP routes whose primary nexthop is eth-rt2 should lose their backup nexthops
#
def test_rib_ipv4_step9():
    logger.info("Test (step 9): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Changing the maximum metric up to the PQ node to 30 on the eth-rt2 interface"
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2" -c "isis fast-reroute remote-lfa maximum-metric 30"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][9]["show_ip_route.ref"]
        )


def test_rib_ipv6_step9():
    logger.info("Test (step 9): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", outputs[rname][9]["show_ipv6_route.ref"]
        )


#
# Step 10
#
# Action(s):
# -Change the maximum metric up to the PQ node to 40 on the eth-rt2 interface
#
# Expected changes:
# -All non-ECMP routes whose primary nexthop is eth-rt2 should recover their backup nexthops
#
def test_rib_ipv4_step10():
    logger.info("Test (step 10): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Changing the maximum metric up to the PQ node to 40 on the eth-rt2 interface"
    )
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "interface eth-rt2" -c "isis fast-reroute remote-lfa maximum-metric 40"'
    )

    for rname in ["rt1"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][10]["show_ip_route.ref"]
        )


def test_rib_ipv6_step10():
    logger.info("Test (step 10): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][10]["show_ipv6_route.ref"],
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
