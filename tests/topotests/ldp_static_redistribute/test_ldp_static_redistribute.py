#!/usr/bin/env python

#
# Copyright 2026 6WIND S.A.
#

"""
test_ldp_static_redistribute.py:

                   +---------+                +---------+
                   |         |                |         |
                   |   CE1   |                |   CE2   |
                   |         |                |         |
                   +---------+                +---------+
ce1-eth0 (172.16.1.1/24)|                          |ce2-eth0 (172.16.1.2/24)
                        |                          |
                        |                          |
                rt1-eth0|                          |rt2-eth0
                   +---------+  10.0.1.0/24   +---------+
                   |         |rt1-eth1        |         |
                   |   RT1   +----------------+   RT2   |
                   | 1.1.1.1 |        rt2-eth1| 2.2.2.2 |
                   |         |                |         |
                   +---------+                +---------+
                rt1-eth2|                          |rt2-eth2
                        |                          |
                        |                          |
             10.0.2.0/24|        +---------+       |10.0.3.0/24
                        |        |         |       |
                        |        |   RT3   |       |
                        +--------+ 3.3.3.3 +-------+
                         rt3-eth2|         |rt3-eth1
                                 +---------+
                                      |rt3-eth0
                                      |
                                      |
              ce3-eth0 (172.16.1.3/24)|
                                 +---------+
                                 |         |
                                 |   CE3   |
                                 |         |
                                 +---------+
"""

import os
import re
import sys
import pytest
import json
from time import sleep
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


def build_topo(tgen):
    "Build function"

        
    #
    # Define FRR Routers
    #
    for router in ["ce1", "ce2", "ce3", "r1", "r2", "r3"]:
        tgen.add_router(router)
        
    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["ce1"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["ce2"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["ce3"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname))
        )

            
    tgen.start_router()


def teardown_module(mod):
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

    # Run test function until we get an result.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def test_isis_convergence():
    logger.info("Test: check ISIS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show isis route json",
            "show_isis_route.ref",
        )

def test_ldp_bindings():
    logger.info("Test: verify LDP bindings")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp binding json", "show_ldp_binding_1.ref"
        )

def test_ospf():
    logger.info("Test: verify OSPF routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r2", "ce2"]:
        router_compare_json_output(
            rname, "show ip ospf route json", "show_ospf_route.ref"
        )

def test_ospf_redistribute():
    logger.info("Test: setting redistribute ospf")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)  

    #add redistribute ospf on r2
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\nrouter isis 1\nredistribute ipv4 ospf level-1\n")   

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show mpls ldp binding json", "show_ldp_binding_2.ref"
        )

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show ip route 12.12.12.12 json", "show_ip_route_ce2_1.ref"
        )


def test_remove_r1_r2_link():
    logger.info("Test: route change when r1/r2 link is down")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)  
       
    r1 = tgen.gears["r1"]
    tgen.net["r1"].cmd("ip link set dev r1-eth1 down")   

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show mpls ldp binding json", "show_ldp_binding_3.ref"
        )

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show ip route 12.12.12.12 json", "show_ip_route_ce2_2.ref"
        )

    
def test_static_redistribute():
    logger.info("Test: verify redistribute static effect")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
        
    #add redistribute ospf on r2
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\nrouter isis 1\nno redistribute ipv4 ospf level-1\n")
    r2.vtysh_cmd("conf t\nrouter isis 1\nredistribute ipv4 static level-1\n")

    #add static route to ce2 loopback
    r2.vtysh_cmd("conf t\nip route 12.12.12.12/32 172.16.1.2\n")

    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show mpls ldp binding json", "show_ldp_binding_4.ref"
        )
    
    for rname in ["r1", "r2"]:
        router_compare_json_output(
            rname, "show ip route 12.12.12.12 json", "show_ip_route_ce2_3.ref"
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









