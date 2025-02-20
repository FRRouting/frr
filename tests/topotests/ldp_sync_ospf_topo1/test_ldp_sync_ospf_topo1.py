#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ldp_ospf_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_ldp_vpls_topo1.py:

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

pytestmark = [pytest.mark.ldpd, pytest.mark.ospfd]


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
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        # Don't start ospfd and ldpd in the CE nodes
        if router.name[0] == "r":
            router.load_config(
                TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
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
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=320, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def test_ospf_convergence():
    logger.info("Test: check OSPF adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show ip ospf neighbor json", "show_ip_ospf_neighbor.json"
        )


def test_rib():
    logger.info("Test: verify RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(rname, "show ip route json", "show_ip_route.ref")


def test_ldp_adjacencies():
    logger.info("Test: verify LDP adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp discovery json", "show_ldp_discovery.ref"
        )


def test_ldp_neighbors():
    logger.info("Test: verify LDP neighbors")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp neighbor json", "show_ldp_neighbor.ref"
        )


def test_ldp_bindings():
    logger.info("Test: verify LDP bindings")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp binding json", "show_ldp_binding.ref"
        )


def test_ldp_pwid_bindings():
    logger.info("Test: verify LDP PW-ID bindings")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show l2vpn atom binding json", "show_l2vpn_binding.ref"
        )


def test_ldp_pseudowires():
    logger.info("Test: verify LDP pseudowires")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show l2vpn atom vc json", "show_l2vpn_vc.ref"
        )


def test_ldp_igp_sync():
    logger.info("Test: verify LDP igp-sync")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp igp-sync json", "show_ldp_igp_sync.ref"
        )


def test_ospf_ldp_sync():
    logger.info("Test: verify OSPF igp-sync")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show ip ospf mpls ldp-sync json", "show_ospf_ldp_sync.ref"
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show ip ospf interface json", "show_ip_ospf_interface.ref"
        )


def test_r1_eth1_shutdown():
    logger.info("Test: verify behaviour after r1-eth1 is shutdown")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Shut down r1-r2 link */
    tgen = get_topogen()
    tgen.gears["r1"].peer_link_enable("r1-eth1", False)
    topotest.sleep(5, "Waiting for the network to reconverge")

    # check if the pseudowire is still up (using an alternate path for nexthop resolution)
    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show l2vpn atom vc json", "show_l2vpn_vc.ref"
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show mpls ldp igp-sync json",
            "show_ldp_igp_sync_r1_eth1_shutdown.ref",
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show ip ospf mpls ldp-sync json",
            "show_ospf_ldp_sync_r1_eth1_shutdown.ref",
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show ip ospf interface json",
            "show_ip_ospf_interface_r1_eth1_shutdown.ref",
        )


def test_r1_eth1_no_shutdown():
    logger.info("Test: verify behaviour after r1-eth1 is no shutdown")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Run no shutdown on r1-eth1 interface */
    tgen = get_topogen()
    tgen.gears["r1"].peer_link_enable("r1-eth1", True)
    topotest.sleep(5, "Waiting for the network to reconverge")

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp igp-sync json", "show_ldp_igp_sync.ref"
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show ip ospf mpls ldp-sync json", "show_ospf_ldp_sync.ref"
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show ip ospf interface json", "show_ip_ospf_interface.ref"
        )


def test_r2_eth1_shutdown():
    logger.info("Test: verify behaviour after r2-eth1 is shutdown")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Shut down r1-r2 link */
    tgen = get_topogen()
    tgen.gears["r2"].peer_link_enable("r2-eth1", False)
    topotest.sleep(5, "Waiting for the network to reconverge")

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show mpls ldp igp-sync json",
            "show_ldp_igp_sync_r1_eth1_shutdown.ref",
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show ip ospf mpls ldp-sync json",
            "show_ospf_ldp_sync_r2_eth1_shutdown.ref",
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show ip ospf interface json",
            "show_ip_ospf_interface_r2_eth1_shutdown.ref",
        )


def test_r2_eth1_no_shutdown():
    logger.info("Test: verify behaviour after r2-eth1 is no shutdown")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Run no shutdown on r2-eth1 interface */
    tgen = get_topogen()
    tgen.gears["r2"].peer_link_enable("r2-eth1", True)
    topotest.sleep(5, "Waiting for the network to reconverge")

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp igp-sync json", "show_ldp_igp_sync.ref"
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show ip ospf mpls ldp-sync json", "show_ospf_ldp_sync.ref"
        )

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show ip ospf interface json", "show_ip_ospf_interface.ref"
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
