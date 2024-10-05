#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_te_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by Orange
# Author: Olivier Dugeon <olivier.dugeon@orange.com>
#

"""
test_ospf_te_topo1.py: Test the FRR OSPF with Traffic Engineering.

         +------------+
         |            |
         |     R1     |
         | 10.0.225.1 |
         |            |
         +------------+
         eth0|    |eth1
             |    |
  10.0.0.0/24|    |10.0.1.0/24
             |    |
         eth0|    |eth1
         +------------+                  +------------+
         |            |                  |            |
         |     R2     |eth2          eth0|     R3     |
         | 10.0.255.2 +------------------+ 10.0.255.3 |
         |            |     10.0.3.0/24  |            |
         +------------+                  +------+-----+
            eth3|                           eth1|
                |                               |
     10.0.4.0/24|                    10.0.5.0/24|
                |                               |
            eth0|                               V
         +------------+                   ASBR 10.0.255.5
         |            |
         |     R4     |
         | 10.0.255.4 |
         |            |
         +------------+

"""

import os
import sys
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Required to instantiate the topology builder class.

# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# and Finally pytest
import pytest

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")
    r4 = tgen.add_router("r4")

    # Interconect router 1 and 2 with 2 links
    tgen.add_link(r1, r2, ifname1="eth0", ifname2="eth0")
    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")

    # Interconect router 3 and 2
    tgen.add_link(r2, r3, ifname1="eth2", ifname2="eth0")

    # Interconect router 4 and 2
    tgen.add_link(r2, r4, ifname1="eth3", ifname2="eth0")

    # Interconnect router 3 with next AS
    s1 = tgen.add_switch("s1")
    tgen.add_link(r3, s1, ifname1="eth1", ifname2="eth0")


def setup_module(mod):
    "Sets up the pytest environment"

    logger.info("\n\n---- Starting OSPF TE tests ----\n")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()

    logger.info("\n\n---- OSPF TE tests End ----\n")


def compare_ted_json_output(tgen, rname, fileref):
    "Compare TED JSON output"

    logger.info('Comparing router "%s" TED output', rname)

    filename = "{}/reference/{}".format(CWD, fileref)
    expected = json.loads(open(filename).read())
    command = "show ip ospf mpls-te database json"

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = '"{}" TED JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def setup_testcase(msg):
    "Setup test case"

    logger.info(msg)
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    return tgen


# Note that all routers must discover the same Network Topology, so the same TED.


def test_step1():
    "Step1: Check initial topology"

    tgen = setup_testcase("Step1: test initial OSPF TE Data Base")

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step1.json")


def test_step2():
    "Step2: Shutdown interface between r1 and r2 and verify that \
    corresponding Edges are removed from the TED on all routers "

    tgen = setup_testcase("Step2: Shutdown interface between r1 & r2")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "interface eth1" -c "shutdown"')

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step2.json")


def test_step3():
    "Step3: Disable Inter-AS on r3 and verify that corresponding Edge and \
    remote ASBR are removed from the TED on all routers"

    tgen = setup_testcase("Step3: Disable Inter-AS on r3")

    tgen.net["r3"].cmd('vtysh -c "conf t" -c "router ospf" -c "no mpls-te inter-as"')
    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step3.json")


def test_step4():
    "Step4: Enable Segment Routing on r1 and r2 and verify that corresponding \
    Edges are updated with Adjacency SID and Subnets with Prefix SID in the \
    TED on all routers"

    tgen = setup_testcase("Step4: Enable Segment Routing on r1 & r2")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "router ospf" -c "segment-routing on"')
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing global-block 20000 23999"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing prefix 10.0.255.1/32 index 10"'
    )
    tgen.net["r2"].cmd('vtysh -c "conf t" -c "router ospf" -c "segment-routing on"')
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing node-msd 16"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing global-block 16000 23999 local-block 5000 6999"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router ospf" -c "segment-routing prefix 10.0.255.2/32 index 20 explicit-null"'
    )

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step4.json")


def test_step5():
    "Step5: Re-enable interface between r1 & r2 and verify that corresponding \
    Edges are added in the TED on all routers"

    tgen = setup_testcase("Step5: Re-enable interface between r1 & r2")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "interface eth1" -c "no shutdown"')

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step5.json")


def test_step6():
    "Step6: Set delay and jitter for interface eth0 on r4, remove use-bw \
    for interface eth3 on r2 and verify that corresponding Edges are \
    updated in the TED on all routers"

    tgen = setup_testcase("Step6: Modify link parameters on r2 & r4")

    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "interface eth3" -c "link-params" -c "no use-bw"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "interface eth0" -c "link-params" -c "delay 20000"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "interface eth0" -c "link-params" -c "delay-variation 10000"'
    )

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step6.json")


def test_step7():
    "Step7: Disable OSPF on r4 and verify that corresponding Vertex, Edges and \
    Subnets are removed from the TED on all remaining routers"

    tgen = setup_testcase("Step7: Disable OSPF on r4")

    tgen.net["r4"].cmd('vtysh -c "conf t" -c "no router ospf"')

    for rname in ["r1", "r2", "r3"]:
        compare_ted_json_output(tgen, rname, "ted_step7.json")


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
