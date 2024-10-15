#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_te_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by Orange
# Author: Olivier Dugeon <olivier.dugeon@orange.com>
#

"""
test_isis_te_topo1.py: Test the FRR IS-IS with Traffic Engineering.

           +------------+
           |            |
           |     R1     |
           | 10.0.225.1 |
           |            |
           +------------+
        r1-eth0|    |r1-eth1
               |    |
    10.0.0.0/24|    |10.0.1.0/24
               |    |2001:db8:1:/64
               |    |
        r2-eth0|    |r2-eth1
           +------------+                  +------------+
           |            |                  |            |
           |     R2     |r2-eth2    r3-eth0|     R3     |
           | 10.0.255.2 +------------------+ 10.0.255.3 |
           |            |     10.0.3.0/24  |            |
           +------------+  2001:db8:3:/64  +------+-----+
           r2-eth3|                        r3-eth1|
                  |                               |
       10.0.4.0/24|                               |
                  |                               |
                  |                               |
           r4-eth0|                 2001:db8:5:/64|
           +------------+                         |
           |            |                         |
           |     R4     |r4-eth1                  |
           | 10.0.255.4 +-------------------------+
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

# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# and Finally pytest
import pytest

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    # Interconect router 1 and 2 with 2 links
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 3 and 2
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 4 and 2
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r2"])

    # Interconnect router 3 and 4
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    "Sets up the pytest environment"

    logger.info("\n\n---- Starting IS-IS TE tests ----\n")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()

    logger.info("\n\n---- IS-IS TE tests End ----\n")


def compare_ted_json_output(tgen, rname, fileref):
    "Compare TED JSON output"

    logger.info('Comparing router "%s" TED output', rname)

    filename = "{}/reference/{}".format(CWD, fileref)
    expected = json.loads(open(filename).read())
    command = "show isis mpls-te database json"

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

    tgen = setup_testcase("Step1: test initial IS-IS TE Data Base")

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step1.json")


def test_step2():
    "Step2: Shutdown interface between r1 and r2 and verify that \
    corresponding Edges are removed from the TED on all routers "

    tgen = setup_testcase("Step2: Shutdown interface between r1 & r2")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "interface r1-eth1" -c "shutdown"')
    tgen.net["r2"].cmd('vtysh -c "conf t" -c "interface r2-eth1" -c "shutdown"')

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step2.json")


def test_step3():
    "Step3: Enable IPv6 address between r1 and r2 and verify that \
    corresponding Edges are added in the TED on all routers"

    tgen = setup_testcase("Step3: Add IPv6 on r1 and r2 interfaces")

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "interface r1-eth0" -c "ipv6 address 2001:db8:0::1/64"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "interface r1-eth0" -c "ipv6 router isis TE"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "interface r2-eth0" -c "ipv6 address 2001:db8:0::2/64"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "interface r2-eth0" -c "ipv6 router isis TE"'
    )
    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step3.json")


def test_step4():
    "Step4: Modify Segment Routing Prefix SID advertisement on Router r4"

    tgen = setup_testcase("Step4: Modify Prefix SID on router r4")

    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "router isis TE" -c "segment-routing prefix 10.0.255.4/32 index 40"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "router isis TE" -c "segment-routing prefix 2001:db8:ffff::4/128 index 1040"'
    )

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step4.json")


def test_step5():
    "Step5: Re-enable interface between r1 & r2 and verify that corresponding \
    Edges are added in the TED on all routers"

    tgen = setup_testcase("Step5: Re-enable interface between r1 & r2")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "interface r1-eth1" -c "no shutdown"')
    tgen.net["r2"].cmd('vtysh -c "conf t" -c "interface r2-eth1" -c "no shutdown"')

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step5.json")


def test_step6():
    "Step6: Set delay and jitter for interface r4-eth0 on r4, remove use-bw \
    for interface r2-eth3 on r2 and verify that corresponding Edges are \
    updated in the TED on all routers"

    tgen = setup_testcase("Step6: Modify link parameters on r2 & r4")

    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "interface r2-eth3" -c "link-params" -c "no use-bw"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "interface r4-eth0" -c "link-params" -c "delay 20000"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "interface r4-eth0" -c "link-params" -c "delay-variation 10000"'
    )

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step6.json")


def test_step7():
    "Step7: Set extended admin-group on r1-eth0"

    tgen = setup_testcase("Step7: Modify link parameters on r1")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "affinity-map WHITE bit-position 0"')
    tgen.net["r1"].cmd('vtysh -c "conf t" -c "affinity-map RED bit-position 31"')
    tgen.net["r1"].cmd('vtysh -c "conf t" -c "affinity-map GREEN bit-position 32"')
    tgen.net["r1"].cmd('vtysh -c "conf t" -c "affinity-map BLACK bit-position 128"')

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "interface r1-eth0" -c "link-params" -c "affinity RED WHITE BLACK GREEN"'
    )

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step7.json")


def test_step8():
    "Step8: Change value of affinity-map GREEN"

    tgen = setup_testcase("Step8: Change value of affinity-map GREEN")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "affinity-map GREEN bit-position 33"')

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step8.json")


def test_step9():
    "Step9: Trying to remove affinity-map GREEN. \
    Must not succeed because in use"

    tgen = setup_testcase("Step9: Trying to remove affinity-map GREEN")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "no affinity-map GREEN"')

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step9.json")


def test_step10():
    "Step10: Removing r1-eth0 affinity GREEN"

    tgen = setup_testcase("Step10: Removing r1-eth0 affinity GREEN")

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "interface r1-eth0" -c "link-params" -c "no affinity GREEN"'
    )

    for rname in ["r1", "r2", "r3", "r4"]:
        compare_ted_json_output(tgen, rname, "ted_step10.json")


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
