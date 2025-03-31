#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_acl.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_acl.py: Test PIM with RP selection using ACLs
"""

# Test PIM RP selection with ACLs
#
# Testing RP selection with ACLs. R1 uses multiple ACLs
# to select desired RPs (R11 to R15)
#
# Test steps:
# - setup_module()
#     Create topology. Hosts are only using zebra/staticd,
#     no PIM, no OSPF (using IGMPv2 for multicast)
# - test_ospf_convergence()
#     Wait for OSPF convergence in each VRF. OSPF is run on
#     R1 and R11 - R15.
# - test_pim_convergence()
#     Wait for PIM convergence on all routers. PIM is run on
#     R1 and R11 - R15.
# - test_mcast_acl_1():
#     Test 1st ACL entry 239.100.0.0/28 with 239.100.0.1 which
#     should use R11 as RP
#     Stop multicast after verification
# - test_mcast_acl_2():
#     Test 2nd ACL entry 239.100.0.17/32 with 239.100.0.17 which
#     should use R12 as RP
#     Stop multicast after verification
# - test_mcast_acl_3():
#     Test 3rd ACL entry 239.100.0.32/27 with 239.100.0.32 which
#     should use R13 as RP
#     Stop multicast after verification
# - test_mcast_acl_4():
#     Test 4th ACL entry 239.100.0.128/25 with 239.100.0.255 which
#     should use R14 as RP
#     Stop multicast after verification
# - test_mcast_acl_5():
#     Test 5th ACL entry 239.100.0.96/28 with 239.100.0.97 which
#     should use R14 as RP
#     Stop multicast after verification
# - test_mcast_acl_6():
#     Test 6th ACL entry 239.100.0.64/28 with 239.100.0.70 which
#     should use R15 as RP
#     Stop multicast after verification
# - teardown_module()
#     shutdown topology
#

# XXX clean up in later commit to avoid conflict on rebase
# pylint: disable=C0413
TOPOLOGY = """
                                             +----------+
                                             |  Host H2 |
                                             |  Source  |
                                             +----------+
                                                .2 |
                             +-----------+         |        +----------+
                             |           | .1      |    .11 | Host R11 |
+---------+                  |    R1     |---------+--------| PIM RP   |
| Host H1 | 192.168.100.0/24 |           | 192.168.101.0/24 +----------+
| receive |------------------| uses ACLs |         |        +----------+
|IGMP JOIN| .10           .1 |  to pick  |         |    .12 | Host R12 |
+---------+                  |    RP     |         +--------| PIM RP   |
                             |           |         |        +----------+
                             +-----------+         |        +----------+
                                                   |    .13 | Host R13 |
                                                   +--------| PIM RP   |
                                                   |        +----------+
                                                   |        +----------+
                                                   |    .14 | Host R14 |
                                                   +--------| PIM RP   |
                                                   |        +----------+
                                                   |        +----------+
                                                   |    .15 | Host R15 |
                                                   +--------| PIM RP   |
                                                            +----------+
"""

import json
import functools
import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.pimd, pytest.mark.ospfd]


def build_topo(tgen):
    for hostNum in range(1, 3):
        tgen.add_router("h{}".format(hostNum))

    # Create the main router
    tgen.add_router("r1")

    # Create the PIM RP routers
    for rtrNum in range(11, 16):
        tgen.add_router("r{}".format(rtrNum))

    # Setup Switches and connections
    for swNum in range(1, 3):
        tgen.add_switch("sw{}".format(swNum))

    # Add connections H1 to R1 switch sw1
    tgen.gears["h1"].add_link(tgen.gears["sw1"])
    tgen.gears["r1"].add_link(tgen.gears["sw1"])

    # Add connections R1 to R1x switch sw2
    tgen.gears["r1"].add_link(tgen.gears["sw2"])
    tgen.gears["h2"].add_link(tgen.gears["sw2"])
    tgen.gears["r11"].add_link(tgen.gears["sw2"])
    tgen.gears["r12"].add_link(tgen.gears["sw2"])
    tgen.gears["r13"].add_link(tgen.gears["sw2"])
    tgen.gears["r14"].add_link(tgen.gears["sw2"])
    tgen.gears["r15"].add_link(tgen.gears["sw2"])


#####################################################
#
#   Tests starting
#
#####################################################


def setup_module(module):
    logger.info("PIM RP ACL Topology: \n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if rname[0] != "h":
            # Only load ospf on routers, not on end hosts
            router.load_config(
                TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
            )
            router.load_config(
                TopoRouter.RD_PIM, os.path.join(CWD, "{}/pimd.conf".format(rname))
            )
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_convergence():
    "Test for OSPFv2 convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking OSPFv2 convergence on router r1")

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/ospf_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip ospf neighbor json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "OSPF router R1 did not converge"
    assert res is None, assertmsg


def test_pim_convergence():
    "Test for PIM convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking PIM convergence on router r1")

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/pim_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip pim neighbor json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "PIM router R1 did not converge"
    assert res is None, assertmsg


def check_mcast_entry(entry, mcastaddr, pimrp):
    "Helper function to check RP"
    tgen = get_topogen()

    logger.info(
        "Testing PIM RP selection for ACL {} entry using {}".format(entry, mcastaddr)
    )

    with McastTesterHelper(tgen) as helper:
        helper.run("h2", ["--send=0.7", mcastaddr, "h2-eth0"])
        helper.run("h1", [mcastaddr, "h1-eth0"])

        logger.info("mcast join and source for {} started".format(mcastaddr))

        # tgen.mininet_cli()

        router = tgen.gears["r1"]
        reffile = os.path.join(CWD, "r1/acl_{}_pim_join.json".format(entry))
        expected = json.loads(open(reffile).read())

        logger.info("verifying pim join on r1 for {}".format(mcastaddr))
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip pim join json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "PIM router r1 did not show join status"
        assert res is None, assertmsg

        logger.info("verifying pim join on PIM RP {} for {}".format(pimrp, mcastaddr))
        router = tgen.gears[pimrp]
        reffile = os.path.join(CWD, "{}/acl_{}_pim_join.json".format(pimrp, entry))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip pim join json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "PIM router {} did not get selected as the PIM RP".format(pimrp)
        assert res is None, assertmsg

    return


def test_mcast_acl_1():
    "Test 1st ACL entry 239.100.0.0/28 with 239.100.0.1"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(1, "239.100.0.1", "r11")


def test_mcast_acl_2():
    "Test 2nd ACL entry 239.100.0.17/32 with 239.100.0.17"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(2, "239.100.0.17", "r12")


def test_mcast_acl_3():
    "Test 3rd ACL entry 239.100.0.32/27 with 239.100.0.32"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(3, "239.100.0.32", "r13")


def test_mcast_acl_4():
    "Test 4th ACL entry 239.100.0.128/25 with 239.100.0.255"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(4, "239.100.0.255", "r14")


def test_mcast_acl_5():
    "Test 5th ACL entry 239.100.0.96/28 with 239.100.0.97"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(5, "239.100.0.97", "r14")


def test_mcast_acl_6():
    "Test 6th ACL entry 239.100.0.64/28 with 239.100.0.70"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(6, "239.100.0.70", "r15")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
