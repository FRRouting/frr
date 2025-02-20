#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_vrf.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_vrf.py: Test PIM with VRFs.
"""

# XXX clean up in later commit to avoid conflict on rebase
# pylint: disable=C0413

# Tests PIM with VRF
#
# R1 is split into 2 VRF: Blue and Red, the others are normal
# routers and Hosts
# There are 2 similar topologies with overlapping IPs in each
# section.
#
# Test steps:
# - setup_module()
#     Create topology. Hosts are only using zebra/staticd,
#     no PIM, no OSPF (using IGMPv2 for multicast)
# - test_ospf_convergence()
#     Wait for OSPF convergence in each VRF. OSPF is run on
#     R1, R11 and R12.
# - test_pim_convergence()
#     Wait for PIM convergence in each VRF. PIM is run on
#     R1, R11 and R12. R11 is the RP for vrf blue, R12 is RP
#     for vrf red.
# - test_vrf_pimreg_interfaces()
#     Adding PIM RP in VRF information and verify pimreg
#     interfaces in VRF blue and red
# - test_mcast_vrf_blue()
#     Start multicast stream for group 239.100.0.1 from Host
#     H2 and join from Host H1 on vrf blue
#     Verify PIM JOIN status on R1 and R11
#     Stop multicast after verification
# - test_mcast_vrf_red()
#     Start multicast stream for group 239.100.0.1 from Host
#     H4 and join from Host H3 on vrf blue
#     Verify PIM JOIN status on R1 and R12
#     Stop multicast after verification
# - teardown_module(module)
#     shutdown topology
#

TOPOLOGY = """
                                               +----------+
                                               |  Host H2 |
                                               |  Source  |
                                               +----------+
                                                 .2 |
+---------+                  +------------+         |        +---------+
| Host H1 | 192.168.100.0/24 |            | .1      |    .11 | Host H2 |
| receive |------------------|  VRF Blue  |---------+--------| PIM RP  |
|IGMP JOIN| .10           .1 |            | 192.168.101.0/24 |         |
+---------+                  |            |                  +---------+
                            =| = = R1 = = |=
+---------+                  |            |                  +---------+
| Host H3 | 192.168.100.0/24 |            | 192.168.101.0/24 | Host H4 |
| receive |------------------|  VRF Red   |---------+--------| PIM RP  |
|IGMP JOIN| .20           .1 |            | .1      |    .12 |         |
+---------+                  +------------+         |        +---------+
                                                 .4 |
                                               +----------+
                                               |  Host H4 |
                                               |  Source  |
                                               +----------+
"""

import json
import functools
import os
import sys
import pytest
import logging

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.topotest import iproute2_is_vrf_capable
from lib.common_config import required_linux_kernel_version
from lib.pim import McastTesterHelper


pytestmark = [pytest.mark.ospfd, pytest.mark.pimd]


def build_topo(tgen):
    for hostNum in range(1, 5):
        tgen.add_router("h{}".format(hostNum))

    # Create the main router
    tgen.add_router("r1")

    # Create the PIM RP routers
    for rtrNum in range(11, 13):
        tgen.add_router("r{}".format(rtrNum))

    # Setup Switches and connections
    for swNum in range(1, 5):
        tgen.add_switch("sw{}".format(swNum))

    ################
    # 1st set of connections to routers for VRF red
    ################

    # Add connections H1 to R1 switch sw1
    tgen.gears["h1"].add_link(tgen.gears["sw1"])
    tgen.gears["r1"].add_link(tgen.gears["sw1"])

    # Add connections R1 to R1x switch sw2
    tgen.gears["r1"].add_link(tgen.gears["sw2"])
    tgen.gears["h2"].add_link(tgen.gears["sw2"])
    tgen.gears["r11"].add_link(tgen.gears["sw2"])

    ################
    # 2nd set of connections to routers for vrf blue
    ################

    # Add connections H1 to R1 switch sw1
    tgen.gears["h3"].add_link(tgen.gears["sw3"])
    tgen.gears["r1"].add_link(tgen.gears["sw3"])

    # Add connections R1 to R1x switch sw2
    tgen.gears["r1"].add_link(tgen.gears["sw4"])
    tgen.gears["h4"].add_link(tgen.gears["sw4"])
    tgen.gears["r12"].add_link(tgen.gears["sw4"])


#####################################################
#
#   Tests starting
#
#####################################################


def setup_module(module):
    logger.info("PIM IGMP VRF Topology: \n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    vrf_setup_cmds = [
        "ip link add name blue type vrf table 11",
        "ip link add name red type vrf table 12",
        "ip link set dev blue up",
        "ip link set dev red up",
        "ip link set dev r1-eth0 vrf blue up",
        "ip link set dev r1-eth1 vrf blue up",
        "ip link set dev r1-eth2 vrf red up",
        "ip link set dev r1-eth3 vrf red up",
    ]

    # Starting Routers
    router_list = tgen.routers()

    # Create VRF on r2 first and add it's interfaces
    for cmd in vrf_setup_cmds:
        tgen.net["r1"].cmd(cmd)

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

    # iproute2 needs to support VRFs for this suite to run.
    if not iproute2_is_vrf_capable():
        pytest.skip(
            "Installed iproute2 version does not support VRFs", allow_module_level=True
        )

    if os.getenv("MROUTE_VRF_MISSING"):
        pytest.skip(
            "Kernel does not support vrf mroute tables.", allow_module_level=True
        )


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_convergence():
    "Test for OSPFv2 convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking OSPFv2 convergence on router r1 for VRF blue")

    # Check for blue neighbor
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/ospf_blue_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip ospf vrf blue neighbor json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "OSPF router R1 did not converge on VRF blue (nbr)"
    assert res is None, assertmsg

    # Check for blue loopback route
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/ospf_blue_route.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip ospf vrf blue route json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
    assertmsg = "OSPF router R1 did not converge on VRF blue (route)"
    assert res is None, assertmsg

    logger.info("Checking OSPFv2 convergence on router r1 for VRF red")

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/ospf_red_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip ospf vrf red neighbor json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "OSPF router R1 did not converge on VRF red (nbr)"
    assert res is None, assertmsg

    # Check for red loopback route
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/ospf_red_route.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip ospf vrf red route json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
    assertmsg = "OSPF router R1 did not converge on VRF red (route)"
    assert res is None, assertmsg


def test_pim_convergence():
    "Test for PIM convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking PIM convergence on router r1 for VRF red")

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/pim_red_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip pim vrf red neighbor json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
    assertmsg = "PIM router R1 did not converge for VRF red"
    assert res is None, assertmsg

    logger.info("Checking PIM convergence on router r1 for VRF blue")

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/pim_blue_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip pim vrf blue neighbor json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
    assertmsg = "PIM router R1 did not converge for VRF blue"
    assert res is None, assertmsg


def _test_vrf_pimreg_interfaces():
    "Adding PIM RP in VRF information and verify pimreg interfaces"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf\ninterface blue\nip pim")
    r1.vtysh_cmd("conf\nvrf blue\nip pim rp 192.168.0.11 239.100.0.1/32\nexit-vrf")

    # Check pimreg11 interface on R1, VRF blue
    reffile = os.path.join(CWD, "r1/pim_blue_pimreg11.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip pim vrf blue inter pimreg11 json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=15, wait=2)
    assertmsg = "PIM router R1, VRF blue (table 11) pimreg11 interface missing or incorrect status"
    assert res is None, assertmsg

    r1.vtysh_cmd("conf\ninterface red\nip pim")
    r1.vtysh_cmd("conf\nvrf red\nip pim rp 192.168.0.12 239.100.0.1/32\nexit-vrf")

    # Check pimreg12 interface on R1, VRF red
    reffile = os.path.join(CWD, "r1/pim_red_pimreg12.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip pim vrf red inter pimreg12 json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=15, wait=2)
    assertmsg = "PIM router R1, VRF red (table 12) pimreg12 interface missing or incorrect status"
    assert res is None, assertmsg

def test_vrf_pimreg_interfaces():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    try:
        _test_vrf_pimreg_interfaces()
    except Exception:
        # get some debug info.
        output = r1.net.cmd_nostatus("ip -o link")
        logging.error("ip link info after failure: %s", output)
        raise

##################################
###  Test PIM / IGMP with VRF
##################################


def check_mcast_entry(mcastaddr, pimrp, receiver, sender, vrf):
    "Helper function to check RP"
    tgen = get_topogen()

    logger.info("Testing PIM for VRF {} entry using {}".format(vrf, mcastaddr))

    with McastTesterHelper(tgen) as helper:
        helper.run(sender, ["--send=0.7", mcastaddr, str(sender) + "-eth0"])
        helper.run(receiver, [mcastaddr, str(receiver) + "-eth0"])

        logger.info("mcast join and source for {} started".format(mcastaddr))

        router = tgen.gears["r1"]
        reffile = os.path.join(CWD, "r1/pim_{}_join.json".format(vrf))
        expected = json.loads(open(reffile).read())

        logger.info("verifying pim join on r1 for {} on VRF {}".format(mcastaddr, vrf))
        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            "show ip pim vrf {} join json".format(vrf),
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=2)
        assertmsg = "PIM router r1 did not show join status on VRF {}".format(vrf)
        assert res is None, assertmsg

        logger.info("verifying pim join on PIM RP {} for {}".format(pimrp, mcastaddr))
        router = tgen.gears[pimrp]
        reffile = os.path.join(CWD, "{}/pim_{}_join.json".format(pimrp, vrf))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip pim join json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=2)
        assertmsg = (
            "PIM router {} did not get selected as the PIM RP for VRF {}".format(
                pimrp, vrf
            )
        )
        assert res is None, assertmsg


def test_mcast_vrf_blue():
    "Test vrf blue with 239.100.0.1"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry("239.100.0.1", "r11", "h1", "h2", "blue")


def test_mcast_vrf_red():
    "Test vrf red with 239.100.0.1"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry("239.100.0.1", "r12", "h3", "h4", "red")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
