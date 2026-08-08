#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_connected_mpls.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2023 by 6WIND
#

"""
test_connected_mpls.py: Testing MPLS configuration with mpls connected route
"""

import os
import re
import sys
import pytest
import json
from functools import partial
import functools

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.checkping import check_ping
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

#####################################################
##
##   Network Topology Definition
##
#####################################################

cmds_list_iface = [
    "ip link add link {0}-eth{1} name {0}-eth{1}.{3} type vlan id {3}",
    "ip link set dev {0}-eth{1}.{3} up",
]


def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["r2"])


#####################################################
##
##   Tests starting
##
#####################################################
def _populate_iface():
    tgen = get_topogen()
    tgen.net["r1"].cmd("echo 100000 > /proc/sys/net/mpls/platform_labels")
    tgen.net["r2"].cmd("echo 100000 > /proc/sys/net/mpls/platform_labels")
    tgen.net["r2"].cmd("ip -f mpls route add 100 dev lo")


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    _populate_iface()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_connected_mpls_route():
    "Test that the static MPLS route can be installed with MPLS label"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Checking that static MPLS route 192.168.2.2/32 is installed with labels on ZEBRA"
    )
    assertmsg = "r1, prefix 192.168.2.2/32 not installed as it should be"
    output = json.loads(tgen.gears["r1"].vtysh_cmd("show ip route 192.168.2.2/32 json"))
    for path in output["192.168.2.2/32"]:
        assert path["installed"] == True, assertmsg + ": path not installed"
        for nh in path["nexthops"]:
            assert nh["directlyConnected"] == True, (
                assertmsg + ": nexthop not directly connected"
            )
            assert nh["interfaceName"] == "r1-eth1", (
                assertmsg + ": wrong nexthop interface"
            )
            assert nh["labels"] == [100], assertmsg + ": wrong nexthop label"

    logger.info(
        "Checking that static MPLS route 192.168.2.2/32 is installed with labels on system"
    )
    output = tgen.net["r1"].cmd("ip route show 192.168.2.2/32")
    assert "encap mpls  100" in output, (
        assertmsg + ": iproute2 has not expected label value"
    )

    # ping does not work because sent MPLS packet is broadcase
    # like all connected routes, packets are broadcast
    # consequently, on receiving router, broadcast packets received can not be forwarded
    # this is the case for MPLS packets.
    # logger.info("Checking that ping via 192.168.2.2 is working")
    # check_ping("r1", "192.168.2.2", True, 10, 0.5)


def test_recursive_mpls_route():
    "Test that a recursive route can re-use the label from the static MPLS route."

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Checking that route 192.168.3.0/24 is installed with labels from recursive route on ZEBRA"
    )
    assertmsg = "r1, prefix 192.168.3.0/32 not installed as it should be"
    output = json.loads(tgen.gears["r1"].vtysh_cmd("show ip route 192.168.3.0/24 json"))
    for path in output["192.168.3.0/24"]:
        assert path["installed"] == True, assertmsg + ": path not installed"
        for nh in path["nexthops"]:
            if "recursive" in nh.keys():
                assert nh["ip"] == "192.168.2.2", assertmsg + ": nexthop not found"
            else:
                assert nh["interfaceName"] == "r1-eth1", (
                    assertmsg + ": wrong nexthop interface"
                )
                assert nh["labels"] == [100], assertmsg + ": wrong nexthop label"

    logger.info("Checking that ping via 192.168.3.2 is working")
    check_ping("r1", "192.168.3.2", True, 10, 0.5)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
