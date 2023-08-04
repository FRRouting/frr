#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_static_routing_mlpls.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2023 by 6WIND
#

"""
test_static_routing_mpls.py: Testing MPLS configuration with mpls interface settings

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

    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["r2"])


#####################################################
##
##   Tests starting
##
#####################################################
def _populate_iface():
    tgen = get_topogen()
    cmds_list = ["echo 100000 > /proc/sys/net/mpls/platform_labels"]
    for cmd in cmds_list:
        for host in ("r1", "r2"):
            logger.info("input: " + cmd)
            output = tgen.net[host].cmd(cmd)
            logger.info("output: " + output)

    # 1st interface <router>-eth<x>.<vlanid>
    for cmd in cmds_list_iface:
        input = cmd.format("r1", "1", "1", "100")
        logger.info("input: " + cmd.format("r1", "1", "1", "100"))
        output = tgen.net["r1"].cmd(cmd.format("r1", "1", "1", "100"))
        logger.info("output: " + output)

    for cmd in cmds_list_iface:
        input = cmd.format("r2", "0", "2", "100")
        logger.info("input: " + cmd.format("r2", "0", "2", "100"))
        output = tgen.net["r2"].cmd(cmd.format("r2", "0", "2", "100"))
        logger.info("output: " + output)


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


def _check_mpls_state_interface(router, interface, up=True):
    output = router.vtysh_cmd("show interface {}".format(interface))
    if up and "MPLS enabled" in output:
        return None
    elif not up and "MPLS enabled" not in output:
        return None
    return "not good"


def _check_mpls_state(router, interface, configured=True):
    test_func = functools.partial(
        _check_mpls_state_interface, router, interface, up=configured
    )
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    return success


def test_mpls_configured_on_interface():
    "Test 'mpls' state is correctly configured on an unconfigured interfaces"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking that MPLS state is on on r2-eth1")
    assertmsg = "r2, interface r2-eth1, mpls operational state is off, not expected"
    assert _check_mpls_state(tgen.gears["r2"], "r2-eth1"), assertmsg

    logger.info("Checking that MPLS state is off on r2-eth2")
    assertmsg = "r2, interface r2-eth2, mpls operational state is on, not expected"
    assert _check_mpls_state(tgen.gears["r2"], "r2-eth2", False), assertmsg


def test_mpls_zebra_route_nexthop():
    "Test 'mpls' state is correctly configured with labeled routes configured"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]
    router.vtysh_cmd("config terminal\nmpls lsp 33 192.168.2.3 implicit-null")

    logger.info(
        "r1, configuring a route with labeled nexthop address, checking that MPLS state is on on r1-eth1"
    )
    router = tgen.gears["r1"]
    router.vtysh_cmd(
        "config terminal\nip route 192.0.2.3/32 192.168.2.2 label 33"
    )
    assertmsg = "r1, interface r1-eth1, mpls operational state is off, not expected"
    assert _check_mpls_state(tgen.gears["r1"], "r1-eth1"), assertmsg
    # interface r1-eth1 should have mpls turned on

    logger.info(
        "r2, configuring a route with labeled nexthop interface, checking that MPLS state is on on r2-eth0"
    )
    router = tgen.gears["r2"]
    router.vtysh_cmd(
        "config terminal\nip route 192.0.2.100/32 192.168.2.1 r2-eth0 label 100"
    )
    # interface r2-eth0 should have mpls turned on
    assertmsg = "r2, interface r2-eth0, mpls operational state is off, not expected"
    assert _check_mpls_state(tgen.gears["r2"], "r2-eth0"), assertmsg


def test_mpls_interface_configured_delete():
    "Test 'mpls' state is correctly set on a configured interface before and after deletion of that interface"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "r1, configuring a route with labeled nexthop address, checking that MPLS is configured on r1-eth1.100"
    )
    router = tgen.gears["r1"]
    router.vtysh_cmd(
        "config terminal\nip route 192.0.2.160/32 172.31.100.2 label 100"
    )
    # interface r1-eth1.100 should have mpls turned on
    assertmsg = "r1, interface r1-eth1.100, mpls operational state is off, not expected"
    assert _check_mpls_state(tgen.gears["r1"], "r1-eth1.100"), assertmsg

    logger.info(
        "r1, deleting r1-eth1.100, checking that MPLS is unconfigured on r1-eth1.200"
    )
    tgen.net["r1"].cmd("ip link delete r1-eth1.100")
    # interface r1-eth1.100 should be turned down
    router.vtysh_cmd(
        "config terminal\nno ip route 192.0.2.160/32 172.31.100.2 label 100"
    )
    # static route is really removed to not conflict with mpls saved state

    # interface r1-eth1.100 should be turned off, and mpls should be on
    assertmsg = "r1, interface r1-eth1.100, mpls operational state is on, not expected"
    assert _check_mpls_state(
        tgen.gears["r1"], "r1-eth1.100", configured=False
    ), assertmsg

    logger.info(
        "r1, re-creating r1-eth1.100, checking that MPLS is configured on r1-eth1.100"
    )
    for cmd in cmds_list_iface:
        input = cmd.format("r1", "1", "1", "100")
        logger.info("input: " + cmd.format("r1", "1", "1", "100"))
        output = tgen.net["r1"].cmd(cmd.format("r1", "1", "1", "100"))
        logger.info("output: " + output)

    # interface r1-eth1.100 should be turned on, and mpls should be on
    assertmsg = "r1, interface r1-eth1.100, mpls operational state is off, not expected"
    assert _check_mpls_state(tgen.gears["r1"], "r1-eth1.100"), assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
