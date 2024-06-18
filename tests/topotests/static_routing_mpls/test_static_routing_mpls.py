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
import sys
import pytest
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
def _populate_mpls_labels():
    tgen = get_topogen()
    cmds_list = ["echo 100000 > /proc/sys/net/mpls/platform_labels"]
    for cmd in cmds_list:
        for host in ("r1", "r2"):
            logger.info("input: " + cmd)
            output = tgen.net[host].cmd(cmd)
            logger.info("output: " + output)


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    _populate_mpls_labels()

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
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
