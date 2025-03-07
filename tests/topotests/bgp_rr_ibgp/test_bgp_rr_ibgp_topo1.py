#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_rr_ibgp_topo1.py
#
# Copyright (c) 2019 by
# Cumulus Networks, Inc.
# Donald Sharp
#

"""
test_bgp_rr_ibgp_topo1.py: Testing IBGP with RR and no IGP

Ensure that a basic rr topology comes up and correctly passes
routes around

"""

import os
import sys
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    tgen.add_router("tor1")
    tgen.add_router("tor2")
    tgen.add_router("spine1")

    # First switch is for a dummy interface (for local network)
    # on tor1
    # 192.168.1.0/24
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["tor1"])

    # 192.168.2.0/24 - tor1 <-> spine1 connection
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["tor1"])
    switch.add_link(tgen.gears["spine1"])

    # 3rd switch is for a dummy interface (for local netwokr)
    # 192.168.3.0/24 - tor2
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["tor2"])

    # 192.168.4.0/24 - tor2 <-> spine1 connection
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["tor2"])
    switch.add_link(tgen.gears["spine1"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()
    # tgen.mininet_cli()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, "Waiting for BGP_RR_IBGP convergence")


def test_bgp_rr_ibgp_routes():
    "Test Route Reflection"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify BGP_RR_IBGP Status
    logger.info("Verifying BGP_RR_IBGP routes")


def test_zebra_ipv4_routingTable():
    "Test 'show ip route'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_list = tgen.routers().values()
    for router in router_list:
        output = router.vtysh_cmd("show ip route json", isjson=True)
        refTableFile = "{}/{}/show_ip_route.json_ref".format(CWD, router.name)
        expected = json.loads(open(refTableFile).read())

        assertmsg = "Zebra IPv4 Routing Table verification failed for router {}".format(
            router.name
        )
        assert topotest.json_cmp(output, expected) is None, assertmsg


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying unexpected STDERR output from daemons")

    router_list = tgen.routers().values()
    for router in router_list:
        router.stop()

        log = tgen.net[router.name].getStdErr("bgpd")
        if log:
            logger.error("BGPd StdErr Log:" + log)
        log = tgen.net[router.name].getStdErr("zebra")
        if log:
            logger.error("Zebra StdErr Log:" + log)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

#
# Auxiliary Functions
#
