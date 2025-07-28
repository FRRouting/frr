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

    # Check that BGP neighbor on tor2 has come up
    tor2 = tgen.gears["tor2"]

    # Expected BGP summary output for tor2
    expected_bgp_summary = {
        "routerId": "192.168.6.2",
        "as": 99,
        "peerCount": 1,
        "peers": {
            "192.168.4.3": {
                "hostname": "spine1",
                "remoteAs": 99,
                "localAs": 99,
                "outq": 0,
                "inq": 0,
                "pfxRcd": 4,
                "pfxSnt": 3,
                "state": "Established",
                "peerState": "OK",
                "idType": "ipv4",
            }
        },
        "failedPeers": 0,
        "displayedPeers": 1,
        "totalPeers": 1,
        "dynamicPeers": 0,
        "bestPath": {"multiPathRelax": "false"},
    }

    # Create a test function that checks BGP neighbor state
    def test_bgp_neighbor_up():
        return topotest.router_json_cmp(
            tor2, "show bgp ipv4 uni summ json", expected_bgp_summary
        )

    # Use run_and_expect to wait for BGP neighbor to come up
    success, result = topotest.run_and_expect(
        test_bgp_neighbor_up, None, count=30, wait=1
    )

    assertmsg = "BGP neighbor on tor2 failed to come up"
    assert success, assertmsg


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
        refTableFile = "{}/{}/show_ip_route.json_ref".format(CWD, router.name)
        expected = json.loads(open(refTableFile).read())

        # Create a test function that compares router output with expected JSON
        def test_router_routes():
            return topotest.router_json_cmp(router, "show ip route json", expected)

        # Use run_and_expect to wait for the routes to match expected output
        success, result = topotest.run_and_expect(
            test_router_routes, None, count=30, wait=1
        )

        assertmsg = "Zebra IPv4 Routing Table verification failed for router {}".format(
            router.name
        )
        assert success, assertmsg


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
