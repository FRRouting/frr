#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_babel_topo1.py
#
# Copyright (c) 2017 by
# Cumulus Networks, Inc.
# Donald Sharp
#

"""
test_babel_topo1.py: Testing BABEL

"""

import os
import sys
import pytest
import json
from functools import partial

pytestmark = [pytest.mark.babeld]

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
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # On main router
    # First switch is for a dummy interface (for local network)
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])

    # Switches for BABEL
    # switch 2 switch is for connection to BABEL router
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # switch 4 is stub on remote BABEL router
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["r3"])

    # switch 3 is between BABEL routers
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


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
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    tgen.start_router()


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

    logger.info("Waiting for BABEL convergence")

    # Check that all routers have established neighbors
    for rname in ["r1", "r2", "r3"]:
        router = tgen.gears[rname]

        def check_convergence(router=router, rname=rname):
            output = router.vtysh_cmd("show babel neighbor")
            if "Neighbour" not in output:
                return "{} has not established babel neighbors yet".format(rname)
            return None

        _, result = topotest.run_and_expect(check_convergence, None, count=60, wait=1)
        assert result is None, "{} failed to converge".format(rname)


def test_babel_neighbors():
    "Test BABEL neighbor discovery and adjacencies"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying BABEL neighbor adjacencies")

    # r1 should have r2 as neighbor
    router = tgen.gears["r1"]

    def check_r1_neighbor():
        output = router.vtysh_cmd("show babel neighbor")
        if "Neighbour" not in output:
            return "r1 should have babel neighbors"
        return None

    _, result = topotest.run_and_expect(check_r1_neighbor, None, count=30, wait=1)
    assert result is None, "r1 failed to establish BABEL neighbor"
    logger.info("r1 neighbors:\n{}".format(router.vtysh_cmd("show babel neighbor")))

    # r2 should have both r1 and r3 as neighbors
    router = tgen.gears["r2"]

    def check_r2_neighbors():
        output = router.vtysh_cmd("show babel neighbor")
        neighbor_count = output.count("Neighbour")
        if neighbor_count < 2:
            return "r2 has {} neighbors, expected at least 2".format(neighbor_count)
        return None

    _, result = topotest.run_and_expect(check_r2_neighbors, None, count=30, wait=1)
    assert result is None, "r2 failed to establish 2 BABEL neighbors"
    logger.info("r2 neighbors:\n{}".format(router.vtysh_cmd("show babel neighbor")))

    # r3 should have r2 as neighbor
    router = tgen.gears["r3"]

    def check_r3_neighbor():
        output = router.vtysh_cmd("show babel neighbor")
        if "Neighbour" not in output:
            return "r3 should have babel neighbors"
        return None

    _, result = topotest.run_and_expect(check_r3_neighbor, None, count=30, wait=1)
    assert result is None, "r3 failed to establish BABEL neighbor"
    logger.info("r3 neighbors:\n{}".format(router.vtysh_cmd("show babel neighbor")))


def runit(router, assertmsg, cmd, expfile):
    logger.info(expfile)

    # Read expected result from file
    expected = json.loads(open(expfile).read())

    test_func = partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, assertmsg


def test_babel_routes():
    "Test BABEL internal routing table"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying BABEL internal routing table")

    # Check that each router has learned routes via babel
    router_list = tgen.routers().values()
    for router in router_list:

        def check_babel_routes(router=router):
            output = router.vtysh_cmd("show babel route")
            # Look for route entries (they contain "metric" keyword)
            if "metric" not in output:
                return "{} has no babel routes yet".format(router.name)
            return None

        _, result = topotest.run_and_expect(check_babel_routes, None, count=30, wait=1)
        assert result is None, "{} should have babel routes".format(router.name)
        logger.info(
            "{} babel routes:\n{}".format(
                router.name, router.vtysh_cmd("show babel route")
            )
        )


def test_zebra_ipv4_routingTable():
    "Test 'show ip route'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_list = tgen.routers().values()
    for router in router_list:
        assertmsg = "Zebra IPv4 Routing Table verification failed for router {}".format(
            router.name
        )
        refTableFile = "{}/{}/show_ip_route.json_ref".format(CWD, router.name)
        runit(router, assertmsg, "show ip route json", refTableFile)


def test_babel_interface_bounce():
    """
    Test BABEL protocol handling when interfaces bounce.

    This triggers wildcard route requests (MESSAGE_REQUEST with AE=0, Plen=0)
    which are short 2-byte messages. This test specifically exercises the bug
    fix where message[6] was incorrectly accessed in MESSAGE_REQUEST handler.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BABEL interface bounce and wildcard route requests")

    router = tgen.gears["r2"]

    # Get initial neighbor count and state
    output = router.vtysh_cmd("show babel neighbor")
    initial_neighbor_count = output.count("Neighbour")
    logger.info("r2 initial neighbors (count={}):".format(initial_neighbor_count))

    # Bounce the interface to r1 - this will trigger wildcard route requests
    logger.info("Shutting down r2-eth0 interface")
    router.vtysh_cmd("configure terminal\ninterface r2-eth0\nshutdown")

    # Verify the neighbor on r2-eth0 goes down or disappears
    def check_neighbor_down():
        output = router.vtysh_cmd("show babel neighbor")
        # After shutdown, we should have fewer neighbors or see "(down)" marker
        neighbor_count = output.count("Neighbour")
        # Count neighbors that are not marked as down on r2-eth0
        if neighbor_count >= initial_neighbor_count:
            # Check if r2-eth0 neighbor is marked as down
            if "r2-eth0" in output and "(down)" not in output:
                return "r2-eth0 neighbor should be down or removed"
        return None

    _, result = topotest.run_and_expect(check_neighbor_down, None, count=30, wait=1)
    assert result is None, "r2-eth0 neighbor did not go down after interface shutdown"
    logger.info(
        "r2 neighbors after shutdown:\n{}".format(
            router.vtysh_cmd("show babel neighbor")
        )
    )

    # Bring interface back up
    logger.info("Bringing up r2-eth0 interface")
    router.vtysh_cmd("configure terminal\ninterface r2-eth0\nno shutdown")

    # Verify neighbors are re-established using run_and_expect
    # This process involves sending and receiving wildcard route requests
    def check_neighbors_recovered():
        output = router.vtysh_cmd("show babel neighbor")
        neighbor_count = output.count("Neighbour")
        if neighbor_count < initial_neighbor_count:
            return "r2 has {} neighbors, expected at least {}".format(
                neighbor_count, initial_neighbor_count
            )
        # Also verify no neighbors are marked as down
        if "(down)" in output:
            return "Some neighbors still marked as down"
        return None

    _, result = topotest.run_and_expect(
        check_neighbors_recovered, None, count=30, wait=1
    )
    assert result is None, "r2 failed to re-establish neighbors after interface bounce"
    logger.info(
        "r2 neighbors after bounce:\n{}".format(router.vtysh_cmd("show babel neighbor"))
    )

    # Verify routes are still learned
    def check_routes_recovered():
        output = router.vtysh_cmd("show babel route")
        if "metric" not in output:
            return "r2 has no babel routes after interface bounce"
        return None

    _, result = topotest.run_and_expect(check_routes_recovered, None, count=30, wait=1)
    assert result is None, "r2 failed to recover babel routes after interface bounce"
    logger.info(
        "r2 babel routes after bounce:\n{}".format(router.vtysh_cmd("show babel route"))
    )


def test_babel_specific_route_request():
    """
    Test specific route requests.

    This adds a new route on r3 and verifies it propagates to r1,
    which exercises specific prefix route requests.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing specific BABEL route requests")

    router = tgen.gears["r3"]

    # Add a new static route on r3
    logger.info("Adding new static route 10.99.99.0/24 on r3")
    router.vtysh_cmd("configure terminal\n" "ip route 10.99.99.0/24 Null0\n")

    # Check that r1 learns the new route via babel (with retries)
    router = tgen.gears["r1"]

    def check_new_route():
        output = router.vtysh_cmd("show ip route 10.99.99.0/24 json", isjson=True)
        if "10.99.99.0/24" not in output:
            return "Route 10.99.99.0/24 not found"
        route_info = output["10.99.99.0/24"]
        if not route_info:
            return "Route entry is empty"
        if route_info[0].get("protocol") != "babel":
            return "Route not learned via babel"
        return None

    success, result = topotest.run_and_expect(check_new_route, None, count=30, wait=1)
    assert result is None, "r1 should learn the new route 10.99.99.0/24 via babel"

    logger.info("Successfully verified new route propagation via BABEL")


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

        log = tgen.net[router.name].getStdErr("babeld")
        if log:
            logger.error("BABELd StdErr Log:" + log)
        log = tgen.net[router.name].getStdErr("zebra")
        if log:
            logger.error("Zebra StdErr Log:" + log)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
