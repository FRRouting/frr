#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_eigrp_topo1.py
#
# Copyright (c) 2017 by
# Cumulus Networks, Inc.
# Donald Sharp
#

"""
test_eigrp_topo1.py: Testing EIGRP

"""

import os
import re
import sys
import pytest
import json

pytestmark = [pytest.mark.eigrpd]

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

    # Switches for EIGRP
    # switch 2 switch is for connection to EIGRP router
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # switch 4 is stub on remote EIGRP router
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["r3"])

    # switch 3 is between EIGRP routers
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
            TopoRouter.RD_EIGRP, os.path.join(CWD, "{}/eigrpd.conf".format(rname))
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

    topotest.sleep(5, "Waiting for EIGRP convergence")


def test_eigrp_routes():
    "Test EIGRP 'show ip eigrp'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify EIGRP Status
    logger.info("Verifying EIGRP routes")

    router_list = tgen.routers().values()
    for router in router_list:
        refTableFile = "{}/{}/show_ip_eigrp.json".format(CWD, router.name)

        # Read expected result from file
        expected = json.loads(open(refTableFile).read())

        # Actual output from router
        actual = ip_eigrp_topo(router)

        assertmsg = '"show ip eigrp topo" mismatches on {}'.format(router.name)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_zebra_ipv4_routingTable():
    "Test 'show ip route'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    failures = 0
    router_list = tgen.routers().values()
    for router in router_list:
        output = router.vtysh_cmd("show ip route json", isjson=True)
        refTableFile = "{}/{}/show_ip_route.json_ref".format(CWD, router.name)
        expected = json.loads(open(refTableFile).read())

        assertmsg = "Zebra IPv4 Routing Table verification failed for router {}".format(
            router.name
        )
        assert topotest.json_cmp(output, expected) is None, assertmsg


def test_shut_interface_and_recover():
    "Test shutdown of an interface and recovery of the interface"

    tgen = get_topogen()
    router = tgen.gears["r1"]
    router.run("ip link set r1-eth1 down")
    topotest.sleep(5, "Waiting for EIGRP convergence")
    router.run("ip link set r1-eth1 up")


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

        log = tgen.net[router.name].getStdErr("eigrpd")
        if log:
            logger.error("EIGRPd StdErr Log:" + log)
        log = tgen.net[router.name].getStdErr("zebra")
        if log:
            logger.error("Zebra StdErr Log:" + log)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


#
# Auxiliary Functions
#
def ip_eigrp_topo(node):
    """
    Parse 'show ip eigrp topo' from `node` and returns a dict with the
    result.

    Example:
    {
        'P': {
            '192.168.1.0/24': {
                'sucessors': 1,
                'fd': 112233,
                'serno': 0,
                'via': 'Connected',
                'interface': 'eth0',
            },
            '192.168.2.0/24': {
                'sucessors': 1,
                'fd': 112234,
                'serno': 0,
                'via': 'Connected',
                'interface': 'eth1',
            }
        }
    }
    """
    output = topotest.normalize_text(node.vtysh_cmd("show ip eigrp topo")).splitlines()
    result = {}
    for idx, line in enumerate(output):
        columns = line.split(" ", 1)

        # Parse the following format into python dicts
        # code A.B.C.D/E, X successors, FD is Y, serno: Z
        #       via FOO, interface-name
        code = columns[0]
        if code not in ["P", "A", "U", "Q", "R", "r", "s"]:
            continue

        if code not in result:
            result[code] = {}

        # Split network from the rest
        columns = columns[1].split(",")

        # Parse first line data
        network = columns[0]
        result[code][network] = {}
        for column in columns:
            # Skip the network column
            if column == columns[0]:
                continue

            match = re.search(r"(\d+) successors", column)
            if match is not None:
                result[code][network]["successors"] = match.group(1)
                continue

            match = re.search(r"FD is (\d+)", column)
            if match is not None:
                result[code][network]["fd"] = match.group(1)
                continue

            match = re.search(r"serno: (\d+)", column)
            if match is not None:
                result[code][network]["serno"] = match.group(1)
                continue

        # Parse second line data
        nextline = output[idx + 1]
        columns = topotest.normalize_text(nextline).split(",")
        for column in columns:
            match = re.search(r"via (.+)", column)
            if match is not None:
                result[code][network]["via"] = match.group(1)
                continue

            match = re.search(r"(.+)", column)
            if match is not None:
                result[code][network]["interface"] = match.group(1)
                continue

    return result
