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

pytestmark = [pytest.mark.zebra]

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


def check_show_static_mpls_route_installed(rname):
    tgen = get_topogen()
    output = json.loads(
        tgen.gears[rname].vtysh_cmd("show ip route 192.168.2.2/32 json")
    )
    found = False
    logmsg = f"{rname}, prefix 192.168.2.2/32 not installed as it should be"
    errmsg = f"{logmsg}, not found"
    for path in output["192.168.2.2/32"]:
        if "installed" not in path.keys() or not path["installed"]:
            errmsg = f"{logmsg} : path not installed"
            continue
        for nh in path["nexthops"]:
            if "directlyConnected" not in nh.keys() or not nh["directlyConnected"]:
                errmsg = f"{logmsg} : nexthop not directly connected"
            elif "interfaceName" not in nh.keys() or nh["interfaceName"] != "r1-eth1":
                errmsg = f"{logmsg} : wrong nexthop interface"
            elif "labels" not in nh.keys() or nh["labels"] != [100]:
                errmsg = f"{logmsg} : wrong nexthop label"
            else:
                found = True
        else:
            errmsg = f"{logmsg}, nexthop not found"
    if found:
        return None
    return errmsg


def check_show_linux_mpls_label_installed(rname):
    tgen = get_topogen()
    output = tgen.net[rname].cmd("ip route show 192.168.2.2/32")
    if "encap mpls  100" not in output:
        return f"{rname}, prefix 192.168.2.2/32 not installed: iproute2 has not expected label value"
    return None


def check_show_static_recursive_route_installed(rname):
    tgen = get_topogen()
    output = json.loads(
        tgen.gears[rname].vtysh_cmd("show ip route 192.168.3.0/24 json")
    )
    found_recursive = False
    found_label = False
    logmsg = f"{rname}, prefix 192.168.3.0/24 not installed as it should be"
    errmsg = f"{logmsg}, not found"
    for path in output["192.168.3.0/24"]:
        if "installed" not in path.keys() or not path["installed"]:
            errmsg = f"{logmsg} : path not installed"
            continue
        for nh in path["nexthops"]:
            if "recursive" in nh.keys() and nh["recursive"]:
                if "ip" not in nh.keys() or nh["ip"] != "192.168.2.2":
                    errmsg = f"{logmsg} : nexthop not found"
                else:
                    found_recursive = True
            elif "interfaceName" not in nh.keys() or nh["interfaceName"] != "r1-eth1":
                errmsg = f"{logmsg} : wrong nexthop interface"
            elif "labels" not in nh.keys() or nh["labels"] != [100]:
                errmsg = f"{logmsg} : wrong nexthop label"
            else:
                found_label = True
        else:
            errmsg = f"{logmsg}, nexthop not found"
    if found_recursive and found_label:
        return None
    return errmsg


def test_connected_mpls_route():
    "Test that the static MPLS route can be installed with MPLS label"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Checking that static MPLS route 192.168.2.2/32 is installed with labels on ZEBRA"
    )
    test_func = functools.partial(check_show_static_mpls_route_installed, "r1")
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, result

    logger.info(
        "Checking that static MPLS route 192.168.2.2/32 is installed with labels on system"
    )
    test_func = functools.partial(check_show_linux_mpls_label_installed, "r1")
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, result

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

    test_func = functools.partial(check_show_static_recursive_route_installed, "r1")
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, result

    logger.info("Checking that ping via 192.168.3.2 is working")
    check_ping("r1", "192.168.3.2", True, 10, 0.5)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
