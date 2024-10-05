#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_instance_redistribute.py
#
# Copyright (c) 2022 by
# Nvidia, Inc.
# Donald Sharp
#

"""
test_ospf_instance_redistribute

"""

import os
import sys
import pytest
import json

pytestmark = [pytest.mark.ospfd, pytest.mark.sharpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from functools import partial

# Required to instantiate the topology builder class.

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    tgen.add_router("r1")

    # Connect r1 and r2 through the eth0 interface
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])


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
    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_OSPF, os.path.join(CWD, "r1/ospfd-3.conf"), "-n 3")
    r1.load_config(TopoRouter.RD_SHARP, os.path.join(CWD, "r1/sharpd.conf"))

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_install_sharp_instance_routes():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Installing sharp routes")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("sharp install route 4.5.6.7 nexthop 192.168.100.2 1")
    r1.vtysh_cmd("sharp install route 4.5.6.8 nexthop 192.168.100.2 1 instance 3")
    r1.vtysh_cmd("sharp install route 4.5.6.9 nexthop 192.168.100.3 1 instance 4")
    r1.vtysh_cmd("conf\nrouter ospf 3\nredistribute sharp")

    json_file = "{}/r1/sharp_installed.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route summ json", expected
    )

    logger.info("Ensuring that they exist in the rib/fib")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r1" sharp routes are not installed'
    assert result is None, assertmsg


def test_ospf_instance_redistribute():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing that ospf instance 3 has the redistributed sharp route")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf\nrouter ospf 3\nredistribute sharp")

    json_file = "{}/r1/ospf_instance_lsa.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf 3 data json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r1" ospf instance 3 does not have the proper redistributed routes'
    assert result is None, assertmsg

    r1.vtysh_cmd("sharp install route 4.5.6.10 nexthop 192.168.100.2 1")
    r1.vtysh_cmd("sharp install route 4.5.6.11 nexthop 192.168.100.2 1 instance 3")
    r1.vtysh_cmd("sharp install route 4.5.6.12 nexthop 192.168.100.2 1 instance 4")

    logger.info("Added new sharp routes let's see if we pick up only the .10")
    json_file = "{}/r1/ospf_instance_lsa2.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf 3 data json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r1" ospf instance 3 does not have the proper redistributed routes'
    assert result is None, assertmsg


def test_ospf_instance_default_information():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing the using default information originate")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf\nrouter ospf 3\ndefault-information originate")

    r1.vtysh_cmd("conf\nip route 0.0.0.0/0 192.168.100.2")
    json_file = "{}/r1/ospf_default_information.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf 3 data json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = '"r1" ospf instance 3 does not properly redistribute the default route'
    assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
