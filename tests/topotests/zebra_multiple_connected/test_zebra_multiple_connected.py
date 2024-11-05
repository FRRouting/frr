#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_multiple_connected.py
#
# Copyright (c) 2022 by
# Nvidia Corporation
# Donald Sharp
#

"""
test_zebra_multiple_connected.py: Testing multiple connected

"""

import os
import sys
import pytest
import json
from functools import partial
from lib.topolog import logger

pytestmark = pytest.mark.random_order(disabled=True)

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

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

    # Switches for zebra
    # switch 2 switch is for connection to zebra router
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # switch 4 is stub on remote zebra router
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["r3"])

    # switch 3 is between zebra routers
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

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_zebra_connected_multiple():
    "Test multiple connected routes that have a kernel route pointing at one"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("ip route add 192.168.1.1/32 via 10.0.1.99 dev r1-eth1")
    router.run("ip link add dummy1 type dummy")
    router.run("ip link set dummy1 up")
    router.run("ip link set dummy1 down")

    routes = "{}/{}/ip_route.json".format(CWD, router.name)
    expected = json.loads(open(routes).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Kernel route is missing from zebra"


def test_zebra_system_recursion():
    "Test a system route recursing through another system route"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("ip route add 10.0.1.30/32 dev r1-eth1")
    router.run("ip route add 10.9.9.0/24 via 10.0.1.30 dev r1-eth1")
    router.run("ip link add dummy2 type dummy")
    router.run("ip link set dummy2 up")
    router.run("ip link set dummy2 down")

    routes = "{}/{}/ip_route2.json".format(CWD, router.name)
    expected = json.loads(open(routes).read())
    test_func = partial(
        topotest.router_json_cmp, router, "show ip route json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Kernel route is missing from zebra"


def test_zebra_noprefix_connected():
    "Test that a noprefixroute created does not create a connected route"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("ip addr add 192.168.44.1/24 dev r1-eth1 noprefixroute")
    expected = "% Network not in table"
    test_func = partial(
        topotest.router_output_cmp, router, "show ip route 192.168.44.0/24", expected
    )
    result, _ = topotest.run_and_expect(test_func, "", count=20, wait=1)
    assert result, "Connected Route should not have been added"


def test_zebra_noprefix_connected_add():
    "Test that a noprefixroute created with a manual route works as expected, this is for NetworkManager"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("ip route add 192.168.44.0/24 dev r1-eth1")

    connected = "{}/{}/ip_route_connected.json".format(CWD, router.name)
    expected = json.loads(open(connected).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route 192.168.44.0/24 json", expected
    )
    result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, "Connected Route should have been added\n{}".format(_)


def test_zebra_kernel_route_add():
    "Test that a random kernel route is properly handled as expected"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("ip route add 4.5.6.7/32 dev r1-eth1")

    kernel = "{}/{}/ip_route_kernel.json".format(CWD, router.name)
    expected = json.loads(open(kernel).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route 4.5.6.7/32 json", expected
    )
    result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, "Connected Route should have been added\n{}".format(_)


def test_zebra_kernel_route_blackhole_add():
    "Test that a blackhole route is not affected by interface's link change"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("ip route add blackhole default")
    router.run("ip link set dev r1-eth1 down")

    kernel = "{}/{}/ip_route_kernel_blackhole.json".format(CWD, router.name)
    expected = json.loads(open(kernel).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route 0.0.0.0/0 json", expected
    )
    result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, "Blackhole Route should have not been removed\n{}".format(_)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
