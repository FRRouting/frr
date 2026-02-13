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

    # Create a p2p connection between r1 and r2
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology and load unified config (frr.conf)."
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None)],
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


def test_zebra_kernel_route_interface_linkdown():
    "Test that a kernel routes should be affected by interface change"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("ip route add 5.5.6.7/32 via 10.0.1.66 dev r1-eth2")

    kernel = "{}/{}/ip_route_kernel_interface_up.json".format(CWD, router.name)
    expected = json.loads(open(kernel).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route 5.5.6.7/32 json", expected
    )
    result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, "Kernel Route should be selected:\n{}".format(_)

    # link down
    router2 = tgen.gears["r2"]
    router2.run("ip link set dev r2-eth2 down")

    kernel = "{}/{}/ip_route_kernel_interface_down.json".format(CWD, router.name)
    expected = json.loads(open(kernel).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route 5.5.6.7/32 json", expected
    )
    result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, "Kernel Route should not be selected:\n{}".format(_)

    # link up
    router2 = tgen.gears["r2"]
    router2.run("ip link set dev r2-eth2 up")

    kernel = "{}/{}/ip_route_kernel_interface_up.json".format(CWD, router.name)
    expected = json.loads(open(kernel).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route 5.5.6.7/32 json", expected
    )
    result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, "Kernel Route should be selected:\n{}".format(_)


def test_zebra_mtu_single_local_route_per_address():
    "Set MTU to 6000 on r2-eth2 and ensure only one local route per address on the interface"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    ifname = "r2-eth2"

    # Set MTU to 6000 on r2-eth2 (via kernel; FRR has no mtu command)
    logger.info("Setting MTU 6000 on %s", ifname)
    r2.run("ip link set dev {} mtu 6000".format(ifname))

    def _check_one_local_per_address():
        # Get interface addresses (IPv4) on r2-eth2
        if_output = r2.vtysh_cmd("show interface {} json".format(ifname), isjson=True)
        if not if_output or ifname not in if_output:
            return "Interface {} not found in show interface output".format(ifname)
        ip_addresses = if_output[ifname].get("ipAddresses", [])
        # Collect IPv4 /32 prefixes (host routes) for each address
        local_prefixes = []
        for addr_obj in ip_addresses:
            addr = addr_obj.get("address", "")
            if not addr or "/" not in addr:
                continue
            prefix, plen = addr.split("/")
            plen = int(plen)
            if ":" in prefix:
                continue  # skip IPv6
            # Local route for this address is the host /32
            local_prefixes.append(prefix + "/32")

        if not local_prefixes:
            return "No IPv4 addresses found on {}".format(ifname)

        # Get route table
        route_output = r2.vtysh_cmd("show ip route json", isjson=True)
        if not route_output:
            return "No output from show ip route json"

        for prefix in local_prefixes:
            if prefix not in route_output:
                return "Prefix {} not in route table".format(prefix)
            entries = route_output[prefix]
            local_count = 0
            for entry in entries:
                if entry.get("protocol") != "local":
                    continue
                nexthops = entry.get("nexthops", [])
                for nh in nexthops:
                    if nh.get("interfaceName") == ifname:
                        local_count += 1  # one local route entry for this prefix
                        break
            if local_count != 1:
                return "Expected exactly one local route for {} on {}, found {}".format(
                    prefix, ifname, local_count
                )
        return None

    _, result = topotest.run_and_expect(
        _check_one_local_per_address, None, count=20, wait=1
    )
    assert result is None, "Local route check failed: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
