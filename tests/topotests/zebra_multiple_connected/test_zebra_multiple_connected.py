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
from lib.common_config import (
    create_address_on_interface,
    create_interface_in_kernel,
    kill_router_daemons,
    shutdown_bringup_interface_in_kernel,
    start_router_daemons,
    step,
)
from lib.topolog import logger

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen

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
    for router in router_list.values():
        router.load_frr_config()

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
    create_interface_in_kernel(tgen, router.name, "dummy1")
    shutdown_bringup_interface_in_kernel(router.tgen, router.name, "dummy1", False)

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
    create_interface_in_kernel(tgen, router.name, "dummy2")
    shutdown_bringup_interface_in_kernel(router.tgen, router.name, "dummy2", False)

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
    shutdown_bringup_interface_in_kernel(router.tgen, router.name, "r1-eth1", False)

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
    shutdown_bringup_interface_in_kernel(router2.tgen, router2.name, "r2-eth2", False)

    kernel = "{}/{}/ip_route_kernel_interface_down.json".format(CWD, router.name)
    expected = json.loads(open(kernel).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route 5.5.6.7/32 json", expected
    )
    result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, "Kernel Route should not be selected:\n{}".format(_)

    # link up
    router2 = tgen.gears["r2"]
    shutdown_bringup_interface_in_kernel(router2.tgen, router2.name, "r2-eth2", True)

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


def test_zebra_kernel_last_ipv4_address_deleted():
    "Test that when last IPv4 address is deleted on interface, kernel routes are deleted as well"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    ifname = "dummy0"

    def _get_routes_dict(val):
        return {
            "203.0.113.0/24": val,
            "10.0.170.0/24": val,
        }

    def _assert_kernel_routes(router, msg, val):
        routes = topotest.ip4_route(router)
        expected = _get_routes_dict(val)
        cmp = topotest.json_cmp(routes, expected)
        assert cmp is None, msg.format(cmp)

    def _assert_kernel_routes_up(router, msg):
        _assert_kernel_routes(router, msg, {})

    def _assert_kernel_routes_down(router, msg):
        _assert_kernel_routes(router, msg, None)

    def _assert_zebra_kernel_routes(router, msg, val):
        expected = _get_routes_dict(val)
        test_func = partial(
            topotest.router_json_cmp, router, "show ip route json", expected
        )
        result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assert result, msg.format(_)

    def _assert_zebra_kernel_routes_up(router, msg):
        _assert_zebra_kernel_routes(router, msg, [])

    def _assert_zebra_kernel_routes_down(router, msg):
        _assert_zebra_kernel_routes(router, msg, None)

    # Prepare scene: create dummy interface
    # add two addresses, two routes
    create_interface_in_kernel(tgen, router.name, ifname)
    create_address_on_interface(tgen, router.name, ifname, "192.168.0.2/24")
    create_address_on_interface(tgen, router.name, ifname, "192.168.100.7/24")
    router.run(f"ip -4 route add 203.0.113.0/24 via 192.168.0.1")
    router.run(f"ip -4 route add 10.0.170.0/24 dev {ifname}")

    _assert_kernel_routes_up(
        router, "Unexpected kernel behaviour: routes should have been added:\n{}"
    )
    _assert_zebra_kernel_routes_up(router, "Expected zebra to add kernel routes:\n{}")

    # Delete one of two addresses, nothing should change
    router.run(f"ip -4 addr del 192.168.0.2/24 dev {ifname}")

    _assert_kernel_routes_up(
        router,
        "Unexpected kernel behaviour: routes should have been unchanged after not last address deletion:\n{}",
    )
    _assert_zebra_kernel_routes_up(
        router,
        "Expected zebra not to change kernel routes after not last address deletion:\n{}",
    )

    # Delete last address, all routes should be gone
    router.run(f"ip -4 addr del 192.168.100.7/24 dev {ifname}")
    _assert_kernel_routes_down(
        router,
        "Unexpected kernel behaviour: routes should have been deleted after last address deletion:\n{}",
    )
    _assert_zebra_kernel_routes_down(
        router,
        "Expected zebra to delete kernel routes after last address deletion:\n{}",
    )


def _get_early_route_metaq_current(router):
    """Return Early Route Processing count from 'show zebra metaq json'."""
    try:
        output = router.vtysh_cmd("show zebra metaq json")
        metaq = json.loads(output)
        for subqueue in metaq["subqueues"]:
            if subqueue["SubQ"] == "Early Route Processing":
                return subqueue["Current"]
    except (KeyError, json.JSONDecodeError, TypeError) as err:
        logger.info("Failed to parse metaq json: %s", err)
    return None


def test_zebra_metaq_early_route_table_discriminator():
    "Local route must not remove a same-prefix kernel route in another table"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    ifname = "dummy0"
    prefix = "192.0.2.99/32"
    table_id = 198

    step("Create dummy0")
    router.run(f"ip link del dev {ifname} >/dev/null 2>&1 || true")
    create_interface_in_kernel(tgen, router.name, ifname)

    step("Wait for zebra to finish handling dummy0 up")

    def _dummy0_up_handled():
        # IPv6 link-local install after link-up is asynchronous. Wait until zebra
        # has the connected route installed (early-route work for up is done) and
        # the early-route metaQ is empty before plugging it.
        try:
            routes = json.loads(router.vtysh_cmd("show ipv6 route connected json"))
        except (json.JSONDecodeError, TypeError) as err:
            return "failed to parse ipv6 connected routes: {}".format(err)

        found_ll = False
        for route_prefix, entries in routes.items():
            if not route_prefix.startswith("fe80:"):
                continue
            for entry in entries:
                for nh in entry.get("nexthops", []):
                    if nh.get("interfaceName") == ifname:
                        found_ll = True
                        break
                if found_ll:
                    break
            if found_ll:
                break
        if not found_ll:
            return "waiting for zebra IPv6 link-local connected route on {}".format(
                ifname
            )

        count = _get_early_route_metaq_current(router)
        if count is None:
            return "failed to read early-route metaq"
        if count != 0:
            return (
                "early-route metaq still draining after dummy0 up, current={}".format(
                    count
                )
            )
        return None

    _, result = topotest.run_and_expect(_dummy0_up_handled, None, count=20, wait=1)
    assert result is None, result

    step("Plug the meta queue so early routes remain visible")
    router.vtysh_cmd("zebra test metaq disable")

    step("Add the table-198 kernel route")
    router.run(f"ip route add {prefix} dev {ifname} table {table_id}")

    step("Wait for the kernel route to land on the early-route metaQ")

    def _kernel_on_early_metaq():
        count = _get_early_route_metaq_current(router)
        if count != 1:
            return "expected 1 early-route entry after kernel add, got {}".format(count)
        return None

    _, result = topotest.run_and_expect(_kernel_on_early_metaq, None, count=20, wait=1)
    assert result is None, result

    step("Immediately add the same /32 as a local address on dummy0")
    router.run(f"ip address add {prefix} dev {ifname}")

    step("Verify the table-198 kernel route stayed on the early-route metaQ")

    def _kernel_still_on_early_metaq():
        count = _get_early_route_metaq_current(router)
        # kernel(table 198) + connected(unicast+multicast) + local(unicast+multicast)
        if count != 5:
            return (
                "expected 5 early-route entries after local add "
                "(kernel + connected + local, each in unicast and multicast), got {}".format(
                    count
                )
            )
        return None

    _, result = topotest.run_and_expect(
        _kernel_still_on_early_metaq, None, count=20, wait=1
    )
    assert (
        result is None
    ), "connected_up removed the wrong kernel route from early-route metaQ: {}".format(
        result
    )

    step("Unplug the meta queue and verify both routes install")
    router.vtysh_cmd("no zebra test metaq disable")

    kernel = "{}/r1/ip_route_table198_kernel.json".format(CWD)
    expected = json.loads(open(kernel).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip route table {} {} json".format(table_id, prefix),
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert (
        result is None
    ), "Kernel route missing from table {} after metaQ drain".format(table_id)

    def _check_local_installed():
        local_output = json.loads(
            router.vtysh_cmd("show ip route {} json".format(prefix))
        )
        if prefix not in local_output:
            return "local route {} missing from main table".format(prefix)
        if not any(e.get("protocol") == "local" for e in local_output[prefix]):
            return "expected local route for {} in main table".format(prefix)
        return None

    _, result = topotest.run_and_expect(_check_local_installed, None, count=20, wait=1)
    assert result is None, result


def test_zebra_kernel_last_ipv6_address_deleted():
    "Test that both kernel and FRR don't delete route when last address is deleted for IPv6"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    ifname = "dummy0"

    def _get_routes_dict(val):
        return {
            "2001:db8:c::/64": val,
            "2001:db8:d::/64": val,
        }

    def _assert_kernel_routes(router, msg, val):
        routes = topotest.ip6_route(router)
        expected = _get_routes_dict(val)
        cmp = topotest.json_cmp(routes, expected)
        assert cmp is None, msg.format(cmp)

    def _assert_kernel_routes_up(router, msg):
        _assert_kernel_routes(router, msg, {})

    def _assert_kernel_routes_down(router, msg):
        _assert_kernel_routes(router, msg, None)

    def _assert_zebra_kernel_routes(router, msg, val):
        expected = _get_routes_dict(val)
        test_func = partial(
            topotest.router_json_cmp, router, "show ipv6 route json", expected
        )
        result, _ = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assert result, msg.format(_)

    def _assert_zebra_kernel_routes_up(router, msg):
        _assert_zebra_kernel_routes(router, msg, [])

    def _assert_zebra_kernel_routes_down(router, msg):
        _assert_zebra_kernel_routes(router, msg, None)

    # Prepare scene: create dummy interface
    # add two addresses, two routes
    create_interface_in_kernel(tgen, router.name, ifname)
    # clear scope link address
    router.run(f"ip -6 addr flush dev {ifname}")
    create_address_on_interface(tgen, router.name, ifname, "2001:db8:a::2/64")
    create_address_on_interface(tgen, router.name, ifname, "2001:db8:b::7/64")
    router.run(f"ip -6 route add 2001:db8:c::/64 via 2001:db8:a::1")
    router.run(f"ip -6 route add 2001:db8:d::/64 dev {ifname}")

    _assert_kernel_routes_up(
        router, "Unexpected kernel behaviour: routes should have been added:\n{}"
    )
    _assert_zebra_kernel_routes_up(router, "Expected zebra to add kernel routes:\n{}")

    # Delete one of two addresses, nothing should change
    router.run(f"ip -6 addr del 2001:db8:a::2/64 dev {ifname}")

    _assert_kernel_routes_up(
        router,
        "Unexpected kernel behaviour: routes should have been unchanged after first IPv6 address deletion:\n{}",
    )
    _assert_zebra_kernel_routes_up(
        router,
        "Expected zebra not to change kernel routes after first IPv6 address deletion:\n{}",
    )

    # Delete last address, but no route changes for IPv6
    router.run(f"ip -6 addr del 2001:db8:b::7/64 dev {ifname}")
    _assert_kernel_routes_up(
        router,
        "Unexpected kernel behaviour: routes should NOT have been deleted after last IPv6 address deletion:\n{}",
    )
    _assert_zebra_kernel_routes_up(
        router,
        "Expected zebra NOT to delete kernel routes after last IPv6 address deletion:\n{}",
    )

    # Delete IPv6 routes manually:
    router.run(f"ip -6 route del 2001:db8:c::/64 via 2001:db8:a::1")
    router.run(f"ip -6 route del 2001:db8:d::/64 dev {ifname}")
    _assert_kernel_routes_down(
        router,
        "Unexpected kernel behaviour: routes should have been deleted:\n{}",
    )
    _assert_zebra_kernel_routes_down(
        router,
        "Expected zebra to delete kernel routes after manual IPv6 routes deletion:\n{}",
    )


def test_zebra_ipv6_dad_kernel_route():
    "Test that a kernel route is deleted in favor of the connected one (IPv6 with DAD enabled)"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("sysctl -w net.ipv6.conf.r1-eth0.accept_dad=1")
    router.run("ip -6 address add 2001:db8:dead:beef::1/64 dev r1-eth0")

    def _check_duplicated_kernel_route():
        try:
            routes = json.loads(router.vtysh_cmd("show ipv6 route json"))
        except (json.JSONDecodeError, TypeError) as err:
            return "failed to parse ipv6 routes: {}".format(err)

        found_connected = False
        for route_prefix, entries in routes.items():
            if not route_prefix == "2001:db8:dead:beef::/64":
                continue
            for entry in entries:
                if entry.get("protocol") == "connected":
                    found_connected = True
                elif entry.get("protocol") == "kernel":
                    return "found ipv6 kernel route"

        if not found_connected:
            return "ipv6 connected route not found"
        return None

    step("IPv6 with DAD enabled: check for duplicated kernel route")
    _, result = topotest.run_and_expect(
        _check_duplicated_kernel_route, None, count=20, wait=1
    )
    assert result is None, result


#
# Kernel routes on link down and link up.
#
# Linux removes the routes over an interface that goes down without telling
# zebra, so zebra removes its copy of them itself: it goes through its kernel
# routes and deletes the ones with no nexthop left alive. Routes that come
# back afterwards must be tracked again, so a second flap removes them too.
#

KR_VRF = "kvrf"
KR_VRF_TABLE = 1300
KR_TABLE = 1400

# name: (show command, prefix)
KR_ROUTES = {
    "v4": ("show ip route json", "198.51.100.0/24"),
    "v6": ("show ipv6 route json", "2001:db8:100::/64"),
    "other-if": ("show ip route json", "198.51.101.0/24"),
    "multipath": ("show ip route json", "198.51.102.0/24"),
    "vrf": ("show ip route vrf {} json".format(KR_VRF), "198.51.103.0/24"),
    "table": ("show ip route table {} json".format(KR_TABLE), "198.51.104.0/24"),
}

KR_ADD = {
    "v4": "ip route add 198.51.100.0/24 via 192.168.60.2 dev kr0",
    "v6": "ip -6 route add 2001:db8:100::/64 via 2001:db8:60::2 dev kr0",
    "other-if": "ip route add 198.51.101.0/24 via 192.168.61.2 dev kr1",
    "multipath": "ip route add 198.51.102.0/24 nexthop via 192.168.60.2 dev kr0 "
    "nexthop via 192.168.61.2 dev kr1",
    "vrf": "ip route add 198.51.103.0/24 via 192.168.62.2 dev kr2 vrf {}".format(
        KR_VRF
    ),
    "table": "ip route add 198.51.104.0/24 via 192.168.60.2 dev kr0 table {}".format(
        KR_TABLE
    ),
}


def _kr_in_zebra(router, name):
    cmd, prefix = KR_ROUTES[name]
    routes = json.loads(router.vtysh_cmd(cmd)).get(prefix, [])
    return any(r.get("protocol") == "kernel" for r in routes)


def _kr_expect(router, present):
    "None once zebra has exactly the kernel routes named in 'present'."

    def check():
        seen = {name: _kr_in_zebra(router, name) for name in KR_ROUTES}
        wrong = {n: v for n, v in seen.items() if v != (n in present)}
        return wrong or None

    _, result = topotest.run_and_expect(check, None, count=30, wait=0.5)
    assert result is None, "kernel routes in zebra, expected {}: wrong {}".format(
        sorted(present), result
    )


def _kr_tracked(router):
    "Kernel routes zebra keeps in its kernel route set."
    # vtysh nests each daemon's memory groups under the daemon's name
    out = json.loads(router.vtysh_cmd("show memory zebra json"))
    for mt in out.get("zebra", {}).get("zebra", []):
        if mt["name"] == "RIB kernel route":
            return mt["currentAllocations"]
    return 0


def _kr_expect_tracked(router, count):
    _, result = topotest.run_and_expect(
        partial(_kr_tracked, router), count, count=30, wait=0.5
    )
    assert result == count, "zebra tracks {} kernel routes, expected {}".format(
        result, count
    )


def test_zebra_kernel_routes_link_flap():
    "Kernel routes over a downed link are removed, and tracked again when re-added"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    router.run(
        "ip link add kr0 type dummy && ip link set kr0 up && "
        "ip addr add 192.168.60.1/24 dev kr0 && "
        "ip addr add 2001:db8:60::1/64 dev kr0 nodad && "
        "ip link add kr1 type dummy && ip link set kr1 up && "
        "ip addr add 192.168.61.1/24 dev kr1 && "
        "ip link add {0} type vrf table {1} && ip link set {0} up && "
        "ip link add kr2 type dummy && ip link set kr2 master {0} && "
        "ip link set kr2 up && ip addr add 192.168.62.1/24 dev kr2".format(
            KR_VRF, KR_VRF_TABLE
        )
    )
    # kernel routes left by the other tests in this module
    tracked = _kr_tracked(router)

    try:
        step("Every kernel route is in zebra and in its kernel route set")
        for cmd in KR_ADD.values():
            router.run(cmd)
        _kr_expect(router, set(KR_ROUTES))
        _kr_expect_tracked(router, tracked + len(KR_ROUTES))

        step("Link down removes only the routes with no nexthop left alive")
        router.run("ip link set kr0 down")
        _kr_expect(router, {"other-if", "multipath", "vrf"})
        _kr_expect_tracked(router, tracked + 3)

        step("Link up brings nothing back: Linux doesn't restore the routes")
        router.run("ip link set kr0 up")
        router.run("ip addr add 2001:db8:60::1/64 dev kr0 nodad 2>/dev/null; true")
        _kr_expect(router, {"other-if", "multipath", "vrf"})
        assert not router.run("ip route show 198.51.100.0/24").strip()

        step("Re-added and replaced routes are tracked: a second flap removes them")
        for name in ("v4", "v6", "table"):
            router.run(KR_ADD[name])
        router.run("ip route replace 198.51.101.0/24 via 192.168.61.3 dev kr1")
        _kr_expect(router, set(KR_ROUTES))
        _kr_expect_tracked(router, tracked + len(KR_ROUTES))
        router.run("ip link set kr0 down")
        _kr_expect(router, {"other-if", "multipath", "vrf"})

        step("The replaced route and the multipath route go once kr1 is down too")
        router.run("ip link set kr1 down")
        _kr_expect(router, {"vrf"})

        step("A kernel route deleted from Linux by hand leaves the set as well")
        router.run("ip link set kr1 up")
        router.run(KR_ADD["other-if"])
        _kr_expect(router, {"other-if", "vrf"})
        router.run("ip route del 198.51.101.0/24")
        _kr_expect(router, {"vrf"})
        _kr_expect_tracked(router, tracked + 1)

        step("A link down in a vrf removes its route; the set is back to the start")
        router.run("ip link set kr2 down")
        _kr_expect(router, set())
        _kr_expect_tracked(router, tracked)
    finally:
        router.run(
            "ip link del kr0; ip link del kr1; ip link del kr2; "
            "ip link del {}; true".format(KR_VRF)
        )


def test_zebra_kernel_routes_read_at_startup():
    "Kernel routes already in Linux when zebra starts are tracked and removed on link down"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    router.run(
        "ip link add kr0 type dummy && ip link set kr0 up && "
        "ip addr add 192.168.60.1/24 dev kr0"
    )
    try:
        step("A kernel route added while zebra is down is read when zebra starts")
        kill_router_daemons(tgen, "r1", ["zebra"], save_config=False)
        router.run(KR_ADD["v4"])
        start_router_daemons(tgen, "r1", ["zebra"])
        _kr_expect(router, {"v4"})
        tracked = _kr_tracked(router)
        assert tracked >= 1, "zebra does not track the kernel route read at startup"

        step("Link down removes the route read at startup, like any other")
        router.run("ip link set kr0 down")
        _kr_expect(router, set())
        _kr_expect_tracked(router, tracked - 1)
    finally:
        router.run("ip link del kr0; true")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
