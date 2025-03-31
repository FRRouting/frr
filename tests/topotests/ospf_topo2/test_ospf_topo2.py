#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_topo2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_topo2.py: Test correct route removal.

Proofs the following issue:
https://github.com/FRRouting/frr/issues/14488

"""

import ipaddress
import json
import pytest
import sys
import time

from lib.topogen import Topogen


pytestmark = [
    pytest.mark.ospf6d,
    pytest.mark.ospfd,
]


def build_topo(tgen):
    """Build the topology used by all tests below."""

    # Create 4 routers
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")
    r4 = tgen.add_router("r4")

    # The r1/r2 and r3/r4 router pairs have two connections each
    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")
    tgen.add_link(r1, r2, ifname1="eth2", ifname2="eth2")
    tgen.add_link(r3, r4, ifname1="eth2", ifname2="eth2")
    tgen.add_link(r3, r4, ifname1="eth3", ifname2="eth3")

    # The r1/r4 and r2/r3 router pairs have one connection each
    tgen.add_link(r1, r4, ifname1="eth3", ifname2="eth1")
    tgen.add_link(r2, r3, ifname1="eth3", ifname2="eth1")


@pytest.fixture(scope="function")
def tgen(request):
    """Setup/Teardown the environment and provide tgen argument to tests.

    Do this once per function as some of the tests will leave the router
    in an unclean state.

    """

    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()

    yield tgen

    tgen.stop_topology()


def ospf_neighbors(router, ip_version):
    """List the OSPF neighbors for the given router and IP version."""

    if ip_version == 4:
        cmd = "show ip ospf neighbor json"
    else:
        cmd = "show ipv6 ospf neighbor json"

    output = router.vtysh_cmd(cmd)

    if ip_version == 4:
        return [v for n in json.loads(output)["neighbors"].values() for v in n]
    else:
        return json.loads(output)["neighbors"]


def ospf_neighbor_uptime(router, interface, ip_version):
    """Uptime of the neighbor with the given interface name in seconds."""

    for neighbor in ospf_neighbors(router, ip_version):
        if ip_version == 4:
            if not neighbor["ifaceName"].startswith("{}:".format(interface)):
                continue

            return neighbor["upTimeInMsec"] / 1000
        else:
            if neighbor["interfaceName"] != interface:
                continue

            h, m, s = [int(d) for d in neighbor["duration"].split(":")]
            return h * 3600 + m * 60 + s

    raise KeyError(
        "No IPv{} neighbor with interface name {} on {}".format(
            ip_version, interface, router.name
        )
    )


def ospf_routes(router, prefix):
    """List the OSPF routes for the given router and prefix."""

    if ipaddress.ip_interface(prefix).ip.version == 4:
        cmd = "show ip route {} json"
    else:
        cmd = "show ipv6 route {} json"

    output = router.vtysh_cmd(cmd.format(prefix))
    return json.loads(output)[prefix]


def ospf_nexthops(router, prefix, protocol):
    """List the OSPF nexthops for the given prefix."""

    for route in ospf_routes(router, prefix):
        if route["protocol"] != protocol:
            continue

        for nexthop in route["nexthops"]:
            yield nexthop


def ospf_directly_connected_interfaces(router, ip_version):
    """The names of the directly connected interfaces, as discovered
    through the OSPF nexthops.

    """

    if ip_version == 4:
        prefix = "192.0.2.{}/32".format(router.name.strip("r"))
    else:
        prefix = "fe80::/64"

    hops = ospf_nexthops(router, prefix, protocol="connected")
    return sorted([n["interfaceName"] for n in hops if n["directlyConnected"]])


def wait_for_ospf(router, ip_version, neighbors, timeout=60):
    """Wait until the router has the given number of neighbors that are
    fully converged.

    Note that this checks for the exact number of neighbors, so if one neighbor
    is requested and three are converged, the wait continues.

    """

    until = time.monotonic() + timeout

    if ip_version == 4:
        filter = {"converged": "Full"}
    else:
        filter = {"state": "Full"}

    def is_match(neighbor):
        for k, v in filter.items():
            if neighbor[k] != v:
                return False

        return True

    while time.monotonic() < until:
        found = sum(1 for n in ospf_neighbors(router, ip_version) if is_match(n))

        if neighbors == found:
            return

    raise TimeoutError(
        "Waited over {}s for {} neighbors to reach {}".format(
            timeout, neighbors, filter
        )
    )


@pytest.mark.parametrize("ip_version", [4, 6])
def test_interface_up(tgen, ip_version):
    """Verify the initial routing table, before any changes."""

    # Wait for the routers to be ready
    routers = {id: tgen.gears[id] for id in ("r1", "r2", "r3", "r4")}

    for router in routers.values():
        wait_for_ospf(router, ip_version=ip_version, neighbors=3)

    # Verify that the link-local routes are correct
    for router in routers.values():
        connected = ospf_directly_connected_interfaces(router, ip_version)

        if ip_version == 4:
            expected = ["eth1", "eth2", "eth3", "lo"]
        else:
            expected = ["eth1", "eth2", "eth3"]

        assert (
            connected == expected
        ), "Expected all interfaces to be connected on {}".format(router.name)


@pytest.mark.parametrize("ip_version", [4, 6])
def test_interface_down(tgen, ip_version):
    """Verify the routing table after taking interfaces down."""

    # Wait for the routers to be ready
    routers = {id: tgen.gears[id] for id in ("r1", "r2", "r3", "r4")}

    for id, router in routers.items():
        wait_for_ospf(router, ip_version=ip_version, neighbors=3)

    # Keep track of the uptime of the eth3 neighbor
    uptime = ospf_neighbor_uptime(routers["r1"], "eth3", ip_version)
    before = time.monotonic()

    # Take the links between r1 and r2 down
    routers["r1"].cmd_raises("ip link set down dev eth1")
    routers["r1"].cmd_raises("ip link set down dev eth2")

    # Wait for OSPF to converge
    wait_for_ospf(routers["r1"], ip_version=ip_version, neighbors=1)

    # The uptime of the unaffected eth3 neighbor should be monotonic
    new_uptime = ospf_neighbor_uptime(routers["r1"], "eth3", ip_version)
    took = round(time.monotonic() - before, 3)

    # IPv6 has a resolution of 1s, for IPv4 some slack is necesssary.
    if ip_version == 4:
        offset = 0.25
    else:
        offset = 1

    assert (
        new_uptime + offset >= uptime + took
    ), "The eth3 neighbor uptime must not decrease"

    # We should only find eth3 once OSPF has converged
    connected = ospf_directly_connected_interfaces(routers["r1"], ip_version)

    if ip_version == 4:
        expected = ["eth3", "lo"]
    else:
        expected = ["eth3"]

    assert connected == expected, "Expected only eth1 and eth2 to be disconnected"


@pytest.mark.parametrize("ip_version", [4, 6])
def test_interface_flap(tgen, ip_version):
    """Verify the routing table after enabling an interface that was down."""

    # Wait for the routers to be ready
    routers = {id: tgen.gears[id] for id in ("r1", "r2", "r3", "r4")}

    for id, router in routers.items():
        wait_for_ospf(router, ip_version=ip_version, neighbors=3)

    # Keep track of the uptime of the eth3 neighbor
    uptime = ospf_neighbor_uptime(routers["r1"], "eth3", ip_version)
    before = time.monotonic()

    # Take the links between r1 and r2 down
    routers["r1"].cmd_raises("ip link set down dev eth1")
    routers["r2"].cmd_raises("ip link set down dev eth2")

    # Wait for OSPF to converge
    wait_for_ospf(routers["r1"], ip_version=ip_version, neighbors=1)

    # Take the links between r1 and r2 up
    routers["r1"].cmd_raises("ip link set up dev eth1")
    routers["r2"].cmd_raises("ip link set up dev eth2")

    # Wait for OSPF to converge
    wait_for_ospf(routers["r1"], ip_version=ip_version, neighbors=3)

    # The uptime of the unaffected eth3 neighbor should be monotonic
    new_uptime = ospf_neighbor_uptime(routers["r1"], "eth3", ip_version)
    took = round(time.monotonic() - before, 3)

    # IPv6 has a resolution of 1s, for IPv4 some slack is necesssary.
    if ip_version == 4:
        offset = 0.25
    else:
        offset = 1

    assert (
        new_uptime + offset >= uptime + took
    ), "The eth3 neighbor uptime must not decrease"

    # We should find all interfaces again
    connected = ospf_directly_connected_interfaces(routers["r1"], ip_version)

    if ip_version == 4:
        expected = ["eth1", "eth2", "eth3", "lo"]
    else:
        expected = ["eth1", "eth2", "eth3"]

    assert connected == expected, "Expected all interfaces to be connected"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
