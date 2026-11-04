#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

#
# test_zebra_kernel_route_iface_down.py
#
# Copyright (c) 2026 Alphalink
#

"""
test_zebra_kernel_route_iface_down.py: when an interface goes down or loses
its last IPv4 address, the kernel removes the routes through it without a
notification. zebra must drop those kernel routes from its RIB, and only
those: the kernel routes through other interfaces stay, including a kernel
route for the same prefix and metric through another interface, and when it
moves to another VRF.
"""

import os
import sys
from functools import partial

import pytest
from lib import topotest
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.staticd]

CWD = os.path.dirname(os.path.realpath(__file__))

# interface: (interface address, kernel route through it)
ROUTES = {
    "dummy1": ("10.10.1.1/24", "10.99.1.1/32"),
    "dummy2": ("10.10.2.1/24", "10.99.2.1/32"),
    "dummy3": ("10.10.3.1/24", "10.99.3.1/32"),
}


@pytest.fixture(scope="module")
def tgen(request):
    "Sets up the pytest environment"

    tgen = Topogen({"s1": ("r1")}, request.module.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    tgen.start_router()

    for ifname, (addr, route) in ROUTES.items():
        r1.cmd("ip link add {} type dummy".format(ifname))
        r1.cmd("ip link set {} up".format(ifname))
        r1.cmd("ip address add {} dev {}".format(addr, ifname))
        r1.cmd("ip route add {} dev {}".format(route, ifname))

    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def kernel_route_present(r1, ifname):
    prefix = ROUTES[ifname][1]
    expected = {
        prefix: [
            {
                "protocol": "kernel",
                "nexthops": [{"interfaceName": ifname, "active": True}],
            }
        ]
    }
    return topotest.router_json_cmp_retry(
        r1, "show ip route {} json".format(prefix), expected, False, 30
    )


def kernel_route_absent(r1, ifname):
    prefix = ROUTES[ifname][1]
    return topotest.router_json_cmp_retry(
        r1, "show ip route {} json".format(prefix), {}, True, 30
    )


def test_kernel_routes_learnt(tgen):
    "The kernel routes of the three interfaces are in the RIB"
    r1 = tgen.gears["r1"]

    for ifname in ROUTES:
        assert kernel_route_present(r1, ifname), "route via {} not learnt".format(
            ifname
        )


def test_interface_down(tgen):
    "An interface going down removes only the kernel routes through it"
    r1 = tgen.gears["r1"]

    r1.cmd("ip link set dummy2 down")

    assert kernel_route_absent(r1, "dummy2"), "route via dummy2 stays"
    for ifname in ("dummy1", "dummy3"):
        assert kernel_route_present(
            r1, ifname
        ), "route via {} lost when dummy2 went down".format(ifname)


def test_last_ipv4_address_deleted(tgen):
    "An interface losing its last IPv4 address removes only its kernel routes"
    r1 = tgen.gears["r1"]

    r1.cmd("ip address del {} dev dummy3".format(ROUTES["dummy3"][0]))

    assert kernel_route_absent(r1, "dummy3"), "route via dummy3 stays"
    assert kernel_route_present(
        r1, "dummy1"
    ), "route via dummy1 lost when dummy3 lost its address"


def kernel_route_interfaces(r1, prefix):
    "Interfaces of the kernel routes of the prefix in the RIB, sorted"
    routes = r1.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
    return sorted(
        nexthop["interfaceName"]
        for route in routes.get(prefix, [])
        if route["protocol"] == "kernel"
        for nexthop in route["nexthops"]
    )


def test_same_prefix_other_interface(tgen):
    "The dead route is dropped by its nexthop, not by its prefix"
    r1 = tgen.gears["r1"]
    prefix = "10.99.4.1/32"

    # The kernel holds two routes for one prefix and metric when their tos
    # differ; zebra ignores the tos and keeps two kernel entries. The newer
    # one, through dummy5, is first in the RIB: a delete by prefix and
    # metric alone would remove it instead of the dead one through dummy4.
    for ifname, addr in (("dummy4", "10.10.4.1/24"), ("dummy5", "10.10.5.1/24")):
        r1.cmd("ip link add {} type dummy".format(ifname))
        r1.cmd("ip link set {} up".format(ifname))
        r1.cmd("ip address add {} dev {}".format(addr, ifname))
    r1.cmd("ip route add {} dev dummy4 metric 100".format(prefix))
    r1.cmd("ip route add {} tos 0x10 dev dummy5 metric 100".format(prefix))

    test_func = partial(kernel_route_interfaces, r1, prefix)
    _, result = topotest.run_and_expect(test_func, ["dummy4", "dummy5"], 30, 1)
    assert result == ["dummy4", "dummy5"], "two kernel routes expected, got {}".format(
        result
    )

    r1.cmd("ip link set dummy4 down")

    _, result = topotest.run_and_expect(test_func, ["dummy5"], 30, 1)
    assert result == ["dummy5"], "kernel routes after dummy4 went down: {}".format(
        result
    )


def test_interface_moved_to_vrf(tgen):
    "A kernel route leaves the RIB when its interface moves to another VRF"
    r1 = tgen.gears["r1"]

    r1.cmd("ip link add dummy7 type dummy")
    r1.cmd("ip link set dummy7 up")
    r1.cmd("ip address add 10.10.7.1/24 dev dummy7")
    r1.cmd("ip route add 10.99.7.1/32 dev dummy7")
    present = {"10.99.7.1/32": [{"protocol": "kernel"}]}
    assert topotest.router_json_cmp_retry(
        r1, "show ip route 10.99.7.1/32 json", present, False, 30
    ), "kernel route missing before the move"

    r1.cmd("ip link add RED type vrf table 1001")
    r1.cmd("ip link set RED up")
    r1.cmd("ip link set dummy7 master RED")

    moved = {"10.10.7.0/24": [{"protocol": "connected"}]}
    assert topotest.router_json_cmp_retry(
        r1, "show ip route vrf RED 10.10.7.0/24 json", moved, False, 30
    ), "dummy7 did not move to RED"
    assert topotest.router_json_cmp_retry(
        r1, "show ip route 10.99.7.1/32 json", {}, True, 30
    ), "kernel route of the default VRF stays after dummy7 moved to RED"


def test_memory_leak(tgen):
    "Run the memory leak test and report results."
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
