#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_kernel_route_order.py
#
# Copyright (c) 2026 by Max Makarov <maxpain@linux.com>
#
# A kernel route has to be handled after the interface and address events
# the kernel generated before it. With the dplane results plugged, zebra
# receives the route while the new VRF, the port being enslaved to it and
# the port address are still queued; once unplugged, the route must end up
# selected in that VRF. Route withdrawals and kernel nexthop objects go
# through the same path and are checked the same way. The plug command only
# exists in development builds, elsewhere the tests are skipped.
#

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

VRF = "vrf-order"
TABLE = 1100
PORT = "order0"
PEER = "order0p"
PREFIX = "198.51.100.7/32"
PREFIX_NHG = "198.51.100.8/32"
NHID = 90000
NHID_UNUSED = 90001


def build_topo(tgen):
    "Build single router topology"
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Set up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Tear down the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _vrf_kernel_route_selected(router):
    output = router.vtysh_cmd(
        "show ip route vrf {} {} json".format(VRF, PREFIX), isjson=True
    )
    expected = {
        PREFIX: [
            {
                "protocol": "kernel",
                "vrfName": VRF,
                "selected": True,
                "installed": True,
                "nexthops": [{"interfaceName": PORT, "active": True}],
            }
        ]
    }
    return topotest.json_cmp(output, expected)


def _vrf_routes_cmp(router, expected):
    output = router.vtysh_cmd("show ip route vrf {} json".format(VRF), isjson=True)
    return topotest.json_cmp(output, expected)


def _nhg_cmp(router, nhid, expected):
    output = router.vtysh_cmd(
        "show nexthop-group rib {} json".format(nhid), isjson=True
    )
    return topotest.json_cmp(output, expected)


def _plugged(router, commands):
    output = router.vtysh_cmd("zebra test dplane disable results")
    if "Unknown command" in output:
        pytest.skip("zebra test dplane commands require a development build")
    try:
        for command in commands:
            router.cmd_raises(command)
    finally:
        router.vtysh_cmd("no zebra test dplane disable results")


def test_zebra_kernel_route_after_interface_events():
    "Kernel route in a new VRF is kept when interface events are delayed"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Add a VRF, a port in it, an address and a kernel route, plugged")
    _plugged(
        r1,
        [
            "ip link add {} type vrf table {}".format(VRF, TABLE),
            "ip link set {} up".format(VRF),
            "ip link add {} type veth peer name {}".format(PORT, PEER),
            "ip link set {} master {}".format(PORT, VRF),
            "ip link set {} up".format(PORT),
            "ip address add 169.254.0.1/32 dev {}".format(PORT),
            "ip route add {} dev {} table {} proto static scope link".format(
                PREFIX, PORT, TABLE
            ),
            "ip link set {} up".format(PEER),
        ],
    )

    step("The kernel route is selected in the VRF")
    test_func = partial(_vrf_kernel_route_selected, r1)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Kernel route {} is not selected in {}:\n{}".format(
        PREFIX, VRF, result
    )


def test_zebra_kernel_route_withdraw_and_nexthop_object():
    "Route withdrawal and kernel nexthop objects are handled in order"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Replace the route with one using a kernel nexthop object")
    _plugged(
        r1,
        [
            "ip route del {} dev {} table {}".format(PREFIX, PORT, TABLE),
            "ip nexthop add id {} dev {}".format(NHID, PORT),
            "ip route add {} nhid {} table {} proto static".format(
                PREFIX_NHG, NHID, TABLE
            ),
        ],
    )

    expected = {
        PREFIX: None,
        PREFIX_NHG: [
            {
                "protocol": "kernel",
                "selected": True,
                "installed": True,
                "nexthops": [{"interfaceName": PORT, "active": True}],
            }
        ],
    }
    test_func = partial(_vrf_routes_cmp, r1, expected)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Unexpected routes in {}:\n{}".format(VRF, result)

    test_func = partial(_nhg_cmp, r1, NHID, {str(NHID): {"type": "kernel"}})
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Kernel nexthop object {} is missing:\n{}".format(
        NHID, result
    )

    step("Remove the route using the kernel nexthop object")
    _plugged(r1, ["ip route del {} table {}".format(PREFIX_NHG, TABLE)])

    test_func = partial(_vrf_routes_cmp, r1, {PREFIX_NHG: None})
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Route {} is still in {}:\n{}".format(
        PREFIX_NHG, VRF, result
    )

    step("Add and then remove a kernel nexthop object no route uses")
    _plugged(r1, ["ip nexthop add id {} dev {}".format(NHID_UNUSED, PORT)])

    expected = {str(NHID_UNUSED): {"type": "kernel"}}
    test_func = partial(_nhg_cmp, r1, NHID_UNUSED, expected)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Kernel nexthop object {} is missing:\n{}".format(
        NHID_UNUSED, result
    )

    _plugged(r1, ["ip nexthop del id {}".format(NHID_UNUSED)])

    test_func = partial(_nhg_cmp, r1, NHID_UNUSED, {str(NHID_UNUSED): None})
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Kernel nexthop object {} is still present:\n{}".format(
        NHID_UNUSED, result
    )
