#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_rip_bfd_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2023 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_rip_bfd_topo1.py: Test RIP BFD integration.
"""

import sys
import re
import pytest

from functools import partial
from lib import topotest
from lib.topogen import Topogen, TopoRouter

pytestmark = [
    pytest.mark.bfdd,
    pytest.mark.ripd,
]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3")}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router_name, router in router_list.items():
        router.load_config(TopoRouter.RD_BFD, "bfdd.conf")
        router.load_config(TopoRouter.RD_RIP, "ripd.conf")
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        if router_name in ["r2", "r3"]:
            router.load_config(TopoRouter.RD_STATIC, "staticd.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    "Test if routers is still running otherwise skip tests"
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def show_rip_json(router):
    "Get router 'show ip rip' JSON output"
    output = router.vtysh_cmd("show ip rip")
    routes = output.splitlines()[6:]
    json = {}

    for route in routes:
        match = re.match(
            r"(.)\((.)\)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)", route
        )
        if match is None:
            continue

        route_entry = {
            "code": match[1],
            "subCode": match[2],
            "nextHop": match[4],
            "metric": int(match[5]),
            "from": match[6],
        }

        if json.get(match[3]) is None:
            json[match[3]] = []

        json[match[3]].append(route_entry)

    return json


def expect_routes(router, routes, time_amount):
    "Expect 'routes' in 'router'."

    def test_function():
        "Internal test function."
        return topotest.json_cmp(show_rip_json(router), routes)

    _, result = topotest.run_and_expect(test_function, None, count=time_amount, wait=1)
    assert result is None, "Unexpected routing table in {}".format(router.name)


def expect_bfd_peers(router, peers):
    "Expect 'peers' in 'router' BFD status."
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bfd peers json",
        peers,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "{} BFD peer status mismatch".format(router)


def test_rip_convergence(tgen):
    "Test that RIP learns the neighbor routes."

    expect_routes(
        tgen.gears["r1"],
        {
            "10.254.254.2/32": [{"code": "R", "subCode": "n", "from": "192.168.0.2"}],
            "10.254.254.3/32": [{"code": "R", "subCode": "n", "from": "192.168.1.2"}],
            "10.254.254.100/32": [
                {
                    "code": "R",
                    "subCode": "n",
                    "from": "192.168.0.2",
                },
                {
                    "code": "R",
                    "subCode": "n",
                    "from": "192.168.1.2",
                },
            ],
        },
        40,
    )

    expect_bfd_peers(
        tgen.gears["r1"],
        [
            {
                "peer": "192.168.0.2",
                "status": "up",
                "receive-interval": 1000,
                "transmit-interval": 1000,
            },
            {
                "peer": "192.168.1.2",
                "status": "up",
                "receive-interval": 1000,
                "transmit-interval": 1000,
            },
        ],
    )

    expect_routes(
        tgen.gears["r2"],
        {
            "10.254.254.1/32": [{"code": "R", "subCode": "n", "from": "192.168.0.1"}],
            "10.254.254.3/32": [{"code": "R", "subCode": "n", "from": "192.168.0.1"}],
            "10.254.254.100/32": [{"code": "S", "subCode": "r", "from": "self"}],
        },
        40,
    )

    expect_bfd_peers(
        tgen.gears["r2"],
        [
            {
                "peer": "192.168.0.1",
                "status": "up",
                "receive-interval": 1000,
                "transmit-interval": 1000,
            }
        ],
    )

    expect_routes(
        tgen.gears["r3"],
        {
            "10.254.254.1/32": [{"code": "R", "subCode": "n", "from": "192.168.1.1"}],
            "10.254.254.2/32": [{"code": "R", "subCode": "n", "from": "192.168.1.1"}],
            "10.254.254.100/32": [{"code": "S", "subCode": "r", "from": "self"}],
        },
        40,
    )

    expect_bfd_peers(
        tgen.gears["r3"],
        [
            {
                "peer": "192.168.1.1",
                "status": "up",
                "receive-interval": 1000,
                "transmit-interval": 1000,
            }
        ],
    )


def test_rip_bfd_convergence(tgen):
    "Test that RIP drop the gone neighbor routes."

    tgen.gears["r3"].link_enable("r3-eth0", False)

    expect_routes(
        tgen.gears["r1"],
        {
            "10.254.254.2/32": [{"code": "R", "subCode": "n", "from": "192.168.0.2"}],
            "10.254.254.3/32": None,
            "10.254.254.100/32": [
                {
                    "code": "R",
                    "subCode": "n",
                    "from": "192.168.0.2",
                }
            ],
        },
        6,
    )

    expect_routes(
        tgen.gears["r3"],
        {
            "10.254.254.1/32": None,
            "10.254.254.2/32": None,
            "10.254.254.100/32": [{"code": "S", "subCode": "r", "from": "self"}],
        },
        6,
    )


def test_memory_leak(tgen):
    "Run the memory leak test and report results."

    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
