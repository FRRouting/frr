#!/usr/bin/python
# SPDX-License-Identifier: ISC
#
# test_bgp_roles_filtering.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2022 by Eugene Bogomazov <eb@qrator.net>
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_bgp_roles_filtering: test leaks prevention and mitigation with roles
"""

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.bgpd]


topodef = {f"s{i}": (f"r{i}", "r10") for i in range(1, 8)}


@pytest.fixture(scope="module")
def tgen(request):
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_BGP, "bgpd.conf")
    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def test_r10_routes(tgen):
    # provider-undefine pair bur strict-mode was set
    def _routes_half_converged():
        routes = json.loads(tgen.gears["r10"].vtysh_cmd("show bgp ipv4 json"))["routes"]
        output = sorted(routes.keys())
        expected = [
            "192.0.2.1/32",
            "192.0.2.2/32",
            "192.0.2.3/32",
            "192.0.2.4/32",
            "192.0.2.5/32",
            "192.0.2.6/32",
            "192.0.2.7/32",
        ]
        return output == expected

    success, _ = topotest.run_and_expect(_routes_half_converged, True, count=20, wait=3)
    assert success, "Routes did not converged"

    routes_with_otc = list()
    for number in range(1, 8):
        prefix = f"192.0.2.{number}/32"
        route_details = json.loads(
            tgen.gears["r10"].vtysh_cmd(f"show bgp ipv4 {prefix} json")
        )
        if route_details["paths"][0].get("otc") is not None:
            routes_with_otc.append(prefix)
    assert routes_with_otc == [
        "192.0.2.1/32",
        "192.0.2.2/32",
        "192.0.2.6/32",
        "192.0.2.7/32",
    ]


def test_r1_routes(tgen):
    routes = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp ipv4 json"))["routes"]
    routes_list = sorted(routes.keys())
    assert routes_list == [
        "192.0.2.1/32",  # own
        "192.0.2.3/32",
        "192.0.2.4/32",
        "192.0.2.5/32",
    ]


def test_r6_routes(tgen):
    routes = json.loads(tgen.gears["r6"].vtysh_cmd("show bgp ipv4 json"))["routes"]
    routes_list = sorted(routes.keys())
    assert routes_list == [
        "192.0.2.3/32",
        "192.0.2.4/32",
        "192.0.2.5/32",
        "192.0.2.6/32",  # own
    ]


def test_r4_routes(tgen):
    routes = json.loads(tgen.gears["r4"].vtysh_cmd("show bgp ipv4 json"))["routes"]
    routes_list = sorted(routes.keys())
    assert routes_list == [
        "192.0.2.1/32",
        "192.0.2.2/32",
        "192.0.2.3/32",
        "192.0.2.4/32",
        "192.0.2.5/32",
        "192.0.2.6/32",
        "192.0.2.7/32",
    ]


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
