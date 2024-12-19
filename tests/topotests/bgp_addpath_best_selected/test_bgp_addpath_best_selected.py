#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if Add-Path best selected paths are announced per neighbor.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 8):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r7"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_addpath_best_selected():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r7 = tgen.gears["r7"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 172.16.16.254/32 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "65006",
                    },
                    "weight": 6,
                },
                {
                    "aspath": {
                        "string": "65005",
                    },
                    "weight": 5,
                },
                {
                    "aspath": {
                        "string": "65004",
                    },
                    "weight": 4,
                },
                {
                    "aspath": {
                        "string": "65003",
                    },
                    "weight": 3,
                },
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge initially"

    def r1_check_bgp_received_routes_from_r2():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv4 neighbors 192.168.1.2 routes json")
        )
        expected = {
            "routes": {
                "172.16.16.254/32": [
                    {
                        "valid": True,
                        "path": "65002 65005",
                    },
                    {
                        "valid": True,
                        "path": "65002 65006",
                    },
                ]
            },
            "totalRoutes": 1,
            "totalPaths": 2,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(r1_check_bgp_received_routes_from_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Received more/less Add-Path best paths, but should be ONLY 1+1 (real best path)"

    def r7_check_bgp_received_routes_from_r2():
        output = json.loads(
            r7.vtysh_cmd("show bgp ipv4 neighbors 192.168.7.2 routes json")
        )
        expected = {
            "routes": {
                "172.16.16.254/32": [
                    {
                        "valid": True,
                        "path": "65002 65004",
                    },
                    {
                        "valid": True,
                        "path": "65002 65005",
                    },
                    {
                        "valid": True,
                        "path": "65002 65006",
                    },
                ]
            },
            "totalRoutes": 1,
            "totalPaths": 3,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(r7_check_bgp_received_routes_from_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Received more/less Add-Path best paths, but should be ONLY 2+1 (real best path)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
