#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if route-map extcommunity none works:

route-map <name> permit 10
 set extcommunity none
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
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


def test_bgp_extcommunity_none():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _bgp_converge(router):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 172.16.16.1/32 json")
        )
        expected = {
            "prefix": "172.16.16.1/32",
            "paths": [
                {
                    "community": {
                        "string": "123:123",
                    },
                    "extendedCommunity": {"string": "LB:65002:25000000 (200.000 Mbps)"},
                }
            ],
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, router)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "BGP Converge failed"

    def _bgp_extcommunity_strip(router):
        router.vtysh_cmd(
            "conf t\nrouter bgp 65001\naddress-family ipv4\nneighbor 192.168.1.2 route-map r2 in"
        )
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 172.16.16.1/32 json")
        )
        expected = {
            "prefix": "172.16.16.1/32",
            "paths": [
                {
                    "community": {
                        "string": "123:123",
                    },
                    "extendedCommunity": None,
                }
            ],
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_extcommunity_strip, router)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to strip incoming extended communities from r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
