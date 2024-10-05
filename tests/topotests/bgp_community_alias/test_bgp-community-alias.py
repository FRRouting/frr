#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if BGP community alias is visible in CLI outputs
"""

import os
import sys
import json
import pytest
import functools

pytestmark = pytest.mark.bgpd

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


def test_bgp_community_alias():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip route json"))
        expected = {
            "172.16.16.1/32": [
                {
                    "tag": 10,
                    "communities": "community-r2-1 65001:2",
                    "largeCommunities": "large-community-r2-1 65001:1:2",
                }
            ],
            "172.16.16.2/32": [
                {
                    "tag": 20,
                    "communities": "65002:1 community-r2-2",
                    "largeCommunities": "",
                }
            ],
            "172.16.16.3/32": [
                {
                    "tag": 100,
                    "communities": "",
                    "largeCommunities": "",
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see BGP community aliases at r1"

    def _bgp_show_prefixes_by_alias(router):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast alias large-community-r2-1 json detail"
            )
        )
        expected = {
            "routes": {
                "172.16.16.1/32": {
                    "paths": [
                        {
                            "community": {"string": "community-r2-1 65001:2"},
                            "largeCommunity": {
                                "string": "large-community-r2-1 65001:1:2"
                            },
                        }
                    ]
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_show_prefixes_by_alias, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see BGP prefixes by community alias at r1"

    def _bgp_show_prefixes_by_large_community_list(router):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast large-community-list r2 json")
        )
        expected = {"routes": {"172.16.16.1/32": [{"valid": True}]}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_show_prefixes_by_large_community_list, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see BGP prefixes by large community list at r1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
