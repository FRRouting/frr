#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if we can match BGP prefixes by next-hop which is
specified by an IPv6 Access-list, prefix-list or just an address.
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


def test_bgp_route_map_match_ipv6_next_hop_access_list():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ipv6 route json"))
        expected = {
            "2001:db8:1::1/128": [
                {
                    "communities": "65002:1",
                }
            ],
            "2001:db8:2::1/128": [
                {
                    "communities": "65002:2",
                }
            ],
            "2001:db8:3::1/128": [
                {
                    "communities": "65002:3",
                }
            ],
            "2001:db8:4::1/128": [
                {
                    "communities": "65002:4",
                }
            ],
            "2001:db8:5::1/128": [
                {
                    "communities": "65002:5",
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, router)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't match routes using ipv6 next-hop access-list"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
