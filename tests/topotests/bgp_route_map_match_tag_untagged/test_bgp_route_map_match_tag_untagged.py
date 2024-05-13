#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

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
    for routern in range(1, 2):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_route_map_match_tag_untagged():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_advertised_routes_r2():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp ipv4 unicast detail json")
        )
        expected = {
            "routes": {
                "10.10.10.10/32": [
                    {
                        "tag": 10,
                    }
                ],
                "10.10.10.20/32": [
                    {
                        "tag": None,
                    }
                ],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_advertised_routes_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Tags for static routes are not as expected"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
