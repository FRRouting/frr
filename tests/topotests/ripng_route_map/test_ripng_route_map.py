#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if route-map for ripng basic functionality works.
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
from lib.common_config import step

pytestmark = [pytest.mark.ripngd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_ripng_route_map():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _show_routes(nh_num):
        output = json.loads(r1.vtysh_cmd("show ipv6 route ripng json"))
        expected = {
            "2001:db8:2::/64": [
                {
                    "metric": 13,
                }
            ],
            "2001:db8:3::/64": [
                {
                    "metric": 14,
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_routes, 2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Got routes, but metric is not set as expected"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
