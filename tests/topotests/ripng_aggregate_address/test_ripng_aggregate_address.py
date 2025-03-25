#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donald Sharp <sharpd@nvidia.com>
#

"""
Test if aggregate-address for ripng basic functionality works.
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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ripngd]


def setup_module(mod):
    topodef = {"s1": ( "r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_ripng_aggregate_address():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    r2 = tgen.gears["r2"]

    def _show_routes(nh_num):
        output = json.loads(r2.vtysh_cmd("show ipv6 route ripng json"))
        expected = {
            "33::/64": [
                {
                    "metric": 2,
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_routes, 2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "No aggregate address received"

    # Turn it off
    r3.vtysh_cmd("conf\nrouter ripng\nno aggregate-address 33::/64")

    def _show_routes_removed(nh_num):
        output = json.loads(r2.vtysh_cmd("show ipv6 route ripng json"))
        expected = {
            "33::1/128": [
                {
                    "metric": 2,
                }
            ],
            "33::2/128": [
                {
                    "metric": 2,
                }
            ],
            "33::3/128": [
                {
                    "metric": 2,
                }
            ],
            "33::4/128": [
                {
                    "metric": 2,
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_routes_removed, 2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Non aggregate routes are not present"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
