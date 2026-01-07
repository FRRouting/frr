#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_static_route_blackhole():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_static_routes():
        output = json.loads(r1.vtysh_cmd("show ip route json"))
        expected = {
            "10.0.0.1/32": [
                {
                    "protocol": "static",
                    "nexthops": [
                        {
                            "blackhole": True,
                        }
                    ],
                }
            ],
            "10.0.0.2/32": [
                {
                    "protocol": "static",
                    "nexthops": [
                        {
                            "reject": True,
                        }
                    ],
                }
            ],
            "10.0.0.3/32": [
                {
                    "protocol": "static",
                    "nexthops": [
                        {
                            "blackhole": True,
                        }
                    ],
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _check_static_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see expected static routes"

    # Try to delete blackhole static routes with a wrong blackhole types.
    # The routes should not be deleted.
    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.1/32 reject
        no ip route 10.0.0.2/32 blackhole
        no ip route 10.0.0.3/32 reject
        """
    )

    test_func = functools.partial(
        _check_static_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see expected static routes"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
