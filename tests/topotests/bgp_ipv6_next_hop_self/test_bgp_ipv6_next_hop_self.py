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

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r4"), "s2": ("r1", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_OSPF6, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_ipv6_next_hop_self():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    def _bgp_check_routes_r2():
        output = json.loads(r2.vtysh_cmd("show bgp json"))
        expected = {
            "routes": {
                "2001:db8:1::1/128": [
                    {
                        "nexthops": [
                            {
                                "ip": "2001:db8:1::1",
                                "hostname": "r1",
                                "afi": "ipv6",
                                "scope": "global",
                                "linkLocalOnly": False,
                                "length": 16,
                            }
                        ],
                    }
                ],
                "2001:db8:1::2/128": [
                    {
                        "nexthops": [
                            {
                                "ip": "::",
                                "hostname": "r2",
                                "afi": "ipv6",
                                "scope": "global",
                                "linkLocalOnly": False,
                                "length": 16,
                            }
                        ],
                    }
                ],
                "2001:db8:1::22/128": [
                    {
                        "nexthops": [
                            {
                                "ip": "::",
                                "hostname": "r2",
                                "afi": "ipv6",
                                "scope": "global",
                                "linkLocalOnly": False,
                                "length": 16,
                            }
                        ],
                    }
                ],
                "2001:db8:cafe:1::/64": [
                    {
                        "nexthops": [
                            {
                                "ip": "2001:db8:1::1",
                                "hostname": "r1",
                                "afi": "ipv6",
                                "scope": "global",
                                "linkLocalOnly": False,
                                "length": 16,
                            }
                        ],
                    }
                ],
            },
            "totalRoutes": 4,
            "totalPaths": 4,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_routes_r2,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assert result is None, "Can't see expected IPv6 routes in BGP table of r2"

    def _bgp_check_routes_r4():
        output = json.loads(r4.vtysh_cmd("show bgp json"))
        expected = {
            "routes": {
                "2001:db8:1::1/128": [
                    {
                        "nexthops": [
                            {
                                "ip": "2001:db8:1::1",
                                "hostname": "r1",
                                "afi": "ipv6",
                                "scope": "global",
                                "linkLocalOnly": False,
                                "length": 16,
                            }
                        ],
                    }
                ],
                "2001:db8:1::22/128": [
                    {
                        "nexthops": [
                            {
                                "ip": "2001:db8:1::2",
                                "hostname": "r1",
                                "afi": "ipv6",
                                "scope": "global",
                                "linkLocalOnly": False,
                                "length": 16,
                            }
                        ],
                    }
                ],
                "2001:db8:cafe:1::/64": [
                    {
                        "nexthops": [
                            {
                                "ip": "2001:db8:1::1",
                                "hostname": "r1",
                                "afi": "ipv6",
                                "scope": "global",
                                "linkLocalOnly": False,
                                "length": 16,
                            }
                        ],
                    }
                ],
            },
            "totalRoutes": 3,
            "totalPaths": 3,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_routes_r4,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assert result is None, "Can't see expected IPv6 routes in BGP table of r4"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
