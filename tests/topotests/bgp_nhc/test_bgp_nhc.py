#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r2", "r3", "r4", "r5"),
        "s3": ("r1", "r6"),
        "s4": ("r6", "r7"),
        "s5": ("r6", "r8"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_nhc():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 json detail"))
        expected = {
            "routes": {
                "10.0.0.1/32": {
                    "paths": [
                        {
                            "aspath": {
                                "string": "65002 65003",
                            },
                            "valid": True,
                            "nextNextHopNodes": [
                                "10.254.0.3",
                                "10.254.0.4",
                                "10.254.0.5",
                            ],
                            "nexthops": [
                                {
                                    "ip": "10.255.0.2",
                                    "hostname": "r2",
                                    "afi": "ipv4",
                                }
                            ],
                        },
                        {
                            "aspath": {
                                "string": "65006 65007",
                            },
                            "valid": True,
                            "nextNextHopNodes": [
                                "10.254.0.7",
                                "10.254.0.8",
                            ],
                            "nexthops": [
                                {
                                    "ip": "10.255.16.6",
                                    "hostname": "r6",
                                    "afi": "ipv4",
                                }
                            ],
                        },
                    ],
                }
            },
            "totalRoutes": 1,
            "totalPaths": 2,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Can't see Next-next hop Nodes (NHC attribute) for 10.0.0.1/32"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
