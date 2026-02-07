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

pytestmark = [pytest.mark.bgpd]


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


def test_route_map_check_unused():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_unused_route_maps():
        output = json.loads(r1.vtysh_cmd("show route-map-unused json"))
        expected = {
            "zebra": {
                "test1": {
                    "invoked": 0,
                    "disabledOptimization": False,
                    "processedChange": False,
                    "rules": [
                        {
                            "sequenceNumber": 10,
                            "type": "permit",
                            "invoked": 0,
                            "cpuTimeMS": 0,
                            "matchClauses": [],
                            "setClauses": [],
                            "action": "Exit routemap",
                        }
                    ],
                    "cpuTimeMS": 0,
                },
                "test2": {
                    "invoked": 0,
                    "disabledOptimization": False,
                    "processedChange": False,
                    "rules": [
                        {
                            "sequenceNumber": 10,
                            "type": "permit",
                            "invoked": 0,
                            "cpuTimeMS": 0,
                            "matchClauses": [],
                            "setClauses": [],
                            "action": "Exit routemap",
                        }
                    ],
                    "cpuTimeMS": 0,
                },
                "test3": {
                    "invoked": 0,
                    "disabledOptimization": False,
                    "processedChange": False,
                    "rules": [
                        {
                            "sequenceNumber": 10,
                            "type": "permit",
                            "invoked": 0,
                            "cpuTimeMS": 0,
                            "matchClauses": [],
                            "setClauses": [],
                            "action": "Exit routemap",
                        }
                    ],
                    "cpuTimeMS": 0,
                },
                "test4": {
                    "invoked": 0,
                    "disabledOptimization": False,
                    "processedChange": False,
                    "rules": [
                        {
                            "sequenceNumber": 10,
                            "type": "permit",
                            "invoked": 0,
                            "cpuTimeMS": 0,
                            "matchClauses": [],
                            "setClauses": [],
                            "action": "Exit routemap",
                        }
                    ],
                    "cpuTimeMS": 0,
                },
            },
            "bgpd": {},
        }

        return topotest.json_cmp(output, expected, exact=True)

    test_func = functools.partial(_check_unused_route_maps)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "There are some unused route-maps"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
