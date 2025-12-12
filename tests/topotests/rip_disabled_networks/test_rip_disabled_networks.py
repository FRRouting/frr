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

pytestmark = [pytest.mark.ripd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_rip_disabled_networks():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    def _show_route_received_r1():
        output = json.loads(r1.vtysh_cmd(f"show ip route 192.168.3.0/24 json"))
        expected = {
            "192.168.3.0/24": [
                {
                    "protocol": "rip",
                    "selected": True,
                    "distance": 120,
                    "installed": True,
                    "internalNextHopNum": 1,
                    "internalNextHopActiveNum": 1,
                    "internalNextHopFibInstalledNum": 1,
                    "nexthops": [
                        {
                            "active": True,
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_route_received_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Didn't receive 192.168.3.0/24"

    def _show_route_received_r3():
        output = json.loads(r3.vtysh_cmd(f"show ip route json"))
        expected = {
            "192.168.1.0/24": None,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_route_received_r3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Received 192.168.1.0/24, but should not"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
