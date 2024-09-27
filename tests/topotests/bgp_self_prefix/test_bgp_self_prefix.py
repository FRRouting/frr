#!/usr/bin/env python
# SPDX-License-Identifier: ISC

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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


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


def test_bgp_self_prefix():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.0.0.2/32": [
                    {
                        "valid": True,
                        "path": "",
                        "nexthops": [
                            {"ip": "10.0.0.2", "hostname": "r2", "afi": "ipv4"}
                        ],
                    }
                ],
                "10.0.0.3/32": [
                    {
                        "valid": True,
                        "path": "65003",
                        "nexthops": [
                            {"ip": "10.0.0.3", "hostname": "r3", "afi": "ipv4"}
                        ],
                    }
                ],
            }
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    def _bgp_check_received_routes():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.0.0.2/32": [
                    {
                        "valid": True,
                        "bestpath": True,
                        "nexthops": [
                            {"ip": "10.0.0.1", "hostname": "r1", "afi": "ipv4"}
                        ],
                    }
                ],
            }
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_received_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see 10.0.0.2/32"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
