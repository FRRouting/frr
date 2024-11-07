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
from lib.common_config import kill_router_daemons

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r2"), "s3": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_addpath_llgr():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast summary json"))
        expected = {
            "peers": {
                "192.168.1.1": {
                    "hostname": "r1",
                    "remoteAs": 65001,
                    "localAs": 65002,
                    "pfxRcd": 1,
                    "state": "Established",
                },
                "192.168.2.1": {
                    "hostname": "r1",
                    "remoteAs": 65001,
                    "localAs": 65002,
                    "pfxRcd": 1,
                    "state": "Established",
                },
                "192.168.3.3": {
                    "hostname": "r3",
                    "remoteAs": 65003,
                    "localAs": 65002,
                    "pfxSnt": 2,
                    "state": "Established",
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Initial peering failed"

    kill_router_daemons(tgen, "r2", ["bgpd"])

    def _bgp_check_stale_llgr_routes():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast 10.0.0.1/32 json"))
        expected = {
            "paths": [
                {
                    "stale": True,
                    "valid": True,
                    "community": {"string": "llgr-stale", "list": ["llgrStale"]},
                },
                {
                    "stale": True,
                    "valid": True,
                    "community": {"string": "llgr-stale", "list": ["llgrStale"]},
                },
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_stale_llgr_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see stale LLGR routes"

    def _bgp_check_stale_routes_cleared():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.0.0.1/32": None,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_stale_routes_cleared,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see stale routes"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
