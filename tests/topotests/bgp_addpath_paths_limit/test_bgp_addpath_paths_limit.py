#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if Paths-Limit capability works as expected.
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 8):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r7"])
    switch.add_link(tgen.gears["r2"])


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


def test_bgp_addpath_paths_limit():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r7 = tgen.gears["r7"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.7.7": {
                "neighborCapabilities": {
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 0,
                            "receivedPathsLimit": 3,
                        }
                    }
                }
            },
            "192.168.1.1": {
                "neighborCapabilities": {
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 0,
                            "receivedPathsLimit": 2,
                        }
                    }
                }
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge initially"

    def _bgp_check_received_routes(router, expected):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 172.16.16.254/32 json")
        )

        if "paths" not in output:
            return "No paths received"

        return topotest.json_cmp(len(output["paths"]), expected)

    test_func = functools.partial(_bgp_check_received_routes, r1, 2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Received routes count is not as expected"

    test_func = functools.partial(_bgp_check_received_routes, r7, 3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Received routes count is not as expected"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
