#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Yukie Kawamata <y-kawamata@sakura.ad.jp>
#

"""
Test that addpath-tx-best-selected count is inherited by dynamic peers
created through bgp listen range + peer-group.

Topology: a single switch connects r1 (listener/reflector) with r2-r5.
r1 accepts dynamic peers from 192.0.2.0/24 into peer-group PG, which has
`addpath-tx-best-selected 2`.  r2-r4 each advertise 172.16.16.254/32, so
r1 has three paths.  r5 (also a dynamic peer in PG) must receive the
best path plus two more selected paths (three paths total).
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
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_addpath_best_selected_dynamic_peers():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r5 = tgen.gears["r5"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 172.16.16.254/32 json"))
        expected = {
            "paths": [
                {"aspath": {"string": "65002"}},
                {"aspath": {"string": "65003"}},
                {"aspath": {"string": "65004"}},
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not converge with three paths"

    def _r5_session_established():
        output = json.loads(r5.vtysh_cmd("show bgp neighbor 192.0.2.1 json"))
        expected = {"192.0.2.1": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_r5_session_established)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r5 did not establish dynamic session with r1"

    def _r5_received_addpath_routes():
        output = json.loads(
            r5.vtysh_cmd("show bgp ipv4 neighbors 192.0.2.1 routes json")
        )
        expected = {
            "routes": {
                "172.16.16.254/32": [
                    {"valid": True, "path": "65001 65002"},
                    {"valid": True, "path": "65001 65003"},
                    {"valid": True, "path": "65001 65004"},
                ]
            },
            "totalRoutes": 1,
            "totalPaths": 3,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_r5_received_addpath_routes)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "r5 received wrong number of Add-Path best selected routes (expected best + 2)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
