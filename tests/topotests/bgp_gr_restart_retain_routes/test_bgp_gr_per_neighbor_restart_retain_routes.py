#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if routes are retained during BGP restarts using
 Graceful Restart per-neighbor.
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step, stop_router

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


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


def test_bgp_gr_restart_retain_routes():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r4 = tgen.gears["r4"]

    def _bgp_converge():
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 neighbors 192.168.34.3 json"))
        expected = {
            "192.168.34.3": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_bgp_retained_routes():
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 unicast 172.16.255.3/32 json"))
        expected = {"paths": [{"stale": True}]}
        return topotest.json_cmp(output, expected)

    def _bgp_check_kernel_retained_routes():
        output = json.loads(
            r4.cmd("ip -j route show 172.16.255.3/32 proto bgp dev r4-eth0")
        )
        expected = [{"dst": "172.16.255.3", "gateway": "192.168.34.3", "metric": 20}]
        return topotest.json_cmp(output, expected)

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R4"

    step("Restart R3")
    stop_router(tgen, "r3")

    step("Check if routes (BGP) are retained at R4")
    test_func = functools.partial(_bgp_check_bgp_retained_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP retained routes on R4"

    step("Check if routes (Kernel) are retained at R4")
    assert (
        _bgp_check_kernel_retained_routes() is None
    ), "Failed to retain BGP routes in kernel on R4"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
