#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if routes are retained during BGP restarts.
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
from lib.common_config import step, stop_router

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
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


def test_bgp_gr_restart_retain_routes():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 neighbors 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_bgp_retained_routes():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 172.16.255.1/32 json"))
        expected = {"paths": [{"stale": True}]}
        return topotest.json_cmp(output, expected)

    def _bgp_check_kernel_retained_routes():
        output = json.loads(
            r2.cmd("ip -j route show 172.16.255.1/32 proto bgp dev r2-eth0")
        )
        expected = [{"dst": "172.16.255.1", "gateway": "192.168.255.1", "metric": 20}]
        return topotest.json_cmp(output, expected)

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R2"

    step("Restart R1")
    stop_router(tgen, "r1")

    step("Check if routes (BGP) are retained at R2")
    test_func = functools.partial(_bgp_check_bgp_retained_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP retained routes on R2"

    step("Check if routes (Kernel) are retained at R2")
    assert (
        _bgp_check_kernel_retained_routes() is None
    ), "Failed to retain BGP routes in kernel on R2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
