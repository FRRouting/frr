#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_max_med_on_startup.py
#
# Copyright (c) 2022 Rubicon Communications, LLC.
#

"""
Test whether `bgp max-med on-startup (5-86400) [(0-4294967295)]` is working
correctly.
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
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_max_med_on_startup():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {"192.168.255.1": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    def _bgp_has_routes(router, metric):
        output = json.loads(
            router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 routes json")
        )
        expected = {"routes": {"172.16.255.254/32": [{"metric": metric}]}}
        return topotest.json_cmp(output, expected)

    # Check session is established
    test_func = functools.partial(_bgp_converge, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed bgp convergence on r2"

    # Check metric has value of max-med
    test_func = functools.partial(_bgp_has_routes, router2, 777)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "r2 does not receive routes with metric 777"

    # Check that when the max-med timer expires, metric is updated
    test_func = functools.partial(_bgp_has_routes, router2, 0)
    _, result = topotest.run_and_expect(test_func, None, count=16, wait=0.5)
    assert result is None, "r2 does not receive routes with metric 0"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
