#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_route_map_on_match_next.py
#
# Copyright (c) 2023 Rubicon Communications, LLC.
#

"""
Test whether `on-match next` added to an existing route-map entry takes effect.
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


def test_bgp_route_map_on_match_next():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {"192.168.255.1": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    def _bgp_has_routes(router, metric, weight):
        output = json.loads(
            router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 routes json")
        )
        expected = {
            "routes": {"10.100.100.1/32": [{"metric": metric, "weight": weight}]}
        }
        return topotest.json_cmp(output, expected)

    # Check thst session is established
    test_func = functools.partial(_bgp_converge, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed bgp convergence on r2"

    # Check that metric is 0 and weight is 100 for the received prefix
    test_func = functools.partial(_bgp_has_routes, router2, 0, 100)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "r2 does not receive routes with metric 0 and weight 100"

    # Update the route-map and add "on-match next" to entry 10
    cmd = """
        configure terminal
        route-map RM permit 10
          on-match next
        exit
    """
    router2.vtysh_cmd(cmd)

    # Check that metric is 20 and weight is 100 for the received prefix
    test_func = functools.partial(_bgp_has_routes, router2, 20, 100)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "r2 does not receive routes with metric 20 and weight 100"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
