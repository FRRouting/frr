#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
This is to verify that the aggregate route is evaluated and announced to
zebra when appropriate, just like other-types of routes.
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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 2):
        tgen.add_router("r{}".format(routern))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_aggregate_address_zebra_announce():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_aggregate_address_has_metric(router, metric):
        output = json.loads(router.vtysh_cmd("show ip route 10.0.10.0/24 json"))
        expected = {
	    "10.0.10.0/24":[
	        {
	            "metric": metric,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("check if the aggregate route is installed in zebra")
    test_func = functools.partial(_bgp_aggregate_address_has_metric, r1, 0)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "failed to see the aggregate route with metric 0"

    step("modify the table-map")
    r1.vtysh_cmd(
        """
    configure terminal
        route-map tmap permit 10
        set metric 100
    """
    )

    step("check if the aggregate route is changed in zebra")
    test_func = functools.partial(_bgp_aggregate_address_has_metric, r1, 100)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "failed to see the aggregate route with metric 100"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
