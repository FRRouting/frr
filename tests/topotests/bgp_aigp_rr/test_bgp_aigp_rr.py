#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2024, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
r1, r2, and r3 are directly connectd to each other.
r4 is only connected to r1 directly.

r1 is the route reflector.
r1 sets the nexthop to itself when advertising routes to r4.

r2 sources 10.0.2.2/32 with agigp-metric 2.

Results:

r1, r2 and r3 should have aigp-meric 2.
r4 should have aigp-metric 12, i.e., aigp + nexthop-metric.
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
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_aigp_rr():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    def _bgp_check_aigp_metric(router, prefix, aigp):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {"paths": [{"aigpMetric": aigp, "valid": True}]}
        return topotest.json_cmp(output, expected)

    def _bgp_check_aigp_bestpath():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.0.1.2/32 json"))
        expected = {
            "prefix": "10.0.1.2/32",
            "paths": [
                {
                    "aigpMetric": 50,
                    "valid": True,
                    "sourced": True,
                    "local": True,
                    "bestpath": {"overall": True, "selectionReason": "Local Route"},
                    "nexthops": [
                        {
                            "ip": "0.0.0.0",
                            "hostname": "r1",
                            "afi": "ipv4",
                            "metric": 0,
                            "accessible": True,
                            "used": True,
                        }
                    ],
                },
                {
                    "aigpMetric": 10,
                    "valid": True,
                    "nexthops": [
                        {
                            "ip": "10.0.0.2",
                            "hostname": "r2",
                            "afi": "ipv4",
                            "metric": 10,
                            "accessible": True,
                            "used": True,
                        }
                    ],
                },
            ],
        }
        return topotest.json_cmp(output, expected)

    # r2, 10.0.2.2/32 with aigp-metric 2
    test_func = functools.partial(_bgp_check_aigp_metric, r2, "10.0.2.2/32", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.2.2/32 is not 2"

    # r1, 10.0.2.2/32 with aigp-metric 2
    test_func = functools.partial(_bgp_check_aigp_metric, r1, "10.0.2.2/32", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.2.2/32 is not 2"

    # r3, 10.0.2.2/32 with aigp-metric 2
    test_func = functools.partial(_bgp_check_aigp_metric, r3, "10.0.2.2/32", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.2.2/32 is not 2"

    # r4, 10.0.2.2/32 with aigp-metric 12: aigp + nexthop-metric
    test_func = functools.partial(_bgp_check_aigp_metric, r4, "10.0.2.2/32", 12)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.2.2/32 is not 12"

    # r1, check if the local route is favored over AIGP comparison
    test_func = functools.partial(_bgp_check_aigp_bestpath)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Local route is not favored over AIGP in best-path selection"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
