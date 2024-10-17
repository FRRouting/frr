#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
r7 sets aigp-metric for 10.0.0.71/32 to 71, and 72 for 10.0.0.72/32.

r6 receives those routes with aigp-metric TLV.

r2 and r3 receives those routes with aigp-metric TLV increased by 20,
and 10 appropriately.

r1 receives routes with aigp-metric TLV 81, 91 and 82, 92 respectively.
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
    for routern in range(1, 8):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r6"])
    switch.add_link(tgen.gears["r7"])


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


def test_bgp_aigp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r5 = tgen.gears["r5"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.71/32 json"))
        expected = {
            "paths": [
                {
                    "aigpMetric": 81,
                    "valid": True,
                    "nexthops": [
                        {
                            "ip": "10.0.0.3",
                            "hostname": "r3",
                            "metric": 30,
                            "accessible": True,
                        }
                    ],
                },
                {
                    "aigpMetric": 91,
                    "valid": True,
                    "bestpath": {"selectionReason": "IGP Metric"},
                    "nexthops": [
                        {
                            "ip": "10.0.0.2",
                            "hostname": "r2",
                            "metric": 10,
                            "accessible": True,
                        }
                    ],
                },
            ]
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_aigp_metric(router, prefix, aigp):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {"paths": [{"aigpMetric": aigp, "valid": True}]}
        return topotest.json_cmp(output, expected)

    def _bgp_check_aigp_metric_bestpath():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast 10.0.0.64/28 longer-prefixes json detail"
            )
        )
        expected = {
            "routes": {
                "10.0.0.71/32": {
                    "paths": [
                        {
                            "aigpMetric": 81,
                            "valid": True,
                            "nexthops": [
                                {
                                    "ip": "10.0.0.3",
                                    "hostname": "r3",
                                    "metric": 30,
                                    "accessible": True,
                                }
                            ],
                        },
                        {
                            "aigpMetric": 91,
                            "valid": True,
                            "bestpath": {"selectionReason": "AIGP"},
                            "nexthops": [
                                {
                                    "ip": "10.0.0.2",
                                    "hostname": "r2",
                                    "metric": 10,
                                    "accessible": True,
                                }
                            ],
                        },
                    ],
                },
                "10.0.0.72/32": {
                    "paths": [
                        {
                            "aigpMetric": 82,
                            "valid": True,
                            "nexthops": [
                                {
                                    "ip": "10.0.0.3",
                                    "hostname": "r3",
                                    "metric": 30,
                                    "accessible": True,
                                }
                            ],
                        },
                        {
                            "aigpMetric": 92,
                            "valid": True,
                            "bestpath": {"selectionReason": "AIGP"},
                            "nexthops": [
                                {
                                    "ip": "10.0.0.2",
                                    "hostname": "r2",
                                    "metric": 10,
                                    "accessible": True,
                                }
                            ],
                        },
                    ],
                },
            }
        }
        return topotest.json_cmp(output, expected)

    # Initial converge, AIGP is not involved in best-path selection process
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "can't converge initially"

    # Enable `bgp bestpath aigp`
    r1.vtysh_cmd(
        """
    configure terminal
        router bgp
            bgp bestpath aigp
    """
    )

    # r4, 10.0.6.6/32 with aigp-metric 20
    test_func = functools.partial(_bgp_check_aigp_metric, r4, "10.0.6.6/32", 20)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.6.6/32 is not 20"

    # r4, 10.0.0.71/32 with aigp-metric 71
    test_func = functools.partial(_bgp_check_aigp_metric, r4, "10.0.0.71/32", 71)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.0.71/32 is not 71"

    # r5, 10.0.0.72/32 with aigp-metric 72
    test_func = functools.partial(_bgp_check_aigp_metric, r5, "10.0.0.72/32", 72)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.0.72/32 is not 72"

    # r2, 10.0.0.71/32 with aigp-metric 101 (71 + 20)
    test_func = functools.partial(_bgp_check_aigp_metric, r2, "10.0.0.71/32", 91)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.0.71/32 is not 91"

    # r3, 10.0.0.72/32 with aigp-metric 92 (72 + 10)
    test_func = functools.partial(_bgp_check_aigp_metric, r3, "10.0.0.72/32", 82)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "aigp-metric for 10.0.0.72/32 is not 82"

    # r1, check if AIGP is considered in best-path selection (lowest wins: aigp + nexthop-metric)
    test_func = functools.partial(_bgp_check_aigp_metric_bestpath)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "AIGP attribute is not considered in best-path selection"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
