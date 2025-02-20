#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if BGP Long-lived Graceful Restart capability works:
    Check if we can see 172.16.1.1/32 after initial converge in R3.
    Check if we can see 172.16.1.1/32 as best selected due to higher weigth in R2.
    Kill bgpd in R1.
    Check if we can see 172.16.1.1/32 as stale in R2.
    Check if we can see 172.16.1.1/32 depreferenced due to LLGR_STALE in R2.
    Check if we can see 172.16.1.1/32 after R1 was killed in R3.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

from lib.common_config import (
    kill_router_daemons,
    step,
)


def build_topo(tgen):
    for routern in range(0, 6):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s0")
    switch.add_link(tgen.gears["r0"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # Dynamic neighbor
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])


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


def test_bgp_llgr():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp json"))
        expected = {
            "routes": {
                "172.16.1.1/32": [{"nexthops": [{"ip": "192.168.2.2", "used": True}]}],
                "172.16.1.2/32": [{"nexthops": [{"ip": "192.168.2.2", "used": True}]}],
            }
        }
        return topotest.json_cmp(output, expected)

    step("Check if we can see 172.16.1.1/32 after initial converge in R3")
    test_func = functools.partial(_bgp_converge, r3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see 172.16.1.1/32 in r3"

    def _bgp_weight_prefered_route(router):
        output = json.loads(router.vtysh_cmd("show ip bgp 172.16.1.1/32 json"))
        expected = {
            "paths": [
                {
                    "bestpath": {"selectionReason": "Weight"},
                    "nexthops": [
                        {
                            "ip": "192.168.1.1",
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step(
        "Check if we can see 172.16.1.1/32 as best selected due to higher weigth in R2"
    )
    test_func = functools.partial(_bgp_weight_prefered_route, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Prefix 172.16.1.1/32 is not selected as bests path due to weight"

    step("Kill bgpd in R1")
    kill_router_daemons(tgen, "r1", ["bgpd"])

    def _bgp_stale_route(router, prefix):
        output = json.loads(router.vtysh_cmd("show ip bgp {} json".format(prefix)))
        expected = {"paths": [{"community": {"string": "llgr-stale"}, "stale": True}]}
        return topotest.json_cmp(output, expected)

    step("Check if we can see 172.16.1.1/32 as stale in R2")
    test_func = functools.partial(_bgp_stale_route, r2, "172.16.1.1/32")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix 172.16.1.1/32 is not stale"

    def _bgp_llgr_depreference_route(router):
        output = json.loads(router.vtysh_cmd("show ip bgp 172.16.1.1/32 json"))
        expected = {
            "paths": [
                {
                    "bestpath": {"selectionReason": "First path received"},
                    "nexthops": [
                        {
                            "ip": "192.168.0.1",
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("Check if we can see 172.16.1.1/32 depreferenced due to LLGR_STALE in R2")
    test_func = functools.partial(_bgp_llgr_depreference_route, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix 172.16.1.1/32 is not depreferenced due to LLGR_STALE"

    step("Check if we can see 172.16.1.1/32 after R1 was killed in R3")
    test_func = functools.partial(_bgp_converge, r3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see 172.16.1.1/32 in r3"

    step("Kill bgpd in R4 (dynamic peer)")
    kill_router_daemons(tgen, "r4", ["bgpd"])

    step("Check if we can see 172.16.1.2/32 after R4 (dynamic peer) was killed")
    test_func = functools.partial(_bgp_stale_route, r2, "172.16.1.2/32")
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assert result is None, "Cannot see 172.16.1.2/32 in r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
