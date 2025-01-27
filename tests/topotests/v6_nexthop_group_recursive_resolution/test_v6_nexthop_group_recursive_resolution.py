#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2024 by Nvidia Corporation
# Donald Sharp
#

"""
Check that the v6 nexthop recursive resolution works when it changes
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

pytestmark = [pytest.mark.staticd]


def build_topo(tgen):

    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)),
                               [(TopoRouter.RD_MGMTD, None),
                                (TopoRouter.RD_ZEBRA, None),
                                (TopoRouter.RD_STATIC, None),
                                (TopoRouter.RD_SHARP, None)])

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_recursive_v6_nexthop_generation():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Testing v6 nexthop resolution")

    #assert False
    router = tgen.gears["r1"]

    def _v6_converge_1_1_initial():
        output = json.loads(
            router.vtysh_cmd("show ipv6 route 1::1 json"))

        expected = {
            "1::1/128":[
                {
                    "prefix":"1::1/128",
                    "prefixLen":128,
                    "protocol":"static",
                    "vrfName":"default",
                    "selected":True,
                    "destSelected":True,
                    "distance":1,
                    "metric":0,
                    "installed":True,
                    "table":254,
                    "nexthops":[
                        {
                            "fib":True,
                            "ip":"fc00::2",
                            "afi":"ipv6",
                            "interfaceName":"r1-eth0",
                            "active":True,
                            "weight":1
                        }
                    ]
                }
            ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_v6_converge_1_1_initial)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to install v6 1::1 route"

    router.vtysh_cmd("sharp install routes 2::2 nexthop 1::1 1")
    router.vtysh_cmd("conf\nipv6 route 1::1/128 fc00::3\nno ipv6 route 1::1/128 fc00::2")

    def _v6_converge_1_1_post():
        output = json.loads(
            router.vtysh_cmd("show ipv6 route 1::1 json"))

        expected = {
            "1::1/128":[
                {
                    "prefix":"1::1/128",
                    "prefixLen":128,
                    "protocol":"static",
                    "vrfName":"default",
                    "selected":True,
                    "destSelected":True,
                    "distance":1,
                    "metric":0,
                    "installed":True,
                    "table":254,
                    "nexthops":[
                        {
                            "fib":True,
                            "ip":"fc00::3",
                            "afi":"ipv6",
                            "interfaceName":"r1-eth0",
                            "active":True,
                            "weight":1
                        }
                    ]
                }
            ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_v6_converge_1_1_post)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to change v6 1::1 route"

    router.vtysh_cmd("sharp install routes 2::2 nexthop 1::1 1")

    def _v6_change_2_2_post():
        output = json.loads(
            router.vtysh_cmd("show ipv6 route 2::2 json"))

        expected = {
            "2::2/128":[
                {
                    "prefix":"2::2/128",
                    "prefixLen":128,
                    "protocol":"sharp",
                    "vrfName":"default",
                    "selected":True,
                    "destSelected":True,
                    "distance":150,
                    "metric":0,
                    "installed":True,
                    "table":254,
                    "nexthops":[
                        {
                            "fib":True,
                            "ip":"fc00::3",
                            "afi":"ipv6",
                            "interfaceName":"r1-eth0",
                            "active":True,
                            "weight":1
                        }
                    ]
                }
            ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_v6_change_2_2_post)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see sharpd route correctly"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
