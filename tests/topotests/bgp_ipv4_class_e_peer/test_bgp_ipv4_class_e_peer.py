#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_ipv4_class_e_peer.py
#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if the peering works by using IPv4 Class E IP ranges, and if
we don't treat next-hop as martian in such a case.
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


def test_bgp_ipv4_class_e_peer():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 240.0.0.1 json"))
        expected = {
            "240.0.0.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_next_hop_ipv4_class_e():
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 172.16.255.1/32 json")
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "nexthops": [
                        {
                            "ip": "240.0.0.1",
                            "accessible": True,
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R2"

    step("Check if IPv4 BGP peering works with Class E IP ranges")
    test_func = functools.partial(_bgp_next_hop_ipv4_class_e)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see 172.16.255.1/32 via 240.0.0.1 on R2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
