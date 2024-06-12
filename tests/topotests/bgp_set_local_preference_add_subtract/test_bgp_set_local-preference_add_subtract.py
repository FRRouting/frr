#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_set_local-preference_add_subtract.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
bgp_set_local-preference_add_subtract.py:
Test if we can add/subtract the value to/from an existing
LOCAL_PREF in route-maps.
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
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
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
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_set_local_preference():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 3}},
            },
            "192.168.255.3": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 3}},
            },
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_local_preference(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.10.10.2/32": [{"locPrf": 160}],
                "10.10.10.3/32": [{"locPrf": 40}],
                "172.16.255.254/32": [
                    {"locPrf": 50, "nexthops": [{"ip": "192.168.255.3"}]},
                    {"locPrf": 150, "nexthops": [{"ip": "192.168.255.2"}]},
                ],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'Failed to see BGP convergence in "{}"'.format(router)

    test_func = functools.partial(_bgp_check_local_preference, router)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'Failed to see applied BGP local-preference in "{}"'.format(
        router
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
