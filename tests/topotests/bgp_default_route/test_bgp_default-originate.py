#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if default-originate works without route-map.
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

    for i, (rname, router) in enumerate(router_list.items(), 1):
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


def test_bgp_default_originate_route_map():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_if_received():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show ip bgp neighbor 192.168.255.1 json")
        )
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_if_originated():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show ip bgp summary json"))
        expected = {"ipv4Unicast": {"peers": {"192.168.255.2": {"pfxSnt": 2}}}}
        return topotest.json_cmp(output, expected)

    def _bgp_route_is_valid(router, prefix):
        output = json.loads(router.vtysh_cmd("show ip bgp {} json".format(prefix)))
        expected = {"paths": [{"valid": True}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_if_received)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "No 0.0.0.0/0 at r2 from r1"

    test_func = functools.partial(_bgp_check_if_originated)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "No 0.0.0.0/0 from r1 to r2"

    test_func = functools.partial(_bgp_route_is_valid, tgen.gears["r2"], "0.0.0.0/0")
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see 0.0.0.0/0 in r2"

    test_func = functools.partial(_bgp_route_is_valid, tgen.gears["r2"], "0.0.0.0/1")
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see 0.0.0.0/1 in r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
