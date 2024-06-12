#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if default-originate works with conditional match.
If 10.0.0.0/22 is recived from r2, then we announce 0.0.0.0/0
to r2.
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


def test_bgp_default_originate_route_map():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 1}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_default_route_is_valid(router):
        output = json.loads(router.vtysh_cmd("show ip bgp 0.0.0.0/0 json"))
        expected = {"paths": [{"valid": True}]}
        return topotest.json_cmp(output, expected)

    step("Converge network")
    test_func = functools.partial(_bgp_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see bgp convergence at r2"

    step("Withdraw 10.0.0.0/22 from R2")
    router.vtysh_cmd(
        "conf t\nrouter bgp\naddress-family ipv4\nno redistribute connected"
    )

    step("Check if we don't have 0.0.0.0/0 at R2")
    test_func = functools.partial(_bgp_default_route_is_valid, router)
    _, result = topotest.run_and_expect(test_func, not None, count=30, wait=0.5)
    assert result is not None, "0.0.0.0/0 exists at r2"

    step("Announce 10.0.0.0/22 from R2")
    router.vtysh_cmd("conf t\nrouter bgp\naddress-family ipv4\nredistribute connected")

    step("Check if we have 0.0.0.0/0 at R2")
    test_func = functools.partial(_bgp_default_route_is_valid, router)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "0.0.0.0/0 does not exist at r2"

    step("Withdraw 10.0.0.0/22 from R2 again")
    router.vtysh_cmd(
        "conf t\nrouter bgp\naddress-family ipv4\nno redistribute connected"
    )

    step("Check if we don't have 0.0.0.0/0 at R2 again")
    test_func = functools.partial(_bgp_default_route_is_valid, router)
    _, result = topotest.run_and_expect(test_func, not None, count=30, wait=0.5)
    assert result is not None, "0.0.0.0/0 exists at r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
