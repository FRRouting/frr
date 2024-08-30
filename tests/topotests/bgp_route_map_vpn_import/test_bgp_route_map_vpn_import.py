#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if `route-map vpn import NAME` works by setting/matching via route-maps.
Routes from VRF Customer to VRF Service MUST be leaked and modified later
with `route-map vpn import`.
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
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]

    r1.run("ip link add Customer type vrf table 1001")
    r1.run("ip link set up dev Customer")
    r1.run("ip link set r1-eth0 master Customer")
    r1.run("ip link add Service type vrf table 1002")
    r1.run("ip link set up dev Service")
    r1.run("ip link set r1-eth1 master Service")
    r1.run("ip link set r1-eth3 master Customer")

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


def test_bgp_route_map_vpn_import():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_check_received_leaked_with_vpn_import():
        output = json.loads(r1.vtysh_cmd("show bgp vrf Service ipv4 unicast json"))
        expected = {
            "routes": {
                "192.0.2.0/24": [
                    {
                        "locPrf": 123,
                    },
                ],
                "192.168.1.0/24": [
                    {
                        "locPrf": None,
                    }
                ],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_leaked_with_vpn_import)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Failed, imported routes are not modified"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
