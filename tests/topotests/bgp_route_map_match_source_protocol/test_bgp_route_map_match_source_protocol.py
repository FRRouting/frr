#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if r1 can announce only static routes to r2, and only connected
routes to r3 using `match source-protocol` with route-maps.
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

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_SHARP, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_route_map_match_source_protocol():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_advertised_routes_r2():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.10/32": {
                    "valid": True,
                }
            },
            "totalPrefixCounter": 1,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_advertised_routes_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to filter routes by source-protocol for r2"

    def _bgp_check_advertised_routes_r3():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.2.2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "192.168.1.0/24": {
                    "valid": True,
                },
                "192.168.2.0/24": {
                    "valid": True,
                },
                "172.16.255.1/32": {
                    "valid": True,
                },
            },
            "totalPrefixCounter": 3,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_advertised_routes_r3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to filter routes by source-protocol for r3"

    def _bgp_check_advertised_routes_r4():
        # Remove match source-protocol towards Nbr out policy for Nbr 192.168.1.2 so it receives all routes
        tgen.gears["r1"].vtysh_cmd(
            """
              configure terminal
                route-map r2 permit 10
                  no match source-protocol
            """
        )

        tgen.gears["r1"].vtysh_cmd(
            "sharp install route 192.168.11.0 nexthop 172.16.255.1 5"
        )

        # Configure a r4 with source protocol sharp and apply it to all redistribute cmds
        tgen.gears["r1"].vtysh_cmd(
            """
              configure terminal
                route-map r4 permit 10
                  match source-protocol sharp
                router bgp 65001
                  address-family ipv4 unicast
                    redistribute connected route-map r4
                    redistribute static route-map r4
                    redistribute sharp route-map r4
            """
        )

        # Since match protocol is sharp, only sharp protocol routes are to be advertised
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.1.2 advertised-routes json"
            )
        )

        expected = {
            "advertisedRoutes": {
                "192.168.11.0/32": {
                    "valid": True,
                },
                "192.168.11.1/32": {
                    "valid": True,
                },
                "192.168.11.2/32": {
                    "valid": True,
                },
                "192.168.11.3/32": {
                    "valid": True,
                },
                "192.168.11.4/32": {
                    "valid": True,
                },
            },
            "totalPrefixCounter": 5,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_advertised_routes_r4)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to match the source-protocol for redistribute cmds"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
