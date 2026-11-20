#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright (c) 2025 Tuetuopay <tuetuopay@me.com>

"""
Test if route-map set for EVPN fields works.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import TopoRouter, Topogen, get_topogen
from lib.topolog import logger


def setup_module(mod):
    if not topotest.platform_has_evpn():
        pytest.skip("platform does not support EVPN")

    topodef = {"s1": ("c1", "r1"), "s2": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    tgen.net["r1"].cmd(
        """
ip link add br10 up type bridge
ip link add vxlan10 up master br10 type vxlan id 10 dstport 4789 local 10.0.0.2 nolearning
        """
    )
    tgen.net["r2"].cmd(
        """
ip link add br10 up type bridge
ip link add vxlan10 up master br10 type vxlan id 10 dstport 4789 local 10.0.0.3 nolearning
        """
    )

    for name, router in tgen.routers().items():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def test_bgp_evpn_route_map_set_gateway_ip():
    tgen: Topogen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2: TopoRouter = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp l2vpn evpn all overlay json"))
        expected = {
            "10.0.0.2:1": {
                "[5]:[0]:[32]:[10.10.10.10]": {
                    "paths": [
                        {
                            "valid": True,
                            "overlay": {
                                "gw": "10.10.10.10",
                            },
                        },
                    ],
                },
            },
            "numPrefix": 1,
        }
        return topotest.json_cmp(output, expected)

    logger.info("Check route type-5 gateway-ip")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "EVPN Route with gateway-ip should be advertised"


def _r2_rt5_nexthops():
    """Installed next hops of r1's RT-5 route 10.10.10.10/32 on r2."""
    r2 = get_topogen().gears["r2"]
    out = r2.vtysh_cmd("show ip route 10.10.10.10/32 json", isjson=True)
    return sorted(
        nh.get("ip")
        for route in out.get("10.10.10.10/32", [])
        if route.get("installed")
        for nh in route.get("nexthops", [])
    )


def test_bgp_evpn_route_map_set_gateway_ip_removed():
    """
    r2 imports r1's RT-5 route with gateway IP 10.10.10.10, which does not
    resolve on r2, so the route is not installed. Once r1 stops setting the
    gateway IP, r2 must install the route via r1. Once r1 sets it again,
    r2 must remove it again.
    """
    tgen: Topogen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1: TopoRouter = tgen.gears["r1"]

    logger.info("Check the RT-5 route with gateway-ip is not installed")
    _, result = topotest.run_and_expect(_r2_rt5_nexthops, [], count=30, wait=1)
    assert result == [], "r2 installed the RT-5 route via {}".format(result)

    logger.info("Remove set-gw-ip on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64000
         address-family l2vpn evpn
          no neighbor 10.0.0.3 route-map set-gw-ip out
        """
    )
    _, result = topotest.run_and_expect(
        _r2_rt5_nexthops, ["10.0.0.2"], count=30, wait=1
    )
    assert result == ["10.0.0.2"], "r2 RT-5 route next hops: {}".format(result)

    logger.info("Put set-gw-ip back on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64000
         address-family l2vpn evpn
          neighbor 10.0.0.3 route-map set-gw-ip out
        """
    )
    _, result = topotest.run_and_expect(_r2_rt5_nexthops, [], count=30, wait=1)
    assert result == [], "r2 still installs the RT-5 route via {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
