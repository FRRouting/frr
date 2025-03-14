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

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import TopoRouter, Topogen, get_topogen
from lib.topolog import logger

def setup_module(mod):
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
        router.load_frr_config(os.path.join(CWD, f"{name}/frr.conf"))

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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
