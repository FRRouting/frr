#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if route-map match by EVPN route-type works.
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
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("c1", "r1"), "s2": ("r1", "r2"), "s3": ("r2", "c2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    tgen.net["r1"].cmd(
        """
ip link add vxlan10 type vxlan id 10 dstport 4789 local 10.10.10.1 nolearning
ip link add name br10 type bridge
ip link set dev vxlan10 master br10
ip link set dev r1-eth0 master br10
ip link set up dev br10
ip link set up dev vxlan10"""
    )

    tgen.net["r2"].cmd(
        """
ip link add vxlan10 type vxlan id 10 dstport 4789 local 10.10.10.2 nolearning
ip link add name br10 type bridge
ip link set dev vxlan10 master br10
ip link set dev r2-eth1 master br10
ip link set up dev br10
ip link set up dev vxlan10"""
    )

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_evpn_route_map_match_route_type():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp l2vpn evpn neighbor 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.1:1": {
                    "[5]:[0]:[32]:[10.10.10.10]": {
                        "valid": True,
                    }
                },
                "10.10.10.2:2": {
                    "[3]:[0]:[32]:[10.10.10.2]": {
                        "valid": True,
                    }
                },
            },
            "totalPrefixCounter": 2,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Filtered EVPN routes should not be advertised"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
