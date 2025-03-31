#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if Opaque Data is accessable from other daemons in Zebra
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

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.ospf6d]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r3", "r4")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_opaque():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip route 192.168.1.0/24 json"))
        expected = {
            "192.168.1.0/24": [
                {
                    "communities": "65002:1 65002:2",
                    "largeCommunities": "65002:1:1 65002:2:1",
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _ospf_converge(router):
        output = json.loads(router.vtysh_cmd("show ip route 192.168.1.0/24 json"))
        expected = {
            "192.168.1.0/24": [
                {
                    "ospfPathType": "Intra-Area",
                    "ospfAreaId": "0.0.0.0",
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _ospf6_converge(router):
        output = json.loads(router.vtysh_cmd("show ipv6 route 2001:db8:1::/64 json"))
        expected = {
            "2001:db8:1::/64": [
                {
                    "ospfPathType": "Intra-Area",
                    "ospfAreaId": "0.0.0.0",
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    router = tgen.gears["r1"]
    test_func = functools.partial(_bgp_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Cannot see BGP community aliases "{}"'.format(router)

    router = tgen.gears["r3"]
    test_func = functools.partial(_ospf_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Cannot see OSPFv2 opaque attributes "{}"'.format(router)

    router = tgen.gears["r3"]
    test_func = functools.partial(_ospf6_converge, router)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Cannot see OSPFv3 opaque attributes "{}"'.format(router)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
