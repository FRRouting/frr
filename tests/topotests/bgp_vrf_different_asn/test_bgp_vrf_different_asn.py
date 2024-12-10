#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

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
    for routern in range(1, 2):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.run("ip link add vrf100 type vrf table 1001")
    r1.run("ip link set up dev vrf100")
    r1.run("ip link set r1-eth0 master vrf100")

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_vrf_different_asn():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_instances():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp vrf all json"))
        expected = {
            "default": {
                "vrfName": "default",
                "localAS": 65000,
            },
            "vrf100": {
                "vrfName": "vrf100",
                "localAS": 65100,
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_instances)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see vrf100 to be under 65100 ASN"

    def _bgp_check_imported_route():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip route 192.168.1.0/24 json")
        )
        expected = {
            "192.168.1.0/24": [
                {
                    "installed": True,
                    "selected": True,
                    "nexthops": [
                        {
                            "interfaceName": "vrf100",
                            "vrf": "vrf100",
                            "active": True,
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_imported_route)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see 192.168.1.0/24 being imported into a default VRF"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
