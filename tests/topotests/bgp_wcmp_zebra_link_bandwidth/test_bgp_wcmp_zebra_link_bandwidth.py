#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    r1 = tgen.gears["r1"]

    r1.cmd_raises("ip link add main type vrf table 666")
    r1.cmd_raises("ip link set up dev main")
    r1.cmd_raises("ip link add red type vrf table 100")
    r1.cmd_raises("ip link set up dev red")
    r1.cmd_raises("ip link add blue type vrf table 200")
    r1.cmd_raises("ip link set up dev blue")
    r1.cmd_raises("ip link set dev r1-eth0 vrf red")
    r1.cmd_raises("ip link set dev r1-eth1 vrf blue")


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_wcmp_zebra_link_bandwidth():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show ip route vrf main json"))
        expected = {
            "10.10.10.10/32": [
                {
                    "protocol": "bgp",
                    "vrfName": "main",
                    "selected": True,
                    "distance": 200,
                    "metric": 0,
                    "installed": True,
                    "table": 666,
                    "internalNextHopNum": 2,
                    "internalNextHopActiveNum": 2,
                    "nexthops": [
                        {
                            "flags": 3,
                            "fib": True,
                            "ip": "192.168.12.2",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth0",
                            "vrf": "red",
                            "active": True,
                            "weight": 63,
                        },
                        {
                            "flags": 3,
                            "fib": True,
                            "ip": "192.168.13.3",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth1",
                            "vrf": "blue",
                            "active": True,
                            "weight": 255,
                        },
                    ],
                }
            ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't find expected weights for 10.10.10.10/32 next-hops"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
