#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if RIP `allow-ecmp` command works correctly.
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
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.ripd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r3", "r4", "r5")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_rip_allow_ecmp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _show_rip_routes():
        xpath = (
            "/frr-ripd:ripd/instance[vrf='default']"
            "/state/routes/route[prefix='10.10.10.1/32']"
        )
        try:
            output = json.loads(
                r1.vtysh_cmd(f"show yang operational-data {xpath} ripd")
            )
        except Exception:
            return False

        try:
            output = output["frr-ripd:ripd"]["instance"][0]["state"]["routes"]
        except KeyError:
            return False

        expected = {
            "route": [
                {
                    "prefix": "10.10.10.1/32",
                    "nexthops": {
                        "nexthop": [
                            {
                                "nh-type": "ip4",
                                "protocol": "rip",
                                "rip-type": "normal",
                                "gateway": "192.168.1.2",
                                "from": "192.168.1.2",
                                "tag": 0,
                            },
                            {
                                "nh-type": "ip4",
                                "protocol": "rip",
                                "rip-type": "normal",
                                "gateway": "192.168.1.3",
                                "from": "192.168.1.3",
                                "tag": 0,
                            },
                        ]
                    },
                    "metric": 2,
                },
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_rip_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Can't see 10.10.10.1/32 as multipath in `show ip rip`"

    def _show_routes(nh_num):
        output = json.loads(r1.vtysh_cmd("show ip route json"))
        expected = {
            "10.10.10.1/32": [
                {
                    "internalNextHopNum": nh_num,
                    "internalNextHopActiveNum": nh_num,
                    "nexthops": [
                        {
                            "ip": "192.168.1.2",
                            "active": True,
                        },
                        {
                            "ip": "192.168.1.3",
                            "active": True,
                        },
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_routes, 4)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Can't see 10.10.10.1/32 as multipath (4) in `show ip route`"

    step(
        "Configure allow-ecmp 2, ECMP group routes SHOULD have next-hops with the lowest IPs"
    )
    r1.vtysh_cmd(
        """
    configure terminal
        router rip
            allow-ecmp 2
    """
    )

    test_func = functools.partial(_show_rip_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "Can't see 10.10.10.1/32 as ECMP with the lowest next-hop IPs"

    test_func = functools.partial(_show_routes, 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Can't see 10.10.10.1/32 as multipath (2) in `show ip route`"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
