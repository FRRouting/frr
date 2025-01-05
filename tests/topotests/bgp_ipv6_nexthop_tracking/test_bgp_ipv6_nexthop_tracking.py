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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_ipv6_nexthop_tracking():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp fd00:2222::/48 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "65002",
                    },
                    "valid": True,
                    "nexthops": [
                        {
                            "ip": "fe80::2222",
                            "hostname": "r2",
                            "afi": "ipv6",
                            "scope": "link-local",
                            "accessible": True,
                            "used": True,
                        },
                    ],
                    "peer": {
                        "peerId": "fe80::2222",
                        "routerId": "10.0.0.2",
                        "hostname": "r2",
                        "type": "external",
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to see fd00:2222::/48 with a valid next-hop"

    def _check_bgp_nexthop_cache():
        output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
        expected = {
            "ipv6": {
                "fe80::2222": {
                    "valid": True,
                    "complete": True,
                    "pathCount": 1,
                    "peer": "fe80::2222",
                    "resolvedPrefix": "fe80::/64",
                    "nexthops": [
                        {
                            "interfaceName": "r1-eth1",
                        }
                    ],
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_bgp_nexthop_cache)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to see a valid next-hop (fe80::2222) in BGP NH cache"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
