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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

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
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_ipv6_link_local_capability():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "r2-eth0": {
                "neighborCapabilities": {
                    "linkLocalNextHop": {
                        "advertised": True,
                        "received": True,
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge initially"

    def _bgp_check_received_nexthops(router):
        output = json.loads(router.vtysh_cmd("show bgp 2001:db8::1/128 json"))
        expected = {
            "paths": [
                {
                    "valid": True,
                    "nexthops": [
                        {
                            "hostname": "r1",
                            "afi": "ipv6",
                            "scope": "link-local",
                            "length": 16,
                            "accessible": True,
                        }
                    ],
                    "peer": {
                        "routerId": "10.0.0.1",
                        "hostname": "r1",
                        "type": "external",
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_nexthops, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see 2001:db8::1/128"

    test_func = functools.partial(_bgp_check_received_nexthops, r3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see 2001:db8::1/128"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
