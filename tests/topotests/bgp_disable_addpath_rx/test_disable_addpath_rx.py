#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if AddPath RX direction is not negotiated via AddPath capability.
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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_disable_addpath_rx():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step(
        "Check if r2 advertised only 2 paths to r1 (despite addpath-tx-all-paths enabled on r2)."
    )

    def check_bgp_advertised_routes(router):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "172.16.16.254/32": {
                    "addrPrefix": "172.16.16.254",
                    "prefixLen": 32,
                },
                "192.168.2.0/24": {
                    "addrPrefix": "192.168.2.0",
                    "prefixLen": 24,
                },
            },
            "totalPrefixCounter": 2,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_bgp_advertised_routes, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "AddPath TX not working."

    step("Check if AddPath RX is disabled on r1 and we receive only 2 paths.")

    def check_bgp_disabled_addpath_rx(router):
        output = json.loads(router.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "addPath": {
                        "ipv4Unicast": {"txReceived": True, "rxReceived": True}
                    },
                },
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_bgp_disabled_addpath_rx, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "AddPath RX advertised, but should not."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
