#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if we send ONLY GUA address for route-server-client peers.
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
from lib.topogen import Topogen, TopoRouter, get_topogen


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
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


def test_bgp_route_server_client():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv6 unicast summary json"))
        expected = {"peers": {"2001:db8:1::1": {"state": "Established", "pfxRcd": 2}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see BGP sessions to be up"

    def _bgp_prefix_received(router):
        output = json.loads(router.vtysh_cmd("show bgp 2001:db8:f::3/128 json"))
        expected = {
            "prefix": "2001:db8:f::3/128",
            "paths": [{"nexthops": [{"ip": "2001:db8:3::2"}]}],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_prefix_received, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see BGP GUA next hop from r3 in r1"

    def _bgp_single_next_hop(router):
        output = json.loads(router.vtysh_cmd("show bgp 2001:db8:f::3/128 json"))
        return len(output["paths"][0]["nexthops"])

    assert (
        _bgp_single_next_hop(r1) == 1
    ), "Not ONLY one Next Hop received for 2001:db8:f::3/128"

    def _bgp_gua_lla_next_hop(router):
        output = json.loads(router.vtysh_cmd("show bgp view RS 2001:db8:f::3/128 json"))
        expected = {
            "prefix": "2001:db8:f::3/128",
            "paths": [
                {
                    "nexthops": [
                        {
                            "ip": "2001:db8:3::2",
                            "hostname": "r3",
                            "afi": "ipv6",
                            "scope": "global",
                        },
                        {"hostname": "r3", "afi": "ipv6", "scope": "link-local"},
                    ]
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_gua_lla_next_hop, r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see BGP LLA next hop from r3 in r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
