#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""

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
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

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


def test_bgp_local_as_same_remote_as():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_local_as_same_remote_as():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast 172.16.255.1/32 json")
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "Local"},
                    "nexthops": [{"ip": "192.168.1.1", "hostname": "r1"}],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("Check if iBGP works when local-as == remote-as")
    test_func = functools.partial(_bgp_check_local_as_same_remote_as)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R2"


def test_bgp_peer_group_local_as_same_remote_as():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_local_as_same_remote_as():
        output = json.loads(
            tgen.gears["r3"].vtysh_cmd("show bgp ipv4 unicast 172.16.255.1/32 json")
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "Local"},
                    "nexthops": [{"ip": "192.168.2.1", "hostname": "r1"}],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_check_local_as_same_remote_as)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R3"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
