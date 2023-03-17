#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if distance can be set to zero via route-maps.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = pytest.mark.bgpd

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
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


def test_bgp_distance_zero():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge_table():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 10.10.10.1/32 json"))
        expected = {"paths": [{"valid": True}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_table)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see distance 0 in BGP table"

    def _bgp_converge_rib():
        output = json.loads(r2.vtysh_cmd("show ip route 10.10.10.1/32 json"))
        expected = {
            "10.10.10.1/32": [
                {"protocol": "bgp", "distance": 0, "selected": True, "installed": True}
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_rib)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see distance 0 in RIB"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
