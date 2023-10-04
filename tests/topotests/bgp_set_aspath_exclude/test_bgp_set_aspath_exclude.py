#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_set_aspath_exclude.py
#
# Copyright 2023 by 6WIND S.A.
#

"""
Test if `set as-path exclude` is working correctly for route-maps.
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


def test_bgp_set_aspath_exclude():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "172.16.255.31/32": [{"path": "65002"}],
                "172.16.255.32/32": [{"path": ""}],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Failed overriding incoming AS-PATH with route-map"


def test_bgp_set_aspath_exclude_access_list():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "r1"
    r1 = tgen.gears[rname]

    r1.vtysh_cmd(
        """
conf
 bgp as-path access-list FIRST permit ^65 
 route-map r2 permit 6 
  set as-path exclude as-path-access-list FIRST
    """
    )

    expected = {
        "routes": {
            "172.16.255.31/32": [{"path": ""}],
            "172.16.255.32/32": [{"path": ""}],
        }
    }

    def _bgp_regexp_1(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_regexp_1, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Failed overriding incoming AS-PATH with regex 1 route-map"
    r1.vtysh_cmd(
        """
conf
 bgp as-path access-list SECOND permit 2
 route-map r2 permit 6
  set as-path exclude as-path-access-list SECOND
    """
    )

    expected = {
        "routes": {
            "172.16.255.31/32": [{"path": "65003"}],
            "172.16.255.32/32": [{"path": "65003"}],
        }
    }

    test_func = functools.partial(_bgp_regexp_1, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Failed overriding incoming AS-PATH with regex 2 route-map"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
