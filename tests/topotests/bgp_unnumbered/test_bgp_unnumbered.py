#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2022 by
# Donald Sharp
#

"""
Test some bgp interface based issues that show up
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
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


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


#
# Test these events:
# a) create an unnumbered neighbor
# b) shutdown the interface
# c) remove the unnumbered peer in bgp and bgp does not crash
def test_bgp_unnumbered_removal():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_nexthop_cache():
        output = tgen.gears["r1"].vtysh_cmd("show bgp nexthop")
        expected = "Current BGP nexthop cache:\n"
        return output == expected

    def _bgp_converge():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp 172.16.255.254/32 json")
        )
        expected = {"prefix": "172.16.255.254/32"}

        return topotest.json_cmp(output, expected)

    step("Ensure Convergence of BGP")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assert result is None, 'Failed bgp convergence in "{}"'.format(tgen.gears["r2"])

    step("Shutdown interface r1-eth0")

    tgen.gears["r1"].vtysh_cmd(
        """
           configure
           int r1-eth0
             shutdown
        """
    )

    step("Remove the neighbor from r1")
    tgen.gears["r1"].vtysh_cmd(
        """
           configure
           router bgp
            no neighbor r1-eth0 interface remote-as external
       """
    )

    step("Ensure that BGP does not crash")
    test_func = functools.partial(_bgp_nexthop_cache)
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=1)

    assert result is True, "BGP did not crash on r1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
