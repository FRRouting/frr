#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_aggregate-address_route-map.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
bgp_aggregate-address_route-map.py:

Test if works the following commands:
router bgp 65031
  address-family ipv4 unicast
    aggregate-address 192.168.255.0/24 route-map aggr-rmap

route-map aggr-rmap permit 10
  set metric 123
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
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

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


def test_bgp_maximum_prefix_invalid():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 3}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_aggregate_address_has_metric(router, metric):
        output = json.loads(router.vtysh_cmd("show ip bgp 172.16.255.0/24 json"))
        expected = {"paths": [{"metric": metric}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see bgp convergence in r2"

    test_func = functools.partial(_bgp_aggregate_address_has_metric, r2, 123)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see applied metric for aggregated prefix in r2"

    r1.vtysh_cmd(
        """
    configure terminal
     route-map aggr-rmap permit 10
      set metric 666
    """
    )

    test_func = functools.partial(_bgp_aggregate_address_has_metric, r2, 666)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see applied metric for aggregated prefix in r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
