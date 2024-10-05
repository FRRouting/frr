#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if BGP UPDATE with AGGREGATOR AS attribute with value zero (0)
is continued to be processed, but AGGREGATOR attribute is discarded.
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
    r1 = tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.0.0.2", defaultRoute="via 10.0.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    router.start()

    peer = tgen.gears["peer1"]
    peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_aggregator_zero():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp neighbor 10.0.0.2 json")
        )
        expected = {
            "10.0.0.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Failed bgp convergence in "{}"'.format(tgen.gears["r1"])

    def _bgp_has_correct_aggregator_route_with_asn_0():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp 192.168.100.101/32 json")
        )

        if "aggregatorAs" in output["paths"][0].keys():
            return False
        else:
            return True

    assert (
        _bgp_has_correct_aggregator_route_with_asn_0() is True
    ), 'Aggregator AS attribute with ASN 0 found in "{}"'.format(tgen.gears["r1"])

    def _bgp_has_correct_aggregator_route_with_good_asn():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp 192.168.100.102/32 json")
        )
        expected = {"paths": [{"aggregatorAs": 65001, "aggregatorId": "10.0.0.2"}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_has_correct_aggregator_route_with_good_asn)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Aggregator AS attribute not found in "{}"'.format(
        tgen.gears["r1"]
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
