#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_reject_as_sets.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if an aggregated route with AS_SET is not sent to peers.
Addressing draft-ietf-idr-deprecate-as-set-confed-set recommendations.

BGP speakers conforming to this document (i.e., conformant BGP
   speakers) MUST NOT locally generate BGP UPDATE messages containing
   AS_SET or AS_CONFED_SET.  Conformant BGP speakers SHOULD NOT send BGP
   UPDATE messages containing AS_SET or AS_CONFED_SET.  Upon receipt of
   such messages, conformant BGP speakers SHOULD use the "Treat-as-
   withdraw" error handling behavior as per [RFC7606].
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

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
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


def test_bgp_reject_as_sets():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed bgp convergence at r2"

    def _bgp_has_aggregated_route():
        output = json.loads(r2.vtysh_cmd("show ip bgp 172.16.0.0/16 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "{65001,65003}",
                        "segments": [{"type": "as-set", "list": [65001, 65003]}],
                        "length": 1,
                    },
                    "aggregatorAs": 65002,
                    "aggregatorId": "192.168.255.1",
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_has_aggregated_route)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see an aggregated route at r2"

    def _bgp_announce_route_without_as_sets():
        output = json.loads(r4.vtysh_cmd("show ip bgp 172.16.0.0/16 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "65002",
                        "segments": [{"type": "as-sequence", "list": [65002]}],
                        "length": 1,
                    },
                    "aggregatorAs": 65002,
                    "aggregatorId": "192.168.255.1",
                    "atomicAggregate": True,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_announce_route_without_as_sets)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Route 172.16.0.0/16 should be sent without AS_SET to r4"

    def _bgp_filter_aggregated_route_to_contributing_as():
        output = json.loads(r3.vtysh_cmd("show ip bgp json"))
        expected = {
            "routes": {
                "172.16.254.254/32": [
                    {
                        "valid": True,
                        "bestpath": True,
                    }
                ],
                "192.168.254.0/30": [
                    {
                        "valid": True,
                        "bestpath": True,
                    },
                    {
                        "valid": True,
                    },
                ],
                "192.168.255.0/30": [
                    {
                        "valid": True,
                        "bestpath": True,
                    }
                ],
            },
            "totalRoutes": 3,
            "totalPaths": 4,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_filter_aggregated_route_to_contributing_as)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Route 172.16.0.0/16 should NOT be sent to contributing AS (r3)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
