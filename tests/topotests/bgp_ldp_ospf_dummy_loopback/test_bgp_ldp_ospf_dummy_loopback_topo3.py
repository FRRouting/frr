#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Louis Scalbert <louis.scalbert@6wind.com>
#

"""
Check that dummy interfaces are considered as loopback when they are CREATED
AFTER zebra statup with a COMPLETE configuration.
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
        router.load_config(
            TopoRouter.RD_LDP, os.path.join(CWD, "{}/ldpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_interfaces():
    """
    Not an actual test. Just make sure that dummies and interfaces are created
    after startup
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for routern in range(1, 4):
        router = tgen.gears["r{}".format(routern)]
        router.cmd("ip link add dummy0 type dummy")
        router.cmd("ip link add dummy1 type dummy")
        router.cmd("ip link add vrf1 type vrf table 10")
        router.cmd("ip link set vrf1 up")
        router.cmd("ip link set dummy1 master vrf1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def test_dummy_interface():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_dummy_interface():
        router = "r1"
        output = json.loads(tgen.gears[router].vtysh_cmd("show interface dummy0 json"))

        expected = {"dummy0": {"interfaceType": "dummy"}}

        return topotest.json_cmp(output, expected)

    step("Check if dummy0 is recognized as a dummy interface")
    test_func = functools.partial(_check_dummy_interface)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to recognize dummy type on r1"


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_path_selection_ecmp():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp ipv4 unicast 192.0.2.8/32 json")
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "multipath": True,
                    "nexthops": [{"ip": "192.0.2.2", "metric": 20}],
                },
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "multipath": True,
                    "nexthops": [{"ip": "192.0.2.3", "metric": 20}],
                },
            ]
        }

    def _bgp_check_path_selection_vpn_ecmp():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show bgp vrf vrf1 ipv4 unicast 192.0.2.8/32 json"
            )
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "multipath": True,
                    "nexthops": [{"ip": "192.0.2.2", "metric": 20}],
                },
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "multipath": True,
                    "nexthops": [{"ip": "192.0.2.3", "metric": 20}],
                },
            ]
        }

        return topotest.json_cmp(output, expected)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check BGP convergence")
    test_func = functools.partial(_bgp_check_path_selection_ecmp)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"

    test_func = functools.partial(_bgp_check_path_selection_vpn_ecmp)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


def test_dummy_loopback_bgp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_bgp_router_id():
        router = "r1"
        output = json.loads(tgen.gears[router].vtysh_cmd("show bgp all json"))

        json_file = "{}/{}/{}".format(CWD, router, "bgp_all.json")

        expected = json.loads(open(json_file).read())

        return topotest.json_cmp(output, expected)

    step("Check if BGP router-ID is correct")
    test_func = functools.partial(_check_bgp_router_id)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check BGP router-ID on r1"


def test_dummy_loopback_ldp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_ldp_router_id():
        router = "r1"
        output = json.loads(tgen.gears[router].vtysh_cmd("show mpls ldp neighbor json"))

        json_file = "{}/{}/{}".format(CWD, router, "ldp_neighbor.json")

        expected = json.loads(open(json_file).read())

        return topotest.json_cmp(output, expected)

    step("Check if LDP router-IDs are correct")
    test_func = functools.partial(_check_ldp_router_id)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check LDP R2, R3 router-ID on r1"


def test_dummy_loopback_ospf():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_ospf_router_id():
        router = "r1"
        output = json.loads(tgen.gears[router].vtysh_cmd("show ip ospf json"))

        json_file = "{}/{}/{}".format(CWD, router, "ldp_neighbor.json")

        expected = {"routerId": "192.0.2.1"}

        return topotest.json_cmp(output, expected)

    step("Check if OSPF router-ID are correct")
    test_func = functools.partial(_check_ospf_router_id)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check OSPF router-ID on r1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
