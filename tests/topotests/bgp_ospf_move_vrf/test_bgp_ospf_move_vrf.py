#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Louis Scalbert <louis.scalbert@6wind.com>
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

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


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
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_path():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp ipv4 unicast 192.0.2.8/32 json")
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "nexthops": [{"ip": "192.0.2.2", "metric": 20}],
                },
            ]
        }

        return topotest.json_cmp(output, expected)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check BGP convergence")
    test_func = functools.partial(_bgp_check_path)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


def test_interfaces():
    """
    Add r1-eth1 to r3
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    def _check_interface():
        router = "r1"
        output = json.loads(tgen.gears[router].vtysh_cmd("show interface r1-eth1 json"))

        expected = {"r1-eth1": {"operationalStatus": "up"}}

        return topotest.json_cmp(output, expected)

    step("Check r1-eth1 presence")
    test_func = functools.partial(_check_interface)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see r1-eth1 on r1"

    r1 = tgen.gears["r1"]
    r1.cmd("ip link add vrf1 type vrf table 10")
    r1.cmd("ip link set vrf1 up")
    r1.cmd("ip link set r1-eth1 master vrf1")


def test_bgp_convergence_vrf1():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_path():
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
                    "nexthops": [{"ip": "192.0.2.2", "metric": 20}],
                },
            ]
        }

        return topotest.json_cmp(output, expected)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check BGP convergence")
    test_func = functools.partial(_bgp_check_path)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP VRF1 prefixes on R1"


def test_loopback_bgp():
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


def test_loopback_ospf():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_ospf_router_id():
        router = "r1"
        output = json.loads(tgen.gears[router].vtysh_cmd("show ip ospf json"))

        expected = {"routerId": "192.168.1.1"}

        return topotest.json_cmp(output, expected)

    step("Check if OSPF router-ID are correct")
    test_func = functools.partial(_check_ospf_router_id)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check OSPF router-ID on r1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
