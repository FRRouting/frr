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

    for routern in range(1, 4):
        tgen.gears["r{}".format(routern)].cmd("ip link add vrf1 type vrf table 10")
        tgen.gears["r{}".format(routern)].cmd("ip link set vrf1 up")
        tgen.gears["r{}".format(routern)].cmd(
            "ip address add dev vrf1 {}.{}.{}.{}/32".format(
                routern, routern, routern, routern
            )
        )
    tgen.gears["r2"].cmd("ip address add dev vrf1 192.0.2.8/32")
    tgen.gears["r3"].cmd("ip address add dev vrf1 192.0.2.8/32")

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

    tgen.start_router()

    tgen.gears["r1"].cmd("ip route add 192.0.2.2 via 192.168.1.2 metric 20")
    tgen.gears["r1"].cmd("ip route add 192.0.2.3 via 192.168.2.2 metric 20")


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_path_selection_ecmp():
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

        return topotest.json_cmp(output, expected)

    step("Check if two ECMP paths are present")
    test_func = functools.partial(_bgp_check_path_selection_ecmp)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


def test_bgp_path_selection_vpn_ecmp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

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

    step("Check if two ECMP paths are present")
    test_func = functools.partial(_bgp_check_path_selection_vpn_ecmp)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


def test_bgp_path_selection_metric():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_path_selection_metric():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp ipv4 unicast 192.0.2.8/32 json")
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "nexthops": [{"ip": "192.0.2.2", "metric": 10}],
                    "bestpath": {"selectionReason": "IGP Metric"},
                },
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "nexthops": [{"ip": "192.0.2.3", "metric": 20}],
                },
            ]
        }

        return topotest.json_cmp(output, expected)

    tgen.gears["r1"].cmd("ip route add 192.0.2.2 via 192.168.1.2 metric 10")
    tgen.gears["r1"].cmd("ip route del 192.0.2.2 via 192.168.1.2 metric 20")

    step("Check if IGP metric best path is selected")
    test_func = functools.partial(_bgp_check_path_selection_metric)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


def test_bgp_path_selection_vpn_metric():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_path_selection_vpn_metric():
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
                    "nexthops": [{"ip": "192.0.2.2", "metric": 10}],
                    "bestpath": {"selectionReason": "IGP Metric"},
                },
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "nexthops": [{"ip": "192.0.2.3", "metric": 20}],
                },
            ]
        }

        return topotest.json_cmp(output, expected)

    step("Check if IGP metric best path is selected")
    test_func = functools.partial(_bgp_check_path_selection_vpn_metric)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
