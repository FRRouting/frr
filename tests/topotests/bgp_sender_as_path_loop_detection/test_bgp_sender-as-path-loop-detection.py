#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_sender-as-path-loop-detection.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if neighbor <neighbor> sender-as-path-loop-detection
command works as expeced.
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
    for routern in range(1, 4):
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


def test_bgp_sender_as_path_loop_detection():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 3}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_has_route_from_r1():
        output = json.loads(r2.vtysh_cmd("show ip bgp 172.16.255.253/32 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "segments": [{"type": "as-sequence", "list": [65001, 65003]}],
                        "length": 2,
                    }
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _bgp_suppress_route_to_r1():
        output = json.loads(
            r2.vtysh_cmd("show ip bgp neighbor 192.168.255.2 advertised-routes json")
        )
        expected = {"totalPrefixCounter": 0}
        return topotest.json_cmp(output, expected)

    def _bgp_suppress_route_to_r3():
        output = json.loads(
            r2.vtysh_cmd("show ip bgp neighbor 192.168.254.2 advertised-routes json")
        )
        expected = {"totalPrefixCounter": 2}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed bgp to convergence"

    test_func = functools.partial(_bgp_has_route_from_r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed to see a route from r1"

    test_func = functools.partial(_bgp_suppress_route_to_r3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Route 172.16.255.253/32 should not be sent to r3 from r2"

    test_func = functools.partial(_bgp_suppress_route_to_r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Routes should not be sent to r1 from r2"


def test_remove_loop_detection_on_one_peer():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_reset_route_to_r1():
        output = json.loads(
            r2.vtysh_cmd("show ip bgp neighbor 192.168.255.2 advertised-routes json")
        )
        expected = {"totalPrefixCounter": 3}
        return topotest.json_cmp(output, expected)

    r2.vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          no neighbor 192.168.255.2 sender-as-path-loop-detection
        """
    )

    r2.vtysh_cmd(
        """
        clear bgp *
        """
    )
    test_func = functools.partial(_bgp_reset_route_to_r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed bgp to reset route"


def test_loop_detection_on_peer_group():
    tgen = get_topogen()

    r2 = tgen.gears["r2"]

    def _bgp_suppress_route_to_r1():
        output = json.loads(
            r2.vtysh_cmd("show ip bgp neighbor 192.168.255.2 advertised-routes json")
        )
        expected = {"totalPrefixCounter": 0}
        return topotest.json_cmp(output, expected)

    def _bgp_suppress_route_to_r3():
        output = json.loads(
            r2.vtysh_cmd("show ip bgp neighbor 192.168.254.2 advertised-routes json")
        )
        expected = {"totalPrefixCounter": 2}
        return topotest.json_cmp(output, expected)

    r2.vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          neighbor loop_group peer-group
          neighbor 192.168.255.2 peer-group loop_group
          neighbor loop_group sender-as-path-loop-detection
        """
    )

    r2.vtysh_cmd(
        """
        clear bgp *
        """
    )

    test_func = functools.partial(_bgp_suppress_route_to_r3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Route 172.16.255.253/32 should not be sent to r3 from r2"

    test_func = functools.partial(_bgp_suppress_route_to_r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Routes should not be sent to r1 from r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
