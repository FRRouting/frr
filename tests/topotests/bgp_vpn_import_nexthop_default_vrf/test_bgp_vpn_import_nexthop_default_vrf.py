#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

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
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.run("ip link add CUSTOMER-A type vrf table 1001")
    r1.run("ip link set up dev CUSTOMER-A")
    r1.run("ip link set r1-eth1 master CUSTOMER-A")

    r2.run("ip link add CUSTOMER-A type vrf table 1001")
    r2.run("ip link set up dev CUSTOMER-A")
    r2.run("ip link set r2-eth1 master CUSTOMER-A")

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_issue_12502():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp vrf CUSTOMER-A ipv4 unicast json"))
        expected = {
            "routes": {
                "192.168.2.0/24": [
                    {
                        "valid": True,
                        "pathFrom": "external",
                        "prefix": "192.168.2.0",
                        "prefixLen": 24,
                        "path": "65002",
                        "nhVrfName": "default",
                        "nexthops": [
                            {
                                "ip": "192.168.179.5",
                                "hostname": "r1",
                                "afi": "ipv4",
                                "used": True,
                            }
                        ],
                    }
                ]
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to see 192.168.2.0/24 with a valid next-hop"

    def _vrf_route_imported_to_zebra():
        output = json.loads(
            r1.vtysh_cmd("show ip route vrf CUSTOMER-A 192.168.2.0/24 json")
        )
        expected = {
            "192.168.2.0/24": [
                {
                    "prefix": "192.168.2.0/24",
                    "protocol": "bgp",
                    "vrfName": "CUSTOMER-A",
                    "selected": True,
                    "installed": True,
                    "table": 1001,
                    "internalNextHopNum": 1,
                    "internalNextHopActiveNum": 1,
                    "nexthops": [
                        {
                            "fib": True,
                            "ip": "192.168.179.5",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth0",
                            "vrf": "default",
                            "active": True,
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_vrf_route_imported_to_zebra)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Failed to see 192.168.2.0/24 to be imported into default VRF (Zebra)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
