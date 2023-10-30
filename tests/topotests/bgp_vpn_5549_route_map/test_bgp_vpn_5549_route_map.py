#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if we can override VPN underlay next-hop from PE1 to PE2.
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
    tgen.add_router("cpe1")
    tgen.add_router("cpe2")
    tgen.add_router("pe1")
    tgen.add_router("pe2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["cpe1"])
    switch.add_link(tgen.gears["pe1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["pe1"])
    switch.add_link(tgen.gears["pe2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["pe2"])
    switch.add_link(tgen.gears["cpe2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["pe1"]
    pe2 = tgen.gears["pe2"]

    pe1.run("ip link add RED type vrf table 1001")
    pe1.run("ip link set up dev RED")
    pe2.run("ip link add RED type vrf table 1001")
    pe2.run("ip link set up dev RED")
    pe1.run("ip link set pe1-eth0 master RED")
    pe2.run("ip link set pe2-eth1 master RED")

    pe1.run("sysctl -w net.ipv4.ip_forward=1")
    pe2.run("sysctl -w net.ipv4.ip_forward=1")
    pe1.run("sysctl -w net.mpls.conf.pe1-eth0.input=1")
    pe2.run("sysctl -w net.mpls.conf.pe2-eth1.input=1")

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_LDP, os.path.join(CWD, "{}/ldpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_vpn_5549():
    tgen = get_topogen()

    pe2 = tgen.gears["pe2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_vpn_nexthop_changed():
        output = json.loads(pe2.vtysh_cmd("show bgp ipv4 vpn json"))
        expected = {
            "routes": {
                "routeDistinguishers": {
                    "192.168.1.2:2": {
                        "172.16.255.1/32": [
                            {"valid": True, "nexthops": [{"ip": "2001:db8::1"}]}
                        ],
                        "192.168.1.0/24": [
                            {"valid": True, "nexthops": [{"ip": "2001:db8:1::1"}]}
                        ],
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_verify_v4_nexthop_validity():
        output = json.loads(tgen.gears["cpe1"].vtysh_cmd("show bgp nexthop json"))
        expected = {
            "ipv4": {
                "192.168.1.2": {
                    "valid": True,
                    "complete": True,
                    "igpMetric": 0,
                    "pathCount": 0,
                    "nexthops": [{"interfaceName": "cpe1-eth0"}],
                },
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_verify_v6_global_nexthop_validity():
        output = json.loads(tgen.gears["pe2"].vtysh_cmd("show bgp nexthop json"))
        expected = {
            "ipv6": {
                "2001:db8::1": {
                    "valid": True,
                    "complete": True,
                    "igpMetric": 0,
                    "pathCount": 2,
                    "nexthops": [{"interfaceName": "pe2-eth0"}],
                },
                "2001:db8:1::1": {
                    "valid": True,
                    "complete": True,
                    "igpMetric": 10,
                    "pathCount": 2,
                    "peer": "2001:db8:1::1",
                    "nexthops": [{"interfaceName": "pe2-eth0"}],
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_vpn_nexthop_changed)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed overriding IPv6 next-hop for VPN underlay"

    test_func = functools.partial(_bgp_verify_v4_nexthop_validity)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "IPv4 nexthop is invalid"

    test_func = functools.partial(_bgp_verify_v6_global_nexthop_validity)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "IPv6 nexthop is invalid"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
