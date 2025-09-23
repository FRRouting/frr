#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn.py
#
# Copyright (c) 2025 by Nvidia Inc.
#                       Donald Sharp
#

"""
test_bgp_evpn_implied.py: Test the FRR BGP daemon implied bgp
instance creation by the fact that a matching vni exists
in the bgp evpn table.
The goal here is to show that the ability to do show commands
in the hidden created vrf still works.  Otherwise the 
show ip route vrf X commands work and show the bgp routes
but it is impossible to see the route in the bgp table
for the vrf.  Notice on r2 that there is no config
for bgp in the 2 vrf's, yet we have bgp routes in the
vrf tables in zebra.
"""

import json
from functools import partial
import os
import sys
import pytest
import platform
import re

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import verify_bgp_rib
from lib.common_config import apply_raw_config
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

    connect_routers(tgen, "rr", "r1")
    connect_routers(tgen, "rr", "r2")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info(
            'BGP EVPN RT5 NETNS tests will not run (have kernel "{}", but it requires 4.18)'.format(
                krel
            )
        )
        return pytest.skip("Skipping BGP EVPN RT5 NETNS Test. Kernel not supported")

    r1 = tgen.net["r1"]
    for vrf in (101, 102):
        ns = "vrf-{}".format(vrf)
        r1.add_netns(ns)
        r1.cmd_raises(
            """
ip link add loop{0} type dummy
ip link add vxlan-{0} type vxlan id {0} dstport 4789 dev eth-rr local 192.168.1.1
""".format(
                vrf
            )
        )
        r1.set_intf_netns("loop{}".format(vrf), ns, up=True)
        r1.set_intf_netns("vxlan-{}".format(vrf), ns, up=True)
        r1.cmd_raises(
            """
ip -n vrf-{0} link set lo up
ip -n vrf-{0} link add bridge-{0} up address {1} type bridge stp_state 0
ip -n vrf-{0} link set dev vxlan-{0} master bridge-{0}
ip -n vrf-{0} link set bridge-{0} up
ip -n vrf-{0} link set vxlan-{0} up
""".format(
                vrf, _create_rmac(1, vrf)
            )
        )

        tgen.gears["r2"].cmd(
            """
ip link add vrf-{0} type vrf table {0}
ip link set dev vrf-{0} up
ip link add loop{0} type dummy
ip link set dev loop{0} master vrf-{0}
ip link set dev loop{0} up
ip link add bridge-{0} up address {1} type bridge stp_state 0
ip link set bridge-{0} master vrf-{0}
ip link set dev bridge-{0} up
ip link add vxlan-{0} type vxlan id {0} dstport 4789 dev eth-rr local 192.168.2.2
ip link set dev vxlan-{0} master bridge-{0}
ip link set vxlan-{0} up type bridge_slave learning off flood off mcast_flood off
""".format(
                vrf, _create_rmac(2, vrf)
            )
        )

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        if rname == "r1":
            router.use_netns_vrf()
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.net["r1"].delete_netns("vrf-101")
    tgen.net["r1"].delete_netns("vrf-102")
    tgen.stop_topology()

def _create_rmac(router, vrf):
    """
    Creates RMAC for a given router and vrf
    """
    return "52:54:00:00:{:02x}:{:02x}".format(router, vrf)


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        logger.info(
            "Checking BGP L2VPN EVPN routes for convergence on {}".format(router.name)
        )
        json_file = "{}/{}/bgp_l2vpn_evpn_routes.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp l2vpn evpn json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_protocols_check_implied_is_working():
    """
    Dump EVPN information
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # Check IPv4/IPv6 routing tables.
    expected = {
        "vrfName": "vrf-101",
        "routerId": "10.0.101.2",
        "defaultLocPrf": 100,
        "localAS": 65000,
        "routes": {
            "10.0.101.1/32": [{
                "valid": True,
                "bestpath": True,
                "pathFrom": "internal",
                "prefix": "10.0.101.1",
                "prefixLen": 32,
                "network": "10.0.101.1/32",
                "metric": 0,
                "locPrf": 100,
                "weight": 0,
                "peerId": "192.168.2.101",
                "path": "",
                "origin": "IGP",
                "announceNexthopSelf": True,
                "nexthops": [{
                    "ip": "192.168.1.1",
                    "hostname": "rr",
                    "afi": "ipv4",
                    "used": True
                }]
            }]
        },
        "totalRoutes": 1,
        "totalPaths": 1
    }
    
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp vrf vrf-101 ipv4 uni json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = '"r2" BGP VRF vrf-101 IPv4 JSON output mismatches'
    assert result is None, assertmsg

    # Check vrf-102 IPv4 routing table
    expected_vrf102 = {
        "vrfName": "vrf-102",
        "routerId": "10.0.102.2",
        "defaultLocPrf": 100,
        "localAS": 65000,
        "routes": {
            "10.0.102.1/32": [{
                "valid": True,
                "bestpath": True,
                "pathFrom": "internal",
                "prefix": "10.0.102.1",
                "prefixLen": 32,
                "network": "10.0.102.1/32",
                "metric": 0,
                "locPrf": 100,
                "weight": 0,
                "peerId": "192.168.2.101",
                "path": "",
                "origin": "IGP",
                "announceNexthopSelf": True,
                "nexthops": [{
                    "ip": "192.168.1.1",
                    "hostname": "rr",
                    "afi": "ipv4",
                    "used": True
                }]
            }]
        },
        "totalRoutes": 1,
        "totalPaths": 1
    }
    
    test_func_vrf102 = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp vrf vrf-102 ipv4 uni json",
        expected_vrf102,
    )
    _, result_vrf102 = topotest.run_and_expect(test_func_vrf102, None, count=20, wait=1)
    assertmsg_vrf102 = '"r2" BGP VRF vrf-102 IPv4 JSON output mismatches'
    assert result_vrf102 is None, assertmsg_vrf102

    # Check that routes are properly added to VRF routing table
    expected_ip_route_vrf101 = {
        "10.0.101.1/32": [{
            "prefix": "10.0.101.1/32",
            "prefixLen": 32,
            "protocol": "bgp",
            "vrfName": "vrf-101",
            "selected": True,
            "destSelected": True,
            "distance": 200,
            "metric": 0,
            "installed": True,
            "nexthops": [{
                "flags": 267,
                "fib": True,
                "ip": "192.168.1.1",
                "afi": "ipv4",
                "interfaceName": "bridge-101",
                "active": True,
                "onLink": True,
                "weight": 1
            }]
        }],
    }
    
    test_func_ip_route = partial(
        topotest.router_json_cmp,
        r2,
        "show ip route vrf vrf-101 json",
        expected_ip_route_vrf101,
    )
    _, result_ip_route = topotest.run_and_expect(test_func_ip_route, None, count=20, wait=1)
    assertmsg_ip_route = '"r2" IP route VRF vrf-101 JSON output mismatches'
    assert result_ip_route is None, assertmsg_ip_route

    # Check that routes are properly added to VRF-102 routing table
    expected_ip_route_vrf102 = {
        "10.0.102.1/32": [{
            "prefix": "10.0.102.1/32",
            "prefixLen": 32,
            "protocol": "bgp",
            "vrfName": "vrf-102",
            "selected": True,
            "destSelected": True,
            "distance": 200,
            "metric": 0,
            "installed": True,
            "nexthops": [{
                "flags": 267,
                "fib": True,
                "ip": "192.168.1.1",
                "afi": "ipv4",
                "interfaceName": "bridge-102",
                "active": True,
                "onLink": True,
                "weight": 1
            }]
        }],
    }
    
    test_func_ip_route_vrf102 = partial(
        topotest.router_json_cmp,
        r2,
        "show ip route vrf vrf-102 json",
        expected_ip_route_vrf102,
    )
    _, result_ip_route_vrf102 = topotest.run_and_expect(test_func_ip_route_vrf102, None, count=20, wait=1)
    assertmsg_ip_route_vrf102 = '"r2" IP route VRF vrf-102 JSON output mismatches'
    assert result_ip_route_vrf102 is None, assertmsg_ip_route_vrf102


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
