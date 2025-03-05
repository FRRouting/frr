#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_leaking.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by 6WIND
# Copyright (c) 2025 by Deutsche Telekom AG
#

"""
 test_bgp_evpn_leaking.py: Test the FRR BGP daemon with EVPN and
 route leaking.
"""

import json
from functools import partial
import os
import sys
import pytest
import platform

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
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    loopbacks = {
        "r1": "192.168.100.21",
        "r2": "192.168.100.41"
    }

    # create VRF vrf-101 on R1, R2, R3
    # create loop101
    cmds_vrflite = [
        "ip link add {0}-vrf-{1} type vrf table {1}",
        "ip ru add oif {0}-vrf-{1} table {1}",
        "ip ru add iif {0}-vrf-{1} table {1}",
        "ip link set dev {0}-vrf-{1} up",
        "ip link add loop{1} type dummy",
        "ip link set dev loop{1} master {0}-vrf-{1}",
        "ip link set dev loop{1} up",
    ]

    cmds_l3vni = [  # config routing 101
        "ip link add name bridge-{1} up type bridge stp_state 0",
        "ip link set bridge-{1} master {0}-vrf-{1}",
        "ip link set dev bridge-{1} up",
        "ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local {2}",
        "ip link set dev vxlan-{1} master bridge-{1}",
        "ip link set vxlan-{1} up type bridge_slave learning off flood off mcast_flood off",
    ]

    for router_name in router_list.keys():
        router = tgen.gears[router_name]
        for vni in [101, 102]:
            for cmd in cmds_vrflite:
                logger.info("cmd to %s: " % router_name + cmd.format(router_name, vni))
                output = router.cmd_raises(cmd.format(router_name, vni))
                logger.info("result: " + output)
            for cmd in cmds_l3vni:
                logger.info("cmd to %s: " % router_name + cmd.format(router_name, vni, loopbacks[router_name]))
                output = router.cmd_raises(cmd.format(router_name, vni, loopbacks[router_name]))
                logger.info("result: " + output)

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # Check BGP IPv4 routing tables on r1
    logger.info("Checking BGP L2VPN EVPN routes for convergence on r1")

    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        json_file = "{}/{}/bgp_l2vpn_evpn_routes.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            assert 0, "bgp_l2vpn_evpn_routes.json file not found"

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


def _test_router_rmac():
    """
    Check EVPN nexthops and RMAC number are correctly configured
    """

    tgen = get_topogen()
    peers = {
        "r1": "r2",
        "r2": "r1"
    }

    for rname, peer in peers.items():
        router = tgen.gears[rname]
        peer_router = tgen.gears[peer]

        remote_macs = router.vtysh_cmd("show evpn rmac vni all json", isjson=True)
        local_macs = peer_router.vtysh_cmd("show vrf vni json", isjson=True)

        for data in remote_macs.values():
            assert len(data.keys()) == 2, "RMACs should have only 2 keys: numRmacs and a single RMAC: {}".format(data.keys())

        remote_vni_to_mac = {str(vni): [key for key in data.keys() if key != "numRmacs"][0] for vni, data in remote_macs.items()}
        local_vni_to_mac = {str(vrf["vni"]): vrf["routerMac"] for vrf in local_macs["vrfs"]}
        logger.info("RMACs on %s (received from %s): %s", rname, peer, remote_vni_to_mac)
        logger.info("Local VRF RMACs on %s: %s", peer, local_vni_to_mac)
        result = topotest.json_cmp(remote_vni_to_mac, local_vni_to_mac, exact=True)
        assert result is None, "RMACs mismatch between {} and {}".format(rname, peer)


def _test_router_ip_routes():
    """
    Check IP routes are correctly configured
    """
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-vrf-101", isjson=False)
    logger.info("==== result from show ip route vrf r1-vrf-101")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-vrf-101", isjson=False)
    logger.info("==== result from show ipv6 route vrf r1-vrf-101")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show evpn rmac vni all", isjson=False)
    logger.info("==== result from show evpn rmac vni all")
    logger.info(output)


def test_router_rmac_before_leak():
    """
    Check EVPN nexthops and RMAC number are correctly configured
    """
    _test_router_ip_routes()
    _test_router_rmac()


def test_evpn_leaking():
    """
    Leak from VRF 102 to VRF 101 on R1 to check that RMACs are not affected
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    config_leaking = {
        "r1": {
            "raw_config": [
                "router bgp 65000 vrf r1-vrf-101",
                "address-family ipv4 unicast",
                "import vrf r1-vrf-102",
                "address-family ipv6 unicast",
                "import vrf r1-vrf-102",
            ]
        }
    }

    logger.info("==== Configure Leaking on R1")
    result = apply_raw_config(tgen, config_leaking)
    assert result is True, "Failed to configure leaking on R1, Error: {} ".format(
        result
    )
    ipv4_routes = {
        "r1": {
            "static_routes": [
                {
                    "vrf": "r1-vrf-101",
                    "network": ["192.168.102.41/32"],
                }
            ]
        }
    }
    result = verify_bgp_rib(tgen, "ipv4", "r1", ipv4_routes, expected=True)
    assert result is True, "expect IPv4 routes from r1-vrf-102 leaked into r1-vrf-101"

    ipv6_routes = {
        "r1": {
            "static_routes": [
                {
                    "vrf": "r1-vrf-101",
                    "network": ["fd00:6::2/128"],
                }
            ]
        }
    }
    result = verify_bgp_rib(tgen, "ipv6", "r1", ipv6_routes, expected=True)
    assert result is True, "expect IPv6 routes from r1-vrf-102 leaked into r1-vrf-101"


def test_router_rmac_after_leak():
    """
    Check EVPN nexthops and RMAC number are correctly configured
    """
    _test_router_ip_routes()
    _test_router_rmac()


def test_evpn_additional_network():
    """
    Leak adding a route in VRF 102 on R2 (which gets leaked into VRF 101 on R1) to check that RMACs are not affected
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    config_leaking = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf r2-vrf-102",
                "address-family ipv4 unicast",
                "network 192.168.102.42/32",
                "address-family ipv6 unicast",
                "network fd00:6::3/128",
            ]
        }
    }

    logger.info("==== Configure additional network on R2")
    result = apply_raw_config(tgen, config_leaking)
    assert result is True, "Failed to configure leaking on R1, Error: {} ".format(
        result
    )
    ipv4_routes = {
        "r1": {
            "static_routes": [
                {
                    "vrf": "r1-vrf-101",
                    "network": ["192.168.102.42/32"],
                }
            ]
        }
    }
    result = verify_bgp_rib(tgen, "ipv4", "r1", ipv4_routes, expected=True)
    assert result is True, "expect new IPv4 routes on R1 (originating from R2) from r1-vrf-102 leaked into r1-vrf-101"

    ipv6_routes = {
        "r1": {
            "static_routes": [
                {
                    "vrf": "r1-vrf-101",
                    "network": ["fd00:6::3/128"],
                }
            ]
        }
    }
    result = verify_bgp_rib(tgen, "ipv6", "r1", ipv6_routes, expected=True)
    assert result is True, "expect new IPv6 routes on R1 (originating from R2) from r1-vrf-102 leaked into r1-vrf-101"


def test_router_rmac_after_additional_network():
    """
    Check EVPN nexthops and RMAC number are correctly configured
    """
    _test_router_ip_routes()
    _test_router_rmac()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
