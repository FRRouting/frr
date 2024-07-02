#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by 6WIND
#

"""
 test_bgp_evpn.py: Test the FRR BGP daemon with BGP IPv6 interface
 with route advertisements on a separate netns.
"""

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

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info(
            'BGP EVPN RT5 NETNS tests will not run (have kernel "{}", but it requires 4.18)'.format(
                krel
            )
        )
        return pytest.skip("Skipping BGP EVPN RT5 NETNS Test. Kernel not supported")

    # create VRF vrf-101 on R1 and R2
    # create loop101
    cmds_vrflite = [
        "ip link add {}-vrf-101 type vrf table 101",
        "ip ru add oif {}-vrf-101 table 101",
        "ip ru add iif {}-vrf-101 table 101",
        "ip link set dev {}-vrf-101 up",
        "ip link add loop101 type dummy",
        "ip link set dev loop101 master {}-vrf-101",
        "ip link set dev loop101 up",
    ]

    cmds_r2 = [  # config routing 101
        "ip link add name bridge-101 up type bridge stp_state 0",
        "ip link set bridge-101 master {}-vrf-101",
        "ip link set dev bridge-101 up",
        "ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev r2-eth0 local 192.168.100.41",
        "ip link set dev vxlan-101 master bridge-101",
        "ip link set vxlan-101 up type bridge_slave learning off flood off mcast_flood off",
    ]

    # cmds_r1_netns_method3 = [
    #     "ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local 192.168.100.21",
    #     "ip link set dev vxlan-{1} netns {0}-vrf-{1}",
    #     "ip netns exec {0}-vrf-{1} ip li set dev lo up",
    #     "ip netns exec {0}-vrf-{1} ip link add name bridge-{1} up type bridge stp_state 0",
    #     "ip netns exec {0}-vrf-{1} ip link set dev vxlan-{1} master bridge-{1}",
    #     "ip netns exec {0}-vrf-{1} ip link set bridge-{1} up",
    #     "ip netns exec {0}-vrf-{1} ip link set vxlan-{1} up",
    # ]

    router = tgen.gears["r1"]

    ns = "r1-vrf-101"
    tgen.net["r1"].add_netns(ns)
    tgen.net["r1"].cmd_raises("ip link add loop101 type dummy")
    tgen.net["r1"].set_intf_netns("loop101", ns, up=True)

    router = tgen.gears["r2"]
    for cmd in cmds_vrflite:
        logger.info("cmd to r2: " + cmd.format("r2"))
        output = router.cmd_raises(cmd.format("r2"))
        logger.info("result: " + output)

    for cmd in cmds_r2:
        logger.info("cmd to r2: " + cmd.format("r2"))
        output = router.cmd_raises(cmd.format("r2"))
        logger.info("result: " + output)

    tgen.net["r1"].cmd_raises(
        "ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev r1-eth0 local 192.168.100.21"
    )
    tgen.net["r1"].set_intf_netns("vxlan-101", "r1-vrf-101", up=True)
    tgen.net["r1"].cmd_raises("ip -n r1-vrf-101 link set lo up")
    tgen.net["r1"].cmd_raises(
        "ip -n r1-vrf-101 link add name bridge-101 up type bridge stp_state 0"
    )
    tgen.net["r1"].cmd_raises(
        "ip -n r1-vrf-101 link set dev vxlan-101 master bridge-101"
    )
    tgen.net["r1"].cmd_raises("ip -n r1-vrf-101 link set bridge-101 up")
    tgen.net["r1"].cmd_raises("ip -n r1-vrf-101 link set vxlan-101 up")

    for rname, router in router_list.items():
        if rname == "r1":
            router.load_config(TopoRouter.RD_MGMTD, None, "--vrfwnetns")
            router.load_config(
                TopoRouter.RD_ZEBRA,
                os.path.join(CWD, "{}/zebra.conf".format(rname)),
                "--vrfwnetns",
            )
        else:
            router.load_config(
                TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
            )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.net["r1"].delete_netns("r1-vrf-101")
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    topotest.sleep(4, "waiting 4 seconds for bgp convergence")
    # Check IPv4/IPv6 routing tables.
    output = tgen.gears["r1"].vtysh_cmd("show bgp l2vpn evpn", isjson=False)
    logger.info("==== result from show bgp l2vpn evpn")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show bgp l2vpn evpn route detail", isjson=False
    )
    logger.info("==== result from show bgp l2vpn evpn route detail")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bgp vrf r1-vrf-101 ipv4", isjson=False)
    logger.info("==== result from show bgp vrf r1-vrf-101 ipv4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bgp vrf r1-vrf-101 ipv6", isjson=False)
    logger.info("==== result from show bgp vrf r1-vrf-101 ipv6")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bgp vrf r1-vrf-101", isjson=False)
    logger.info("==== result from show bgp vrf r1-vrf-101 ")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-vrf-101", isjson=False)
    logger.info("==== result from show ip route vrf r1-vrf-101")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-vrf-101", isjson=False)
    logger.info("==== result from show ipv6 route vrf r1-vrf-101")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show evpn vni detail", isjson=False)
    logger.info("==== result from show evpn vni detail")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show evpn next-hops vni all", isjson=False)
    logger.info("==== result from show evpn next-hops vni all")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show evpn rmac vni all", isjson=False)
    logger.info("==== result from show evpn rmac vni all")
    logger.info(output)

    expected = {
        "fd00::2/128": [
            {
                "prefix": "fd00::2/128",
                "vrfName": "r1-vrf-101",
                "nexthops": [
                    {
                        "ip": "::ffff:c0a8:6429",
                    }
                ],
            }
        ]
    }
    result = topotest.router_json_cmp(
        tgen.gears["r1"], "show ipv6 route vrf r1-vrf-101 fd00::2/128 json", expected
    )
    assert result is None, "ipv6 route check failed"

    expected = {
        "101": {
            "numNextHops": 2,
            "192.168.100.41": {
                "nexthopIp": "192.168.100.41",
            },
            "::ffff:c0a8:6429": {
                "nexthopIp": "::ffff:c0a8:6429",
            },
        }
    }
    result = topotest.router_json_cmp(
        tgen.gears["r1"], "show evpn next-hops vni all json", expected
    )
    assert result is None, "evpn next-hops check failed"

    expected = {"101": {"numRmacs": 1}}
    result = topotest.router_json_cmp(
        tgen.gears["r1"], "show evpn rmac vni all json", expected
    )
    assert result is None, "evpn rmac number check failed"

    # Check IPv4 and IPv6 connectivity between r1 and r2 ( routing vxlan evpn)
    pingrouter = tgen.gears["r1"]
    logger.info(
        "Check Ping IPv4 from  R1(r1-vrf-101) to R2(r2-vrf-101 = 192.168.101.41)"
    )
    output = pingrouter.run("ip netns exec r1-vrf-101 ping 192.168.101.41 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = (
            "expected ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) should be ok"
        )
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) OK")

    logger.info("Check Ping IPv6 from  R1(r1-vrf-101) to R2(r2-vrf-101 = fd00::2)")
    output = pingrouter.run("ip netns exec r1-vrf-101 ping fd00::2 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assert 0, "expected ping IPv6 from R1(r1-vrf-101) to R2(fd00::2) should be ok"
    else:
        logger.info("Check Ping IPv6 from R1(r1-vrf-101) to R2(fd00::2) OK")

    config_no_ipv6 = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf r2-vrf-101",
                "address-family ipv6 unicast",
                "no network fd00::2/128",
            ]
        }
    }

    logger.info("==== Remove IPv6 network on R2")
    result = apply_raw_config(tgen, config_no_ipv6)
    assert result is True, "Failed to remove IPv6 network on R2, Error: {} ".format(
        result
    )
    ipv6_routes = {
        "r1": {
            "static_routes": [
                {
                    "vrf": "r1-vrf-101",
                    "network": ["fd00::2/128"],
                }
            ]
        }
    }
    result = verify_bgp_rib(tgen, "ipv6", "r1", ipv6_routes, expected=False)
    assert result is not True, "expect IPv6 route fd00::2/128 withdrawn"
    output = tgen.gears["r1"].vtysh_cmd("show evpn next-hops vni all", isjson=False)
    logger.info("==== result from show evpn next-hops vni all")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show evpn rmac vni all", isjson=False)
    logger.info("==== result from show evpn next-hops vni all")
    logger.info(output)

    expected = {
        "101": {
            "numNextHops": 1,
            "192.168.100.41": {
                "nexthopIp": "192.168.100.41",
            },
        }
    }
    result = topotest.router_json_cmp(
        tgen.gears["r1"], "show evpn next-hops vni all json", expected
    )
    assert result is None, "evpn next-hops check failed"

    expected = {"101": {"numRmacs": 1}}
    result = topotest.router_json_cmp(
        tgen.gears["r1"], "show evpn rmac vni all json", expected
    )
    assert result is None, "evpn rmac number check failed"

    logger.info(
        "Check Ping IPv4 from  R1(r1-vrf-101) to R2(r2-vrf-101 = 192.168.101.41)"
    )
    output = pingrouter.run("ip netns exec r1-vrf-101 ping 192.168.101.41 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = (
            "expected ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) should be ok"
        )
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) OK")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
