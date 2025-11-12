#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_v6_vtep.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by 6WIND
# Copyright (c) 2025 by cisco Systems Inc.
#

"""
 test_bgp_evpn_v6_vtep.py: Test the FRR BGP daemon with BGP IPv6 interface,
 IPv6 VTEP Address and with route advertisements on a separate netns.
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
    tgen.add_router("r3")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])


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

    cmds_r2 = [  # config routing 101
        "ip link add name bridge-101 up type bridge stp_state 0",
        "ip link set bridge-101 master {}-vrf-101",
        "ip link set dev bridge-101 up",
        "ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev r2-eth0 local 192:168:100::41",
        "ip link set dev vxlan-101 master bridge-101",
        "ip link set vxlan-101 up type bridge_slave learning off flood off mcast_flood off",
    ]

    cmds_r3 = [  # config routing 102
        "ip link add name bridge-102 up type bridge stp_state 0",
        "ip link set bridge-102 master {}-vrf-102",
        "ip link set dev bridge-102 up",
        "ip link add name vxlan-102 type vxlan id 102 dstport 4789 dev r3-eth0 local 192:168:100::61",
        "ip link set dev vxlan-102 master bridge-102",
        "ip link set vxlan-102 up type bridge_slave learning off flood off mcast_flood off",
    ]

    # cmds_r1_netns_method3 = [
    #     "ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local 192:168:100::21",
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
        logger.info("cmd to r2: " + cmd.format("r2", 101))
        output = router.cmd_raises(cmd.format("r2", 101))
        logger.info("result: " + output)

    for cmd in cmds_r2:
        logger.info("cmd to r2: " + cmd.format("r2"))
        output = router.cmd_raises(cmd.format("r2"))
        logger.info("result: " + output)

    router = tgen.gears["r3"]
    for cmd in cmds_vrflite:
        logger.info("cmd to r3: " + cmd.format("r3", 102))
        output = router.cmd_raises(cmd.format("r3", 102))
        logger.info("result: " + output)

    for cmd in cmds_r3:
        logger.info("cmd to r3: " + cmd.format("r3"))
        output = router.cmd_raises(cmd.format("r3"))
        logger.info("result: " + output)

    tgen.net["r1"].cmd_raises(
        "ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev r1-eth0 local 192:168:100::21"
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

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        if rname == "r1":
            router.use_netns_vrf()
            router.load_frr_config(os.path.join(CWD, "{}/frr-v6-vtep.conf".format(rname)))
        else:
            router.load_frr_config(os.path.join(CWD, "{}/frr-v6-vtep.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.net["r1"].delete_netns("r1-vrf-101")
    tgen.stop_topology()


def _test_evpn_ping_router(pingrouter, ipv4_only=False):
    """
    internal function to check ping between r1 and r2
    """
    # Check IPv4 and IPv6 connectivity between r1 and r2 ( routing vxlan evpn)
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

    if ipv4_only:
        return

    logger.info("Check Ping IPv6 from  R1(r1-vrf-101) to R2(r2-vrf-101 = fd00::2)")
    output = pingrouter.run("ip netns exec r1-vrf-101 ping fd00::2 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assert 0, "expected ping IPv6 from R1(r1-vrf-101) to R2(fd00::2) should be ok"
    else:
        logger.info("Check Ping IPv6 from R1(r1-vrf-101) to R2(fd00::2) OK")


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
        json_file = "{}/{}/bgp_l2vpn_evpn_routes_v6_vtep.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            assert 0, "bgp_l2vpn_evpn_routes_v6_vtep.json file not found"

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


def test_protocols_dump_info():
    """
    Dump EVPN information
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
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


def test_router_check_ip():
    """
    Check routes are correctly installed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        "fd00::2/128": [
            {
                "prefix": "fd00::2/128",
                "vrfName": "r1-vrf-101",
                "nexthops": [
                    {
                        "ip": "192:168:100::41",
                    }
                ],
            }
        ]
    }
    result = topotest.router_json_cmp(
        tgen.gears["r1"], "show ipv6 route vrf r1-vrf-101 fd00::2/128 json", expected
    )
    assert result is None, "ipv6 route check failed"


def _test_router_check_evpn_contexts(router):
    """
    Check EVPN nexthops and RMAC number  are correctly configured
    """
    expected = {
        "101": {
            "numNextHops": 1,
            "192:168:100::41": {
                "nexthopIp": "192:168:100::41",
            },
        }
    }

    result = topotest.router_json_cmp(
        router, "show evpn next-hops vni all json", expected
    )
    assert result is None, "evpn next-hops check failed"

    expected = {"101": {"numRmacs": 1}}
    result = topotest.router_json_cmp(router, "show evpn rmac vni all json", expected)
    assert result is None, "evpn rmac number check failed"


def test_router_check_evpn_contexts():
    """
    Check EVPN nexthops and RMAC number  are correctly configured
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_router_check_evpn_contexts(tgen.gears["r1"])


def test_evpn_ping():
    """
    Check ping between R1 and R2 is ok
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_evpn_ping_router(tgen.gears["r1"])


def test_evpn_disable_routemap():
    """
    Check the removal of a route-map on R2. More EVPN Prefixes are expected
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal\n
        router bgp 65000 vrf r2-vrf-101\n
        address-family l2vpn evpn\n
        advertise ipv4 unicast\n
        advertise ipv6 unicast\n
        """
    )
    router = tgen.gears["r1"]
    json_file = "{}/{}/bgp_l2vpn_evpn_routes_all_v6_vtep.json".format(CWD, router.name)
    if not os.path.isfile(json_file):
        assert 0, "bgp_l2vpn_evpn_routes_all_v6_vtep.json file not found"

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


def test_evpn_remove_ip():
    """
    Check the removal of an EVPN route is correctly handled
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    config_no_ipv6 = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf r2-vrf-101",
                "address-family ipv6 unicast",
                "no network fd00::3/128",
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


def test_router_check_evpn_contexts_again():
    """
    Check EVPN nexthops and RMAC number  are correctly configured
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_router_check_evpn_contexts(tgen.gears["r1"])


def test_evpn_ping_again():
    """
    Check ping between R1 and R2 is ok
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_evpn_ping_router(tgen.gears["r1"], ipv4_only=True)


def _test_wait_for_multipath_convergence(router):
    """
    Wait for multipath convergence on R2
    """
    expected = {
        "192.168.102.21/32": [
            {"nexthops": [{"ip": "192:168:100::21"}, {"ip": "192:168:100::21"}]}
        ]
    }
    # Using router_json_cmp instead of verify_fib_routes, because we need to check for
    # two next-hops with the same IP address.
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip route vrf r2-vrf-101 192.168.102.21/32 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert (
        result is None
    ), "R2 does not have two next-hops for 192.168.102.21/32 JSON output mismatches"


def _test_rmac_present(router):
    """
    Check that the RMAC is present on R2
    """
    output = router.vtysh_cmd("show evpn rmac vni 101", isjson=False)
    logger.info("==== result from show evpn rmac vni 101")
    logger.info(output)

    expected = {"numRmacs": 1}
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show evpn rmac vni 101 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "evpn rmac is missing on router"


def _validate_singleton_equivalent_nhg(router, vrf, prefix):
    """
    Internal validation function for singleton-equivalent NHG optimization.
    Returns None on success, error string on failure.
    """
    route = router.vtysh_cmd(f"show ip route vrf {vrf} {prefix} json", isjson=True)
    if prefix not in route:
        return f"Route {prefix} not found"
    rcv_nhg_id = route[prefix][0].get("receivedNexthopGroupId")
    ins_nhg_id = route[prefix][0].get("installedNexthopGroupId")
    if not rcv_nhg_id or not ins_nhg_id:
        return "Received or Installed NHG ID not found"
    if rcv_nhg_id == ins_nhg_id:
        return f"Received NHG ({rcv_nhg_id}) should differ from Installed NHG ({ins_nhg_id})"

    rcv_nhg = router.vtysh_cmd(f"show nexthop-group rib {rcv_nhg_id} json", isjson=True)
    ins_nhg = router.vtysh_cmd(f"show nexthop-group rib {ins_nhg_id} json", isjson=True)
    rcv_depends = rcv_nhg[str(rcv_nhg_id)].get("depends", [])
    if ins_nhg_id not in rcv_depends and str(ins_nhg_id) not in [
        str(d) for d in rcv_depends
    ]:
        return f"Received NHG {rcv_nhg_id} depends {rcv_depends} does not include Installed NHG {ins_nhg_id}"
    logger.info(
        f"Route {prefix}: Received NHG={rcv_nhg_id}, Installed NHG={ins_nhg_id}"
    )
    return None


def _test_singleton_equivalent_nhg_optimization(router, vrf, prefix):
    """
    Verify singleton-equivalent NHG optimization for duplicate nexthops:
    - Installed NHG ID should differ from Received NHG ID
    - Received NHG should have 2 nexthops (duplicates) and NOT be installed
    - Received NHG should depend on Installed NHG
    - Installed NHG should be singleton (1 nexthop) and have Installed flag
    """
    test_func = partial(_validate_singleton_equivalent_nhg, router, vrf, prefix)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert (
        result is None
    ), f"Singleton-equivalent NHG optimization check failed for {prefix}"
    logger.info(f"Singleton-equivalent NHG optimization verified for {prefix}")


def test_evpn_multipath():
    """
    Configure a second path between R1 and R2, then flap it a couple times.
    As long as the route is present, the RMAC should be present at the same time.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    evpn_multipath = {
        "r1": {
            "raw_config": [
                "interface r1-eth0",
                "ipv6 address 192:168:99::21/96",
                "router bgp 65000",
                "neighbor 192:168:99::41 remote-as 65000",
                "neighbor 192:168:99::41 capability extended-nexthop",
                "neighbor 192:168:99::41 update-source 192:168:99::21",
                "address-family l2vpn evpn",
                "neighbor 192:168:99::41 activate",
                "neighbor 192:168:99::41 route-map rmap_r1 in",
            ]
        },
        "r2": {
            "raw_config": [
                "interface r2-eth0",
                "ipv6 address 192:168:99::41/96",
                "router bgp 65000",
                "neighbor 192:168:99::21 remote-as 65000",
                "neighbor 192:168:99::21 capability extended-nexthop",
                "neighbor 192:168:99::21 update-source 192:168:99::41",
                "address-family l2vpn evpn",
                "neighbor 192:168:99::21 activate",
            ]
        },
    }

    logger.info("==== Configure second path between R1 and R2")
    result = apply_raw_config(tgen, evpn_multipath)
    assert (
        result is True
    ), "Failed to configure second path between R1 and R2, Error: {} ".format(result)

    dut = tgen.gears["r2"]
    dut_peer = tgen.gears["r1"]
    _test_wait_for_multipath_convergence(dut)
    _test_rmac_present(dut)

    for i in range(4):
        peer = "192:168:100::41" if i % 2 == 0 else "192:168:99::41"
        dut_peer.vtysh_cmd("clear bgp {0}".format(peer))
        _test_wait_for_multipath_convergence(dut)
        _test_rmac_present(dut)

    _test_singleton_equivalent_nhg_optimization(dut, "r2-vrf-101", "192.168.102.21/32")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
