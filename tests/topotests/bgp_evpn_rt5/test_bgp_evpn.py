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

    # create VRF vrf-101 on R1, R2
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
        "ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev r2-eth0 local 192.168.0.2",
        "ip link set dev vxlan-101 master bridge-101",
        "ip link set vxlan-101 up type bridge_slave learning off flood off mcast_flood off",
    ]

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

    tgen.net["r1"].cmd_raises(
        "ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev r1-eth0 local 192.168.0.1"
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
            router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
        else:
            router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.net["r1"].delete_netns("r1-vrf-101")
    tgen.stop_topology()


def _test_evpn_ping_router(pingrouter, ipv4_only=False, ipv6_only=False):
    """
    internal function to check ping between r1 and r2
    """
    # Check IPv4 and IPv6 connectivity between r1 and r2 ( routing vxlan evpn)
    if not ipv6_only:
        logger.info(
            "Check Ping IPv4 from  R1(r1-vrf-101) to R2(r2-vrf-101 = 192.168.101.41)"
        )
        output = pingrouter.run(
            "ip netns exec r1-vrf-101 ping 192.168.101.41 -f -c 1000"
        )
        logger.info(output)
        if "1000 packets transmitted, 1000 received" not in output:
            assertmsg = "expected ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) should be ok"
            assert 0, assertmsg
        else:
            logger.info("Check Ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) OK")

    if not ipv4_only:
        logger.info("Check Ping IPv6 from  R1(r1-vrf-101) to R2(r2-vrf-101 = fd00::2)")
        output = pingrouter.run("ip netns exec r1-vrf-101 ping fd00::2 -f -c 1000")
        logger.info(output)
        if "1000 packets transmitted, 1000 received" not in output:
            assert (
                0
            ), "expected ping IPv6 from R1(r1-vrf-101) to R2(fd00::2) should be ok"
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


def _print_evpn_nexthop_rmac(router):
    tgen = get_topogen()
    output = tgen.gears[router].vtysh_cmd("show evpn next-hops vni all", isjson=False)
    logger.info("==== result from {} show evpn next-hops vni all".format(router))
    logger.info(output)
    output = tgen.gears[router].vtysh_cmd("show evpn rmac vni all", isjson=False)
    logger.info("==== result from {}: show evpn rmac vni all".format(router))
    logger.info(output)


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
    _print_evpn_nexthop_rmac("r1")


def test_bgp_vrf_routes():
    """
    Check routes are correctly imported to VRF
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        for af in ("ipv4", "ipv6"):
            json_file = "{}/{}/bgp_vrf_{}_routes_detail.json".format(
                CWD, router.name, af
            )
            if not os.path.isfile(json_file):
                assert 0, "bgp vrf routes file not found"

            expected = json.loads(open(json_file).read())
            test_func = partial(
                topotest.router_json_cmp,
                router,
                "show bgp vrf {}-vrf-101 {} unicast detail json".format(
                    router.name, af
                ),
                expected,
            )
            _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
            assertmsg = '"{}" JSON output mismatches'.format(router.name)
            assert result is None, assertmsg


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
                        "ip": "::ffff:192.168.0.2",
                    }
                ],
            }
        ]
    }
    result = topotest.router_json_cmp(
        tgen.gears["r1"], "show ipv6 route vrf r1-vrf-101 fd00::2/128 json", expected
    )
    assert result is None, "ipv6 route check failed"


def _test_router_check_evpn_next_hop(expected_paths=1):
    dut = get_topogen().gears["r2"]

    # Check IPv4
    expected = {
        "ip": "192.168.0.1",
        "refCount": 1,
        "prefixList": [{"prefix": "192.168.102.21/32", "pathCount": expected_paths}],
    }
    test_func = partial(
        topotest.router_json_cmp,
        dut,
        "show evpn next-hops vni 101 ip 192.168.0.1 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "evpn ipv4 next-hops check failed"

    # Check IPv6
    expected = {
        "ip": "::ffff:192.168.0.1",
        "refCount": 1,
        "prefixList": [{"prefix": "fd00::1/128", "pathCount": expected_paths}],
    }
    test_func = partial(
        topotest.router_json_cmp,
        dut,
        "show evpn next-hops vni 101 ip ::ffff:192.168.0.1 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "evpn ipv6 next-hops check failed"


def _test_router_check_evpn_contexts(router, ipv4_only=False, ipv6_only=False):
    """
    Check EVPN nexthops and RMAC number  are correctly configured
    """
    if ipv4_only:
        expected = {
            "101": {
                "numNextHops": 1,
                "192.168.0.2": {
                    "nexthopIp": "192.168.0.2",
                },
            }
        }
    elif ipv6_only:
        expected = {
            "101": {
                "numNextHops": 1,
                "::ffff:192.168.0.2": {
                    "nexthopIp": "::ffff:192.168.0.2",
                },
            }
        }
    else:
        expected = {
            "101": {
                "numNextHops": 2,
                "192.168.0.2": {
                    "nexthopIp": "192.168.0.2",
                },
                "::ffff:192.168.0.2": {
                    "nexthopIp": "::ffff:192.168.0.2",
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
    _test_router_check_evpn_next_hop()


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
    json_file = "{}/{}/bgp_l2vpn_evpn_routes_all.json".format(CWD, router.name)
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


def _check_evpn_routes(router, family, vrf, routes, expected=True):
    tgen = get_topogen()
    rib_routes = {
        "r1": {
            "static_routes": [
                {
                    "vrf": vrf,
                    "network": routes,
                }
            ]
        }
    }
    result = verify_bgp_rib(tgen, family, router, rib_routes, expected=expected)

    if expected:
        assert result is True, "expect routes {} present".format(routes)
    else:
        assert result is not True, "expect routes {} not present".format(routes)


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
    _check_evpn_routes("r1", "ipv6", "r1-vrf-101", ["fd00::2/128"], expected=False)
    _print_evpn_nexthop_rmac("r1")


def test_router_check_evpn_contexts_again():
    """
    Check EVPN nexthops and RMAC number  are correctly configured
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_router_check_evpn_contexts(tgen.gears["r1"], ipv4_only=True)
    _test_router_check_evpn_next_hop()


def test_evpn_ping_again():
    """
    Check ping between R1 and R2 is ok
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_evpn_ping_router(tgen.gears["r1"], ipv4_only=True)


def test_evpn_other_address_family():
    """
    Check the removal of an EVPN route is correctly handled
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    config_add_ipv6 = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf r2-vrf-101",
                "address-family ipv6 unicast",
                "network fd00::3/128",
                "network fd00::2/128",
            ]
        }
    }

    logger.info("==== Add IPv6 again network on R2")
    result = apply_raw_config(tgen, config_add_ipv6)
    assert result is True, "Failed to add IPv6 network on R2, Error: {} ".format(result)
    _check_evpn_routes("r1", "ipv6", "r1-vrf-101", ["fd00::2/128"], expected=True)

    config_no_ipv4 = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf r2-vrf-101",
                "address-family ipv4 unicast",
                "no network 192.168.101.41/32",
                "no network 192.168.102.41/32",
            ]
        }
    }

    logger.info("==== Remove IPv4 network on R2")
    result = apply_raw_config(tgen, config_no_ipv4)
    assert result is True, "Failed to remove IPv4 network on R2, Error: {} ".format(
        result
    )

    _check_evpn_routes(
        "r1", "ipv4", "r1-vrf-101", ["192.168.101.41/32"], expected=False
    )
    _print_evpn_nexthop_rmac("r1")


def test_router_check_evpn_contexts_again_other_address_family():
    """
    Check EVPN nexthops and RMAC number  are correctly configured
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_router_check_evpn_contexts(tgen.gears["r1"], ipv6_only=True)


def test_evpn_ping_again_other_address_family():
    """
    Check ping between R1 and R2 is ok
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_evpn_ping_router(tgen.gears["r1"], ipv6_only=True)


def _get_established_epoch(router, peer):
    """
    Get the established epoch for a peer
    """
    output = router.vtysh_cmd(f"show bgp neighbor {peer} json", isjson=True)
    assert peer in output, "peer not found"
    peer_info = output[peer]
    assert "bgpState" in peer_info, "peer state not found"
    assert peer_info["bgpState"] == "Established", "peer not in Established state"
    assert "bgpTimerUpEstablishedEpoch" in peer_info, "peer epoch not found"
    return peer_info["bgpTimerUpEstablishedEpoch"]


def _check_established_epoch_differ(router, peer, last_established_epoch):
    """
    Check that the established epoch has changed
    """
    output = router.vtysh_cmd(f"show bgp neighbor {peer} json", isjson=True)
    assert peer in output, "peer not found"
    peer_info = output[peer]
    assert "bgpState" in peer_info, "peer state not found"

    if peer_info["bgpState"] != "Established":
        return "peer not in Established state"

    assert "bgpTimerUpEstablishedEpoch" in peer_info, "peer epoch not found"

    if peer_info["bgpTimerUpEstablishedEpoch"] == last_established_epoch:
        return "peer epoch not changed"
    return None


def _test_epoch_after_clear(router, peer, last_established_epoch):
    """
    Checking that the established epoch has changed and the peer is in Established state again after clear
    Without this, the second session is cleared as well on slower systems (like CI)
    """
    test_func = partial(
        _check_established_epoch_differ,
        router,
        peer,
        last_established_epoch,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert (
        result is None
    ), "Established Epoch still the same after clear bgp for peer {}".format(peer)


def _test_wait_for_multipath_convergence(router, expected_paths=1):
    """
    Wait for multipath convergence on R2
    """
    expected = {
        "192.168.102.21/32": [{"nexthops": [{"ip": "192.168.0.1"}] * expected_paths}]
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
    ), f"R2 does not have {expected_paths} next-hops for 192.168.102.21/32 JSON output mismatches"


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
                "ip address 192.168.99.1/24",
                "router bgp 65000",
                "neighbor 192.168.99.2 remote-as 65000",
                "neighbor 192.168.99.2 capability extended-nexthop",
                "neighbor 192.168.99.2 update-source 192.168.99.1",
                "address-family l2vpn evpn",
                "neighbor 192.168.99.2 activate",
                "neighbor 192.168.99.2 route-map rmap_r1 in",
            ]
        },
        "r2": {
            "raw_config": [
                "interface r2-eth0",
                "ip address 192.168.99.2/24",
                "router bgp 65000",
                "neighbor 192.168.99.1 remote-as 65000",
                "neighbor 192.168.99.1 capability extended-nexthop",
                "neighbor 192.168.99.1 update-source 192.168.99.2",
                "address-family l2vpn evpn",
                "neighbor 192.168.99.1 activate",
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
    _test_wait_for_multipath_convergence(dut, expected_paths=2)
    _test_rmac_present(dut)

    # Enable dataplane logs in FRR
    dut.vtysh_cmd("configure terminal\ndebug zebra dplane detailed\n")

    for i in range(4):
        peer = "192.168.0.2" if i % 2 == 0 else "192.168.99.2"
        local_peer = "192.168.0.1" if i % 2 == 0 else "192.168.99.1"

        # Retrieving the last established epoch from the DUT to check against
        last_established_epoch = _get_established_epoch(dut, local_peer)
        if last_established_epoch is None:
            assert False, "Failed to retrieve established epoch for peer {}".format(
                peer
            )

        dut_peer.vtysh_cmd("clear bgp {0}".format(peer))

        _test_epoch_after_clear(dut, local_peer, last_established_epoch)
        _test_wait_for_multipath_convergence(dut, expected_paths=2)
        _test_rmac_present(dut)
        _test_router_check_evpn_next_hop(expected_paths=2)

    # Check for MAC_DELETE or NEIGH_DELETE in zebra log
    log = dut.net.getLog("log", "zebra")
    if re.search(r"(MAC_DELETE|NEIGH_DELETE)", log):
        assert False, "MAC_DELETE or NEIGH_DELETE found in zebra log"

    dut.vtysh_cmd("configure terminal\nno debug zebra dplane detailed\n")


def test_shutdown_multipath_check_next_hops():
    """
    Deconfigure a second path between R1 and R2, then check that pathCount decreases
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    shutdown_evpn_multipath = {
        "r1": {
            "raw_config": [
                "router bgp 65000",
                "neighbor 192.168.99.2 shutdown",
            ]
        },
        "r2": {
            "raw_config": [
                "router bgp 65000",
                "neighbor 192.168.99.1 shutdown",
            ]
        },
    }
    logger.info("==== Deconfigure second path between R1 and R2")
    result = apply_raw_config(tgen, shutdown_evpn_multipath)
    assert (
        result is True
    ), "Failed to deconfigure second path between R1 and R2, Error: {} ".format(result)
    _test_wait_for_multipath_convergence(tgen.gears["r2"])
    _test_router_check_evpn_next_hop()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
