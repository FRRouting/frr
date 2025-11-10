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


def _test_evpn_ping_router(
    pingrouter, dst_router, source_vrf, dst_vrf, ipv4_only=False, ipv6_only=False
):
    """
    internal function to check ping between r1 and r2
    """
    if pingrouter.name == "r1":
        command = "ip netns exec vrf-{0} ping".format(source_vrf)
    else:
        command = "ping -I vrf-{0}".format(source_vrf)

    dst_router_id = dst_router.name[1:]
    dst_ips = []

    if not ipv6_only:
        dst_ips.append("10.0.{0}.{1}".format(dst_vrf, dst_router_id))
    if not ipv4_only:
        dst_ips.append("fd0{0}::{1}".format(dst_vrf - 100, dst_router_id))

    for ip in dst_ips:
        logger.info(
            "Check Ping from {0}(vrf-{2}) to {1}(vrf-{3}, {4})".format(
                pingrouter.name, dst_router.name, source_vrf, dst_vrf, ip
            )
        )
        output = pingrouter.run("{0} {1} -f -c 1000".format(command, ip))
        logger.info(output)
        if "1000 packets transmitted, 1000 received" not in output:
            assertmsg = "expected ping from {0}(vrf-{2}) to {1}(vrf-{3}, {4}) should be ok".format(
                pingrouter.name, dst_router.name, source_vrf, dst_vrf, ip
            )
            assert 0, assertmsg
        else:
            logger.info(
                "Check Ping from {0}(vrf-{2}) to {1}(vrf-{3}, {4}) OK".format(
                    pingrouter.name, dst_router.name, source_vrf, dst_vrf, ip
                )
            )


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
    output = tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf-101 ipv4", isjson=False)
    logger.info("==== result from show bgp vrf vrf-101 ipv4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf-101 ipv6", isjson=False)
    logger.info("==== result from show bgp vrf vrf-101 ipv6")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf-101", isjson=False)
    logger.info("==== result from show bgp vrf vrf-101")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf vrf-101", isjson=False)
    logger.info("==== result from show ip route vrf vrf-101")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf vrf-101", isjson=False)
    logger.info("==== result from show ipv6 route vrf vrf-101")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show evpn vni detail", isjson=False)
    logger.info("==== result from show evpn vni detail")
    logger.info(output)
    _print_evpn_nexthop_rmac("r1")


def _test_bgp_vrf_routes(router, vrf, suffix=None):
    for af in ("ipv4", "ipv6"):
        logger.info(f"Check {af} routes on {router.name} vrf-{vrf}")

        json_file = "{}/{}/bgp_vrf_{}_{}_routes_detail{}.json".format(
            CWD, router.name, vrf, af, "_" + suffix if suffix else ""
        )
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp vrf vrf-{} {} unicast detail json".format(vrf, af),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" JSON output mismatches VRF: {} Suffix: {}'.format(
            router.name, vrf, suffix
        )
        assert result is None, assertmsg


def test_bgp_vrf_routes():
    """
    Check routes are correctly imported to VRF
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for vrf in (101, 102):
        for rname in ("r1", "r2"):
            router = tgen.gears[rname]
            _test_bgp_vrf_routes(router, vrf)


def test_router_check_ip():
    """
    Check routes are correctly installed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        "fd01::2/128": [
            {
                "prefix": "fd01::2/128",
                "vrfName": "vrf-101",
                "nexthops": [
                    {
                        "ip": "::ffff:192.168.2.2",
                    }
                ],
            }
        ]
    }
    result = topotest.router_json_cmp(
        tgen.gears["r1"], "show ipv6 route vrf vrf-101 fd01::2/128 json", expected
    )
    assert result is None, "ipv6 route check failed"


def _test_router_check_evpn_next_hop(expected_paths=1):
    r2 = get_topogen().gears["r2"]

    # Check IPv4
    expected = {
        "ip": "192.168.1.1",
        "refCount": 1,
        "prefixList": [{"prefix": "10.0.101.1/32", "pathCount": expected_paths}],
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show evpn next-hops vni 101 ip 192.168.1.1 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "evpn ipv4 next-hops check failed"

    # Check IPv6
    expected = {
        "ip": "::ffff:192.168.1.1",
        "refCount": 1,
        "prefixList": [{"prefix": "fd01::1/128", "pathCount": expected_paths}],
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show evpn next-hops vni 101 ip ::ffff:192.168.1.1 json",
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
                "192.168.2.2": {
                    "nexthopIp": "192.168.2.2",
                },
            }
        }
    elif ipv6_only:
        expected = {
            "101": {
                "numNextHops": 1,
                "::ffff:192.168.2.2": {
                    "nexthopIp": "::ffff:192.168.2.2",
                },
            }
        }
    else:
        expected = {
            "101": {
                "numNextHops": 2,
                "192.168.2.2": {
                    "nexthopIp": "192.168.2.2",
                },
                "::ffff:192.168.2.2": {
                    "nexthopIp": "::ffff:192.168.2.2",
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

    _test_evpn_ping_router(tgen.gears["r1"], tgen.gears["r2"], 101, 101)


def test_evpn_disable_routemap():
    """
    Check the removal of a route-map on R2. More EVPN Prefixes are expected
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
 router bgp 65000 vrf vrf-101
  address-family l2vpn evpn
   advertise ipv4 unicast
   advertise ipv6 unicast
        """
    )

    r1 = tgen.gears["r1"]
    json_file = "{}/{}/bgp_l2vpn_evpn_routes_all.json".format(CWD, r1.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
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
        assert result, "expect routes {} present".format(routes)
    else:
        assert result is not True, "expect routes {} not present".format(routes)


def test_evpn_remove_ipv6():
    """
    Check the removal of an EVPN route is correctly handled
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    config_no_ipv6 = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf vrf-101",
                "address-family ipv6 unicast",
                "no network fd01::12/128",
                "no network fd01::2/128",
            ]
        }
    }

    logger.info("==== Remove IPv6 network on R2")
    result = apply_raw_config(tgen, config_no_ipv6)
    assert result, "Failed to remove IPv6 network on R2, Error: {} ".format(result)
    _check_evpn_routes("r1", "ipv6", "vrf-101", ["fd01::2/128"], expected=False)
    _print_evpn_nexthop_rmac("r1")
    _test_router_check_evpn_next_hop()
    _test_evpn_ping_router(tgen.gears["r1"], tgen.gears["r2"], 101, 101, ipv4_only=True)
    _test_router_check_evpn_contexts(tgen.gears["r1"], ipv4_only=True)


def test_evpn_remove_ipv4():
    """
    Check the removal of an EVPN route is correctly handled
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    config_add_ipv6 = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf vrf-101",
                "address-family ipv6 unicast",
                "network fd01::12/128",
                "network fd01::2/128",
            ]
        }
    }

    logger.info("==== Add IPv6 again network on R2")
    result = apply_raw_config(tgen, config_add_ipv6)
    assert result, "Failed to add IPv6 network on R2, Error: {} ".format(result)
    _check_evpn_routes("r1", "ipv6", "vrf-101", ["fd01::2/128"], expected=True)

    config_no_ipv4 = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf vrf-101",
                "address-family ipv4 unicast",
                "no network 10.0.101.2/32",
                "no network 10.0.101.12/32",
            ]
        }
    }

    logger.info("==== Remove IPv4 network on R2")
    result = apply_raw_config(tgen, config_no_ipv4)
    assert result, "Failed to remove IPv4 network on R2, Error: {} ".format(result)

    _check_evpn_routes("r1", "ipv4", "vrf-101", ["10.0.101.2/32"], expected=False)
    _print_evpn_nexthop_rmac("r1")
    _test_router_check_evpn_next_hop()
    _test_evpn_ping_router(tgen.gears["r1"], tgen.gears["r2"], 101, 101, ipv6_only=True)
    _test_router_check_evpn_contexts(tgen.gears["r1"], ipv6_only=True)


def test_evpn_restore_ipv4():
    """
    Restore IPv4 network on R2
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    config_add_ipv4 = {
        "r2": {
            "raw_config": [
                "router bgp 65000 vrf vrf-101",
                "address-family ipv4 unicast",
                "network 10.0.101.2/32",
                "network 10.0.101.12/32",
            ]
        }
    }

    logger.info("==== Add IPv4 network again on R2")
    result = apply_raw_config(tgen, config_add_ipv4)
    assert result, "Failed to add IPv4 network again on R2, Error: {} ".format(result)

    _check_evpn_routes("r1", "ipv4", "vrf-101", ["10.0.101.2/32"], expected=True)
    _test_router_check_evpn_next_hop()
    _test_evpn_ping_router(tgen.gears["r1"], tgen.gears["r2"], 101, 101)
    _test_router_check_evpn_contexts(tgen.gears["r1"])


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
        "10.0.101.1/32": [{"nexthops": [{"ip": "192.168.1.1"}] * expected_paths}]
    }
    # Using router_json_cmp instead of verify_fib_routes, because we need to check for
    # two next-hops with the same IP address.
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip route vrf vrf-101 10.0.101.1/32 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert (
        result is None
    ), f"R2 does not have {expected_paths} next-hops for 10.0.101.1/32 JSON output mismatches"


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
                "interface eth-rr",
                "ip address 192.168.101.1/24",
                "router bgp 65000",
                "neighbor 192.168.101.101 remote-as 65000",
                "neighbor 192.168.101.101 capability extended-nexthop",
                "neighbor 192.168.101.101 update-source 192.168.101.1",
                "address-family l2vpn evpn",
                "neighbor 192.168.101.101 activate",
                "neighbor 192.168.101.101 route-map rmap_r1 in",
            ]
        },
        "r2": {
            "raw_config": [
                "interface eth-rr",
                "ip address 192.168.102.2/24",
                "router bgp 65000",
                "neighbor 192.168.102.101 remote-as 65000",
                "neighbor 192.168.102.101 capability extended-nexthop",
                "neighbor 192.168.102.101 update-source 192.168.102.2",
                "address-family l2vpn evpn",
                "neighbor 192.168.102.101 activate",
            ]
        },
        "rr": {
            "raw_config": [
                "interface eth-r1",
                " ip address 192.168.101.101/24",
                "interface eth-r2",
                " ip address 192.168.102.101/24",
                "router bgp 65000",
                " neighbor 192.168.101.1 remote-as 65000",
                " neighbor 192.168.101.1 capability extended-nexthop",
                " neighbor 192.168.101.1 update-source 192.168.102.101",
                " neighbor 192.168.102.2 remote-as 65000",
                " neighbor 192.168.102.2 capability extended-nexthop",
                " neighbor 192.168.102.2 update-source 192.168.102.101",
                " address-family l2vpn evpn",
                "  neighbor 192.168.101.1 activate",
                "  neighbor 192.168.101.1 route-reflector-client",
                "  neighbor 192.168.102.2 activate",
                "  neighbor 192.168.102.2 route-reflector-client",
            ]
        },
    }

    logger.info("==== Configure second path between R1 and R2")
    result = apply_raw_config(tgen, evpn_multipath)
    assert (
        result
    ), "Failed to configure second path between R1 and R2, Error: {} ".format(result)

    rr = tgen.gears["rr"]
    r2 = tgen.gears["r2"]
    _test_wait_for_multipath_convergence(r2, expected_paths=2)
    _test_rmac_present(r2)

    # Enable dataplane logs in FRR
    r2.vtysh_cmd(
        """
configure terminal
 debug zebra dplane detailed
"""
    )

    for i in range(4):
        rr_addr = "192.168.2.101" if i % 2 == 0 else "192.168.102.101"
        r2_addr = "192.168.2.2" if i % 2 == 0 else "192.168.102.2"

        # Retrieving the last established epoch from the r2 to check against
        last_established_epoch = _get_established_epoch(r2, rr_addr)
        if last_established_epoch is None:
            assert False, "Failed to retrieve established epoch for peer {}".format(
                rr_addr
            )

        rr.vtysh_cmd("clear bgp {0}".format(r2_addr))

        _test_epoch_after_clear(r2, rr_addr, last_established_epoch)
        _test_wait_for_multipath_convergence(r2, expected_paths=2)
        _test_rmac_present(r2)
        _test_router_check_evpn_next_hop(expected_paths=2)

    # Check for MAC_DELETE or NEIGH_DELETE in zebra log
    log = r2.net.getLog("log", "zebra")
    if re.search(r"(MAC_DELETE|NEIGH_DELETE)", log):
        assert False, "MAC_DELETE or NEIGH_DELETE found in zebra log"

    r2.vtysh_cmd(
        """
configure terminal
 no debug zebra dplane detailed
"""
    )
    _test_singleton_equivalent_nhg_optimization(r2, "vrf-101", "10.0.101.1/32")


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
                "neighbor 192.168.101.101 shutdown",
            ]
        },
        "r2": {
            "raw_config": [
                "router bgp 65000",
                "neighbor 192.168.102.101 shutdown",
            ]
        },
        "rr": {
            "raw_config": [
                "router bgp 65000",
                " neighbor 192.168.101.1 shutdown",
                " neighbor 192.168.102.2 shutdown",
            ]
        },
    }
    logger.info("==== Deconfigure second path between R1 and R2")
    result = apply_raw_config(tgen, shutdown_evpn_multipath)
    assert (
        result
    ), "Failed to deconfigure second path between R1 and R2, Error: {} ".format(result)
    _test_wait_for_multipath_convergence(tgen.gears["r2"])
    _test_router_check_evpn_next_hop()


def test_rmap_match_evpn_vni_105():
    """
    change input route-map from r2.
    match evpn vni value from 101 to 105
    expecting all prefixes are denied
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    nb_prefix = 4
    expected = {"numPrefix": nb_prefix, "totalPrefix": nb_prefix}
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn rd 65000:2 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, f"r1 was expecting {nb_prefix} from r2"

    # change route-map and test
    cfg = {
        "r1": {
            "raw_config": [
                "route-map rmap_r1 permit 1",
                "match evpn vni 105",
            ]
        },
    }
    assert apply_raw_config(tgen, cfg), "Configuration failed"

    nb_prefix = 0
    expected = {"numPrefix": nb_prefix, "totalPrefix": nb_prefix}
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn rd 65000:2 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, f"r1 was expecting {nb_prefix} from r2"


def test_rmap_match_evpn_vni_101():
    """
    change input route-map from r2.
    re-apply match evpn vni value 101
    expecting all prefixes are received
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # change route-map and test
    cfg = {
        "r1": {
            "raw_config": [
                "route-map rmap_r1 permit 1",
                "match evpn vni 101",
            ]
        },
    }
    assert apply_raw_config(tgen, cfg), "Configuration failed"

    r1 = tgen.gears["r1"]
    nb_prefix = 4
    expected = {"numPrefix": nb_prefix, "totalPrefix": nb_prefix}
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn rd 65000:2 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, f"r1 was expecting {nb_prefix} from r2"


def test_rmap_match_evpn_vni_101_deny():
    """
    change input route-map from r2.
    set deny action to vni 101
    expecting all prefixes are denied
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # change route-map and test
    cfg = {
        "r1": {
            "raw_config": [
                "route-map rmap_r1 deny 1",
            ]
        },
    }
    assert apply_raw_config(tgen, cfg), "Configuration failed"

    r1 = tgen.gears["r1"]
    nb_prefix = 0
    expected = {"numPrefix": nb_prefix, "totalPrefix": nb_prefix}
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn rd 65000:2 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, f"r1 was expecting {nb_prefix} from r2"


def test_no_rmap_match_evpn_vni():
    """
    un-apply input route-map from r2
    expecting all prefixes are received
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # change route-map and test
    cfg = {
        "r1": {
            "raw_config": [
                "router bgp 65000",
                " address-family l2vpn evpn",
                "  no neighbor 192.168.1.101 route-map rmap_r1 in",
                "  no neighbor 192.168.101.101 route-map rmap_r1 in",
            ]
        },
    }
    assert apply_raw_config(tgen, cfg), "Configuration failed"

    r1 = tgen.gears["r1"]
    nb_prefix = 4
    expected = {"numPrefix": nb_prefix, "totalPrefix": nb_prefix}
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn rd 65000:2 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"r1 was expecting {nb_prefix} from r2"


def _validate_evpn_rmacs(router, expected):
    """
    Internal function to check RMACs are matching the expected values
    and that VTEP IPs are unique for each VRF/VNI
    """
    data = router.vtysh_cmd("show evpn rmac vni all json", isjson=True)

    # Each object (vni) in expected should be in the output
    for vni in expected.keys():
        if vni not in data:
            return "Failed to find expected VNI {}".format(vni)

    # Each rmac in expected should be in output
    # the VTEP in each expected rmac object should be in output - in v4 or v6 form
    # Each VTEP should be in vni only once...

    for vni, details in data.items():
        vtep_ips = []
        jvni = None

        if vni in expected:
            jvni = expected[vni]

        for key, detail in details.items():
            if key == "numRmacs":
                continue

            vtep_ip = detail["vtepIp"]
            rmac = detail["routerMac"]
            if jvni != None:
                if rmac in jvni:
                    # Compare VTEP IPs - a forgiving comparison
                    if detail["vtepIp"].find(jvni[rmac]["vtepIp"]) < 0:
                        return "VTEP {} failed, not found in VNI {}".format(
                            detail["vtepIp"], vni)
            if vtep_ip in vtep_ips:
                # VTEP IP is occuring for more than one RMAC in the same VNI
                return "Duplicate VTEP IP {} found in VNI {}".format(vtep_ip, vni)
            vtep_ips.append(vtep_ip)

    return None


def _test_evpn_rmac(tgen):
    """
    Internal function to check RMACs for both VRFs from peers
    """
    for router, peer in {1: 2, 2: 1}.items():
        r = tgen.gears["r{}".format(router)]
        # Expecting the RMACs of the peer
        expected = {
            str(vrf): {
                _create_rmac(peer, vrf): {
                    "routerMac": _create_rmac(peer, vrf),
                    "vtepIp": "192.168.{}.{}".format(peer, peer),
                }
            }
            for vrf in (101, 102)
        }
        test_func = partial(
            _validate_evpn_rmacs,
            r,
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "r{}".format(router) + " missing rmacs for vni"


def test_evpn_l3vpn_import():
    """
    Import vrf-102 to vrf-101 on r2 and vice versa on r3
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _test_evpn_rmac(tgen)

    # import r1 vrf 101 routes into vrf 102 and vice versa on r2
    # establishing connectivity for r1 between vrf 101 and vrf 102
    # over r2. Overwriting origin to allow re-export to iBGP peer.
    cfg = {
        "r2": {
            "raw_config": [
                "ip prefix-list vrf-101 seq 5 permit 10.0.102.1/32",
                "ipv6 prefix-list vrf-101 seq 5 permit fd02::1/128",
                "route-map vrf-import-to-101 permit 1",
                " match ip address prefix-list vrf-101",
                " set origin incomplete",
                " route-map vrf-import-to-101 permit 2",
                " match ipv6 address prefix-list vrf-101",
                " set origin incomplete",
                "ip prefix-list vrf-102 seq 5 permit 10.0.101.1/32",
                "ipv6 prefix-list vrf-102 seq 5 permit fd01::1/128",
                "route-map vrf-import-to-102 permit 1",
                " match ip address prefix-list vrf-102",
                " set origin incomplete",
                " route-map vrf-import-to-102 permit 2",
                " match ipv6 address prefix-list vrf-102",
                " set origin incomplete",
                "router bgp 65000 vrf vrf-101",
                " address-family ipv4 unicast",
                "  import vrf route-map vrf-import-to-101",
                "  import vrf vrf-102",
                " address-family ipv6 unicast",
                "  import vrf route-map vrf-import-to-101",
                "  import vrf vrf-102",
                "router bgp 65000 vrf vrf-102",
                " address-family ipv4 unicast",
                "  import vrf route-map vrf-import-to-102",
                "  import vrf vrf-101",
                " address-family ipv6 unicast",
                "  import vrf route-map vrf-import-to-102",
                "  import vrf vrf-101",
            ]
        },
    }
    assert apply_raw_config(tgen, cfg), "Configuration failed"

    for vrf in (101, 102):
        _test_bgp_vrf_routes(tgen.gears["r1"], vrf, suffix="import")

    _test_evpn_rmac(tgen)
    _test_evpn_ping_router(tgen.gears["r1"], tgen.gears["r1"], 101, 102)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
