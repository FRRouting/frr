#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_netns_vrf.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_netns_vrf.py: Test OSPF with Network Namespace VRFs.
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    # Create 3 routers
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # Create a empty network for router 1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    # Create a empty network for router 2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 2 and 3
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # Create empty netowrk for router3
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # check for zebra capability
    for rname, router in router_list.items():
        if router.check_capability(TopoRouter.RD_ZEBRA, "--vrfwnetns") == False:
            return pytest.skip(
                "Skipping OSPF VRF NETNS feature. VRF NETNS backend not available on FRR"
            )

    if os.system("ip netns list") != 0:
        return pytest.skip(
            "Skipping OSPF VRF NETNS Test. NETNS not available on System"
        )

    logger.info("Testing with VRF Namespace support")

    for rname, router in router_list.items():
        # create VRF rx-ospf-cust1 and link rx-eth{0,1} to rx-ospf-cust1
        ns = "{}-ospf-cust1".format(rname)
        router.net.add_netns(ns)
        router.net.set_intf_netns(rname + "-eth0", ns, up=True)
        router.net.set_intf_netns(rname + "-eth1", ns, up=True)

        router.load_config(TopoRouter.RD_MGMTD, None, "--vrfwnetns")
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
            "--vrfwnetns",
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # Move interfaces out of vrf namespace and delete the namespace
    router_list = tgen.routers()
    for rname, _ in router_list.items():
        tgen.net[rname].reset_intf_netns(rname + "-eth0")
        tgen.net[rname].reset_intf_netns(rname + "-eth1")
        tgen.net[rname].delete_netns(rname + "-ospf-cust1")
    tgen.stop_topology()


# Shared test function to validate expected output.
def compare_show_ip_route_vrf(rname, expected):
    """
    Calls 'show ip ospf vrf [rname]-ospf-cust1 route' for router `rname` and compare the obtained
    result with the expected output.
    """
    tgen = get_topogen()
    vrf_name = "{0}-ospf-cust1".format(rname)
    current = topotest.ip4_route_zebra(tgen.gears[rname], vrf_name)
    ret = topotest.difflines(
        current, expected, title1="Current output", title2="Expected output"
    )
    return ret


def test_ospf_convergence():
    "Test OSPF daemon convergence"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for rname, router in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence', rname)

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospfroute.txt".format(rname))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(
            topotest.router_output_cmp,
            router,
            "show ip ospf vrf {0}-ospf-cust1 route".format(rname),
            expected,
        )
        result, diff = topotest.run_and_expect(test_func, "", count=160, wait=0.5)
        assertmsg = "OSPF did not converge on {}:\n{}".format(rname, diff)
        assert result, assertmsg


def test_ospf_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv4 kernel routes in "%s"', router.name)
        reffile = os.path.join(CWD, "{}/zebraroute.txt".format(router.name))
        expected = open(reffile).read()
        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ip_route_vrf, router.name, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=140, wait=0.5)
        assertmsg = 'OSPF IPv4 route mismatch in router "{}": {}'.format(
            router.name, diff
        )
        assert result, assertmsg


def test_ospf_json():
    "Test 'show ip ospf json' output for coherency."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for rname, router in tgen.routers().items():
        logger.info(
            'Comparing router "%s" "show ip ospf vrf %s-ospf-cust1 json" output',
            router.name,
            router.name,
        )
        expected = {
            "{}-ospf-cust1".format(router.name): {
                "vrfName": "{}-ospf-cust1".format(router.name),
                "routerId": "10.0.255.{}".format(rname[1:]),
                "tosRoutesOnly": True,
                "rfc2328Conform": True,
                "spfScheduleDelayMsecs": 0,
                "holdtimeMinMsecs": 50,
                "holdtimeMaxMsecs": 5000,
                "lsaMinIntervalMsecs": 5000,
                "lsaMinArrivalMsecs": 1000,
                "writeMultiplier": 20,
                "refreshTimerMsecs": 10000,
                "asbrRouter": "injectingExternalRoutingInformation",
                "attachedAreaCounter": 1,
                "areas": {},
            }
        }
        # Area specific additional checks
        if router.name == "r1" or router.name == "r2" or router.name == "r3":
            expected["{}-ospf-cust1".format(router.name)]["areas"]["0.0.0.0"] = {
                "areaIfActiveCounter": 2,
                "areaIfTotalCounter": 2,
                "authentication": "authenticationNone",
                "backbone": True,
                "lsaAsbrNumber": 0,
                "lsaNetworkNumber": 1,
                "lsaNssaNumber": 0,
                "lsaNumber": 4,
                "lsaOpaqueAreaNumber": 0,
                "lsaOpaqueLinkNumber": 0,
                "lsaRouterNumber": 3,
                "lsaSummaryNumber": 0,
                "nbrFullAdjacentCounter": 2,
            }

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip ospf vrf {0}-ospf-cust1 json".format(rname),
            expected,
        )
        _, diff = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(rname)
        assert diff is None, assertmsg


def test_ospf_link_down():
    "Test OSPF convergence after a link goes down"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Simulate a network down event on router3 switch3 interface.
    router3 = tgen.gears["r3"]
    topotest.interface_set_status(
        router3, "r3-eth0", ifaceaction=False, vrf_name="r3-ospf-cust1"
    )

    # Expect convergence on all routers
    for rname, router in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence after link failure', rname)
        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospfroute_down.txt".format(rname))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(
            topotest.router_output_cmp,
            router,
            "show ip ospf vrf {0}-ospf-cust1 route".format(rname),
            expected,
        )
        result, diff = topotest.run_and_expect(test_func, "", count=140, wait=0.5)
        assertmsg = "OSPF did not converge on {}:\n{}".format(rname, diff)
        assert result, assertmsg


def test_ospf_link_down_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info(
            'Checking OSPF IPv4 kernel routes in "%s" after link down', router.name
        )

        str = "{0}-ospf-cust1".format(router.name)
        reffile = os.path.join(CWD, "{}/zebraroutedown.txt".format(router.name))
        expected = open(reffile).read()
        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ip_route_vrf, router.name, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=140, wait=0.5)
        assertmsg = (
            'OSPF IPv4 route mismatch in router "{}" after link down: {}'.format(
                router.name, diff
            )
        )
        assert result, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
