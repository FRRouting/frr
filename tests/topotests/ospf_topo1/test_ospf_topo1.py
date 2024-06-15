#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_topo1.py: Test the FRR OSPF routing daemon.
"""

import os
import re
import sys
from functools import partial
from time import sleep
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

    # Create 4 routers
    for routern in range(1, 5):
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

    # Interconect router 3 and 4
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    # Create a empty network for router 4
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    ospf6_config = "ospf6d.conf"

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/{}".format(rname, ospf6_config))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_wait_protocol_convergence():
    "Wait for OSPFv2/OSPFv3 to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_ospfv2_neighbor_full(router, neighbor):
        "Wait until OSPFv2 convergence."
        logger.info("waiting OSPFv2 router '{}'".format(router))

        def run_command_and_expect():
            """
            Function that runs command and expect the following outcomes:
             * Full/DR
             * Full/DROther
             * Full/Backup
            """
            result = tgen.gears[router].vtysh_cmd(
                "show ip ospf neighbor json", isjson=True
            )
            if (
                topotest.json_cmp(
                    result, {"neighbors": {neighbor: [{"converged": "Full"}]}}
                )
                is None
            ):
                return None

            if (
                topotest.json_cmp(
                    result, {"neighbors": {neighbor: [{"converged": "Full"}]}}
                )
                is None
            ):
                return None

            return topotest.json_cmp(
                result, {"neighbors": {neighbor: [{"converged": "Full"}]}}
            )

        _, result = topotest.run_and_expect(
            run_command_and_expect, None, count=130, wait=1
        )
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    def expect_ospfv3_neighbor_full(router, neighbor):
        "Wait until OSPFv3 convergence."
        logger.info("waiting OSPFv3 router '{}'".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 neighbor json",
            {"neighbors": [{"neighborId": neighbor, "state": "Full"}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for OSPFv2 convergence
    expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    expect_ospfv2_neighbor_full("r1", "10.0.255.3")
    expect_ospfv2_neighbor_full("r2", "10.0.255.1")
    expect_ospfv2_neighbor_full("r2", "10.0.255.3")
    expect_ospfv2_neighbor_full("r3", "10.0.255.1")
    expect_ospfv2_neighbor_full("r3", "10.0.255.2")
    expect_ospfv2_neighbor_full("r3", "10.0.255.4")
    expect_ospfv2_neighbor_full("r4", "10.0.255.3")

    # Wait for OSPFv3 convergence
    expect_ospfv3_neighbor_full("r1", "10.0.255.2")
    expect_ospfv3_neighbor_full("r1", "10.0.255.3")
    expect_ospfv3_neighbor_full("r2", "10.0.255.1")
    expect_ospfv3_neighbor_full("r2", "10.0.255.3")
    expect_ospfv3_neighbor_full("r3", "10.0.255.1")
    expect_ospfv3_neighbor_full("r3", "10.0.255.2")
    expect_ospfv3_neighbor_full("r3", "10.0.255.4")
    expect_ospfv3_neighbor_full("r4", "10.0.255.3")


def compare_show_ipv6_ospf6(rname, expected):
    """
    Calls 'show ipv6 ospf6 route' for router `rname` and compare the obtained
    result with the expected output.
    """
    tgen = get_topogen()
    current = tgen.gears[rname].vtysh_cmd("show ipv6 ospf6 route")

    # Remove the link addresses
    current = re.sub(r"fe80::[^ ]+", "fe80::xxxx:xxxx:xxxx:xxxx", current)
    expected = re.sub(r"fe80::[^ ]+", "fe80::xxxx:xxxx:xxxx:xxxx", expected)

    # Remove the time
    current = re.sub(r"\d+:\d{2}:\d{2}", "", current)
    expected = re.sub(r"\d+:\d{2}:\d{2}", "", expected)

    return topotest.difflines(
        topotest.normalize_text(current),
        topotest.normalize_text(expected),
        title1="Current output",
        title2="Expected output",
    )


def test_ospf_convergence():
    "Test OSPF daemon convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for router, rnode in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospfroute.txt".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 80 seconds.
        test_func = partial(
            topotest.router_output_cmp, rnode, "show ip ospf route", expected
        )
        result, diff = topotest.run_and_expect(test_func, "", count=160, wait=0.5)
        assert result, "OSPF did not converge on {}:\n{}".format(router, diff)


def test_ospf_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv4 kernel routes in "%s"', router.name)

        routes = topotest.ip4_route(router)
        expected = {
            "10.0.1.0/24": {},
            "10.0.2.0/24": {},
            "10.0.3.0/24": {},
            "10.0.10.0/24": {},
            "172.16.0.0/24": {},
            "172.16.1.0/24": {},
        }
        assertmsg = 'OSPF IPv4 route mismatch in router "{}"'.format(router.name)
        assert topotest.json_cmp(routes, expected) is None, assertmsg


def test_ospf6_convergence():
    "Test OSPF6 daemon convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    ospf6route_file = "{}/ospf6route_ecmp.txt"
    for rnum in range(1, 5):
        router = "r{}".format(rnum)

        logger.info('Waiting for router "%s" IPv6 OSPF convergence', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, ospf6route_file.format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_ospf6, router, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=25, wait=3)
        if (not result) and (rnum == 1):
            # Didn't match the new ECMP version - try the old pre-ECMP format
            ospf6route_file = "{}/ospf6route.txt"

            # Load expected results from the command
            reffile = os.path.join(CWD, ospf6route_file.format(router))
            expected = open(reffile).read()

            test_func = partial(compare_show_ipv6_ospf6, router, expected)
            result, diff = topotest.run_and_expect(test_func, "", count=1, wait=3)
            if not result:
                # Didn't match the old version - switch back to new ECMP version
                # and fail
                ospf6route_file = "{}/ospf6route_ecmp.txt"

                # Load expected results from the command
                reffile = os.path.join(CWD, ospf6route_file.format(router))
                expected = open(reffile).read()

                test_func = partial(compare_show_ipv6_ospf6, router, expected)
                result, diff = topotest.run_and_expect(test_func, "", count=1, wait=3)

        assert result, "OSPF6 did not converge on {}:\n{}".format(router, diff)


def test_ospf6_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv6 kernel routes in "%s"', router.name)

        def _routes_in_fib6():
            routes = topotest.ip6_route(router)
            expected = {
                "2001:db8:1::/64": {},
                "2001:db8:2::/64": {},
                "2001:db8:3::/64": {},
                "2001:db8:100::/64": {},
                "2001:db8:200::/64": {},
                "2001:db8:300::/64": {},
            }
            logger.info("Routes:")
            logger.info(routes)
            logger.info(topotest.json_cmp(routes, expected))
            logger.info("ENd:")
            return topotest.json_cmp(routes, expected)

        _, result = topotest.run_and_expect(_routes_in_fib6, None, count=20, wait=1)

        assertmsg = 'OSPF IPv6 route mismatch in router "{}"'.format(router.name)
        assert result is None, assertmsg


def test_ospf_json():
    "Test 'show ip ospf json' output for coherency."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for rnum in range(1, 5):
        router = tgen.gears["r{}".format(rnum)]
        logger.info(router.vtysh_cmd("show ip ospf database"))
        logger.info('Comparing router "%s" "show ip ospf json" output', router.name)
        expected = {
            "routerId": "10.0.255.{}".format(rnum),
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
        # Area specific additional checks
        if router.name == "r1" or router.name == "r2" or router.name == "r3":
            expected["areas"]["0.0.0.0"] = {
                "areaIfActiveCounter": 2,
                "areaIfTotalCounter": 2,
                "authentication": "authenticationNone",
                "backbone": True,
                "lsaAsbrNumber": 1,
                "lsaNetworkNumber": 1,
                "lsaNssaNumber": 0,
                "lsaNumber": 7,
                "lsaOpaqueAreaNumber": 0,
                "lsaOpaqueLinkNumber": 0,
                "lsaRouterNumber": 3,
                "lsaSummaryNumber": 2,
                "nbrFullAdjacentCounter": 2,
            }
        if router.name == "r3" or router.name == "r4":
            expected["areas"]["0.0.0.1"] = {
                "areaIfActiveCounter": 1,
                "areaIfTotalCounter": 1,
                "authentication": "authenticationNone",
                "lsaAsbrNumber": 2,
                "lsaNetworkNumber": 1,
                "lsaNssaNumber": 0,
                "lsaNumber": 9,
                "lsaOpaqueAreaNumber": 0,
                "lsaOpaqueLinkNumber": 0,
                "lsaRouterNumber": 2,
                "lsaSummaryNumber": 4,
                "nbrFullAdjacentCounter": 1,
            }
            # r4 has more interfaces for area 0.0.0.1
            if router.name == "r4":
                expected["areas"]["0.0.0.1"].update(
                    {
                        "areaIfActiveCounter": 2,
                        "areaIfTotalCounter": 2,
                    }
                )

        # router 3 has an additional area
        if router.name == "r3":
            expected["attachedAreaCounter"] = 2

        output = router.vtysh_cmd("show ip ospf json", isjson=True)
        result = topotest.json_cmp(output, expected)
        assert result is None, '"{}" JSON output mismatches the expected result'.format(
            router.name
        )


def test_ospf_link_down():
    "Test OSPF convergence after a link goes down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Simulate a network down event on router3 switch3 interface.
    router3 = tgen.gears["r3"]
    router3.peer_link_enable("r3-eth0", False)

    # Expect convergence on all routers
    for router, rnode in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence after link failure', router)
        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospfroute_down.txt".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 80 seconds.
        test_func = partial(
            topotest.router_output_cmp, rnode, "show ip ospf route", expected
        )
        result, diff = topotest.run_and_expect(test_func, "", count=140, wait=0.5)
        assert result, "OSPF did not converge on {}:\n{}".format(router, diff)


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

        routes = topotest.ip4_route(router)
        expected = {
            "10.0.1.0/24": {},
            "10.0.2.0/24": {},
            "10.0.3.0/24": {},
            "10.0.10.0/24": {},
            "172.16.0.0/24": {},
            "172.16.1.0/24": {},
        }
        if router.name == "r1" or router.name == "r2":
            expected.update(
                {
                    "10.0.10.0/24": None,
                    "172.16.0.0/24": None,
                    "172.16.1.0/24": None,
                }
            )
        elif router.name == "r3" or router.name == "r4":
            expected.update(
                {
                    "10.0.1.0/24": None,
                    "10.0.2.0/24": None,
                }
            )
        # Route '10.0.3.0' is no longer available for r4 since it is down.
        if router.name == "r4":
            expected.update(
                {
                    "10.0.3.0/24": None,
                }
            )
        assertmsg = 'OSPF IPv4 route mismatch in router "{}" after link down'.format(
            router.name
        )
        count = 0
        not_found = True
        while not_found and count < 10:
            not_found = topotest.json_cmp(routes, expected)
            if not_found:
                sleep(1)
                routes = topotest.ip4_route(router)
                count += 1
            else:
                not_found = False
                break
        assert not_found is False, assertmsg


def test_ospf6_link_down():
    "Test OSPF6 daemon convergence after link goes down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for rnum in range(1, 5):
        router = "r{}".format(rnum)

        logger.info(
            'Waiting for router "%s" IPv6 OSPF convergence after link down', router
        )

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospf6route_down.txt".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_ospf6, router, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=25, wait=3)
        assert result, "OSPF6 did not converge on {}:\n{}".format(router, diff)


def test_ospf6_link_down_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info(
            'Checking OSPF IPv6 kernel routes in "%s" after link down', router.name
        )

        routes = topotest.ip6_route(router)
        expected = {
            "2001:db8:1::/64": {},
            "2001:db8:2::/64": {},
            "2001:db8:3::/64": {},
            "2001:db8:100::/64": {},
            "2001:db8:200::/64": {},
            "2001:db8:300::/64": {},
        }
        if router.name == "r1" or router.name == "r2":
            expected.update(
                {
                    "2001:db8:100::/64": None,
                    "2001:db8:200::/64": None,
                    "2001:db8:300::/64": None,
                }
            )
        elif router.name == "r3" or router.name == "r4":
            expected.update(
                {
                    "2001:db8:1::/64": None,
                    "2001:db8:2::/64": None,
                }
            )
        # Route '2001:db8:3::/64' is no longer available for r4 since it is down.
        if router.name == "r4":
            expected.update(
                {
                    "2001:db8:3::/64": None,
                }
            )
        assertmsg = 'OSPF IPv6 route mismatch in router "{}" after link down'.format(
            router.name
        )
        count = 0
        not_found = True
        while not_found and count < 10:
            not_found = topotest.json_cmp(routes, expected)
            if not_found:
                sleep(1)
                routes = topotest.ip6_route(router)
                count += 1
            else:
                not_found = False
                break

        assert not_found is False, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
