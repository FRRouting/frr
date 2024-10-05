#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_redistribute_table.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2023 by 6WIND
#

"""
 test_bgp_redistribute_table.py: Test the FRR BGP daemon with 'redistribute table-direct'
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 2 routers.
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

    for rname, router in router_list.items():
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

    tgen.stop_topology()


def _router_json_cmp_exact_filter(router, cmd, expected):
    output = router.vtysh_cmd(cmd)
    logger.info("{}: {}\n{}".format(router.name, cmd, output))

    json_output = json.loads(output)

    # filter out tableVersion, version, nhVrfId and vrfId
    for _, attrs in json_output.items():
        for attr in attrs:
            if "table" in attr:
                attr.pop("table")
            if "internalStatus" in attr:
                attr.pop("internalStatus")
            if "internalFlags" in attr:
                attr.pop("internalFlags")
            if "internalNextHopNum" in attr:
                attr.pop("internalNextHopNum")
            if "internalNextHopActiveNum" in attr:
                attr.pop("internalNextHopActiveNum")
            if "nexthopGroupId" in attr:
                attr.pop("nexthopGroupId")
            if "installedNexthopGroupId" in attr:
                attr.pop("installedNexthopGroupId")
            if "uptime" in attr:
                attr.pop("uptime")
            if "prefixLen" in attr:
                attr.pop("prefixLen")
            if "asPath" in attr:
                attr.pop("asPath")
            for nexthop in attr.get("nexthops", []):
                if "flags" in nexthop:
                    nexthop.pop("flags")
                if "interfaceIndex" in nexthop:
                    nexthop.pop("interfaceIndex")

    return topotest.json_cmp(json_output, expected, exact=True)


def _check_zebra_rib_r1(with_redistributed_route, with_second_route=False):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    with_str = "" if with_redistributed_route else "out"

    router = tgen.gears["r1"]
    if with_redistributed_route:
        with_str = ""
        if with_second_route:
            json_file = "{}/{}/ipv4_routes_with_all_redistribute.json".format(
                CWD, router.name
            )
        else:
            json_file = "{}/{}/ipv4_routes_with_redistribute.json".format(
                CWD, router.name
            )
    else:
        with_str = "out"
        json_file = "{}/{}/ipv4_routes_without_redistribute.json".format(
            CWD, router.name
        )

    step(f"Checking IPv4 routes for convergence on r1 with{with_str} kernel route")
    expected = json.loads(open(json_file).read())
    test_func = partial(
        _router_json_cmp_exact_filter,
        router,
        "show ip route bgp json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def _test_add_and_check_kernel_route_on_table_2200():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_list = tgen.routers()

    step("r2, adding new kernel route 172.31.0.10/32 on table 2200")
    cmd = "ip route add 172.31.0.10/32 via 172.31.1.10 table 2200"
    tgen.net["r2"].cmd(cmd)

    _check_zebra_rib_r1(True)


def test_step1_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking IPv4 routes for convergence on r1")
    _check_zebra_rib_r1(False)


def test_step2_add_kernel_route_on_table_2200():
    """
    On r2, create a kernel route on table 2200
    * Check that the kernel route is redistributed to r1
    """
    _test_add_and_check_kernel_route_on_table_2200()


def test_step3_remove_kernel_route_on_table_2200():
    """
    On r2, remove a kernel route on table 2200
    * Check that the kernel route is no more redistributed to r1
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_list = tgen.routers()

    step("r2, remove a kernel route on table 2200")
    cmd = "ip route delete 172.31.0.10/32 via 172.31.1.10 table 2200"
    tgen.net["r2"].cmd(cmd)

    _check_zebra_rib_r1(False)


def test_step4_add_kernel_route_on_table_2200():
    """
    On r2, add a kernel route on table 2200
    * Check that the kernel route is redistributed to r1
    """
    _test_add_and_check_kernel_route_on_table_2200()


def test_step5_no_redistribute_table_2200():
    """
    On r2, unconfigure the 'no redistribute' service
    * Check that the 'redistribute' command is not configured
    * Check that the kernel route is not redistributed to r1
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nrouter bgp 65501\naddress-family ipv4 unicast\nno redistribute table-direct\n"
    )

    step("r2, check that the 'redistribute' command is not configured")
    out = tgen.net["r2"].cmd(
        "vtysh -c 'show running-config' | grep 'redistribute table-direct'"
    )

    if "redistribute" in out:
        assert True, "r2, redistribute command still present"

    _check_zebra_rib_r1(False)


def test_step6_redistribute_table_2200():
    """
    On r2, configure the 'redistribute' service
    * Check that the 'redistribute' command is configured
    * Check that the kernel route is redistributed to r1
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nrouter bgp 65501\naddress-family ipv4 unicast\nredistribute table-direct 2200\n"
    )

    step("r2, check that the 'redistribute' command is configured")
    out = tgen.net["r2"].cmd(
        "vtysh -c 'show running-config' | grep 'redistribute table-direct'"
    )
    if "redistribute" not in out:
        assert True, "r2, redistribute command still present"

    _check_zebra_rib_r1(True)


def test_step7_reset_bgp_instance_add_kernel_route_and_add_bgp():
    """
    On r2, remove BGP configuration, create a kernel route on table 2200,
    then restore BGP configuration
    * Check that the kernel route is redistributed to r1
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_list = tgen.routers()

    router = tgen.gears["r2"]
    step("r2, removing r2 BGP configuration")
    router.vtysh_cmd("configure terminal\nno router bgp 65501\n")

    step("r2, adding new kernel route 172.31.0.15/32 on table 2200")
    cmd = "ip route add 172.31.0.15/32 via 172.31.1.100 table 2200"
    tgen.net["r2"].cmd(cmd)

    router = tgen.gears["r2"]
    step("r2, restoring r2 BGP configuration")
    tgen.net["r2"].cmd("vtysh -f {}".format(os.path.join(CWD, "r2/bgpd.conf")))

    _check_zebra_rib_r1(True, with_second_route=True)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
