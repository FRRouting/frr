#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_vpnv4_noretain.py
# Part of NetDEF Topology Tests
#
# Copyright 2022 6WIND S.A.
#

"""
 test_bgp_vpnv4_noretain.py: Do not keep the VPNvx entries when no
 VRF matches incoming VPNVx entries
"""

import os
import sys
import json
from functools import partial
from copy import deepcopy
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

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["r2"])


def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "modprobe mpls_router",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
        "ip link add vrf1 type vrf table 10",
        "ip link set dev vrf1 up",
        "ip link set dev {0}-eth1 master vrf1",
        "echo 1 > /proc/sys/net/mpls/conf/vrf1/input",
        "ip link add vrf2 type vrf table 20",
        "ip link set dev vrf2 up",
        "ip link set dev {0}-eth2 master vrf2",
        "echo 1 > /proc/sys/net/mpls/conf/vrf2/input",
        "ip link add vrf3 type vrf table 30",
        "ip link set dev vrf3 up",
        "ip link set dev {0}-eth3 master vrf3",
        "echo 1 > /proc/sys/net/mpls/conf/vrf3/input",
        "ip link add vrf4 type vrf table 40",
        "ip link set dev vrf4 up",
        "ip link set dev {0}-eth4 master vrf4",
        "echo 1 > /proc/sys/net/mpls/conf/vrf4/input",
    ]

    for cmd in cmds_list:
        input = cmd.format("r1", "1", "2")
        logger.info("input: " + cmd)
        output = tgen.net["r1"].cmd(cmd.format("r1", "1", "2"))
        logger.info("output: " + output)

    for cmd in cmds_list:
        input = cmd.format("r2", "2", "1")
        logger.info("input: " + cmd)
        output = tgen.net["r2"].cmd(cmd.format("r2", "2", "1"))
        logger.info("output: " + output)


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface()

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


def router_json_cmp_exact_filter(router, cmd, expected):
    output = router.vtysh_cmd(cmd)
    logger.info("{}: {}\n{}".format(router.name, cmd, output))

    json_output = json.loads(output)

    # filter out tableVersion, version and nhVrfID
    json_output.pop("tableVersion")
    for rd, data in json_output["routes"]["routeDistinguishers"].items():
        for _, attrs in data.items():
            for attr in attrs:
                if "nhVrfId" in attr:
                    attr.pop("nhVrfId")
                if "version" in attr:
                    attr.pop("version")

    # filter out RD with no data (e.g. "444:3": {})
    json_tmp = deepcopy(json_output)
    for rd, data in json_tmp["routes"]["routeDistinguishers"].items():
        if len(data.keys()) == 0:
            json_output["routes"]["routeDistinguishers"].pop(rd)

    return topotest.json_cmp(json_output, expected, exact=True)


def router_vrf_json_cmp_exact_filter(router, cmd, expected):
    output = router.vtysh_cmd(cmd)
    logger.info("{}: {}\n{}".format(router.name, cmd, output))

    json_output = json.loads(output)

    # filter out tableVersion, version, nhVrfId and vrfId
    for vrf, data in json_output.items():
        if "vrfId" in data:
            data.pop("vrfId")
        if "tableVersion" in data:
            data.pop("tableVersion")
        if "routes" not in data:
            continue
        for _, attrs in data["routes"].items():
            for attr in attrs:
                if "nhVrfId" in attr:
                    attr.pop("nhVrfId")
                if "version" in attr:
                    attr.pop("version")

    # filter out VRF with no routes
    json_tmp = deepcopy(json_output)
    for vrf, data in json_tmp.items():
        if "routes" not in data or len(data["routes"].keys()) == 0:
            json_output.pop(vrf)

    return topotest.json_cmp(json_output, expected, exact=True)


def check_show_bgp_ipv4_vpn(rname, json_file):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears[rname]

    logger.info("Checking VPNv4 routes for convergence on {}".format(rname))

    json_file = "{}/{}/{}".format(CWD, router.name, json_file)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        router_json_cmp_exact_filter,
        router,
        "show bgp ipv4 vpn json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def check_show_bgp_vrf_ipv4(rname, json_file):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears[rname]

    logger.info("Checking VRF IPv4 routes for convergence on {}".format(rname))

    json_file = "{}/{}/{}".format(CWD, router.name, json_file)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        router_vrf_json_cmp_exact_filter,
        router,
        "show bgp vrf all ipv4 unicast json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def test_protocols_convergence_step0():
    """
    Assert that all protocols have converged
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # check that r2 peerings are ok
    logger.info("Checking BGP ipv4 vpn summary for r2")
    router = tgen.gears["r2"]
    json_file = "{}/{}/ipv4_vpn_summary.json".format(CWD, router.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp ipv4 vpn summary json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def test_bgp_no_retain_step1():
    """
    Check bgp no retain route-target all on r1
    """

    rname = "r1"
    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_init.json")


def test_bgp_retain_step2():
    """
    Apply and check bgp retain route-target all on r1
    """
    rname = "r1"
    cfg = """
configure
router bgp 65500
 address-family ipv4 vpn
  bgp retain route-target all
"""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_all.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_init.json")


def test_bgp_no_retain_step3():
    """
    Apply and check no bgp retain route-target all on r1
    """
    rname = "r1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.vtysh_cmd(
        "configure\nrouter bgp 65500\naddress-family ipv4 vpn\nno bgp retain route-target all\n"
    )

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_init.json")


def test_bgp_no_retain_add_vrf2_step4():
    """
    Add vrf2 on r1 and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
router bgp 65500 vrf vrf2
 bgp router-id 192.0.2.1
 address-family ipv4 unicast
  redistribute connected
  label vpn export 102
  rd vpn export 192.0.2.1:200
  rt vpn import 192.0.2.2:200
  import vpn
 exit-address-family
!
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init_plus_r2_vrf2.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_plus_r2_vrf2.json")


def test_bgp_no_retain_unimport_vrf2_step5():
    """
    Unimport to vrf2 on r1 and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
router bgp 65500 vrf vrf2
 address-family ipv4 unicast
  no import vpn
 exit-address-family
!
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_init.json")


def test_bgp_no_retain_import_vrf2_step6():
    """
    Re-import to vrf2 on r1 and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
router bgp 65500 vrf vrf2
 address-family ipv4 unicast
  import vpn
 exit-address-family
!
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init_plus_r2_vrf2.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_plus_r2_vrf2.json")


def test_bgp_no_retain_import_vrf1_step7():
    """
    Import r1 vrf1 into r1 vrf2 and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
router bgp 65500 vrf vrf2
 address-family ipv4 unicast
  rt vpn import 192.0.2.1:100
 exit-address-family
!
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_plus_r1_vrf1.json")


def test_bgp_no_retain_import_vrf3_step8():
    """
    Import r2 vrf3 into r1 vrf2 and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
router bgp 65500 vrf vrf2
 address-family ipv4 unicast
  rt vpn import 192.0.2.2:300
 exit-address-family
!
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init_plus_r2_vrf3.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_plus_r2_vrf3.json")


def test_bgp_no_retain_unimport_vrf3_step9():
    """
    Un-import r2 vrf3 into r1 vrf2 and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
router bgp 65500 vrf vrf2
 address-family ipv4 unicast
  no rt vpn import 192.0.2.2:300
 exit-address-family
!
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_init.json")


def test_bgp_no_retain_import_vrf3_step10():
    """
    Import r2 vrf3 into r1 vrf2 and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
router bgp 65500 vrf vrf2
 address-family ipv4 unicast
  rt vpn import 192.0.2.2:300
 exit-address-family
!
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init_plus_r2_vrf3.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_plus_r2_vrf3.json")


def test_bgp_no_retain_remove_vrf2_step11():
    """
    Remove BGP vrf2 on r1 and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
no router bgp 65500 vrf vrf2
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_no_retain_init.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_init.json")


def test_bgp_retain_step12():
    """
    Configure retain and check bgp tables
    """

    rname = "r1"
    cfg = """
configure
router bgp 65500
 address-family ipv4 vpn
  bgp retain route-target all
"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)

    check_show_bgp_ipv4_vpn(rname, "ipv4_vpn_routes_all.json")
    check_show_bgp_ipv4_vpn("r2", "ipv4_vpn_routes_all.json")

    check_show_bgp_vrf_ipv4(rname, "ipv4_vrf_all_routes_init.json")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
