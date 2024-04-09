#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_vpnv4_asbr.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2023 by 6WIND
#

"""
 test_bgp_vpnv4_asbr.py: Test the FRR BGP daemon with rfc4364 option 10b
 r1, r2, and r100 are in an iBGP AS, while r2, r3 do an eBGP peering
 h1 is a host behind r1 VRF1, and {h2,h3} are hosts behind r3 VRF1
 The test demonstrates the connectivity across the network between h1 and h3.


 +----------+          +----+--------+              +--------+              +--------+-----+
 |          |172.31.0.0|vrf | r1     |192.168.0.0/24| r2     |192.168.1.0/24|r3      | vrf |
 |   h1     +----------+    |       1+------+-------+        +------+-------+3       |     +--- 172.31.3.0/24
 |   10     |          |VRF1|AS65500 |      |       | AS65500|      |       |AS65501 |VRF1 |
 +----------+          +-------------+      |       +--------+      |       +--------+--+-++
                           192.0.2.1        |       192.0.2.2       |                172| |
                                       +----------+            +----+--------+        31| |
                                       |rr100     |            |rs200/AS65502|         1| |
                                       +----------+            +-------------+         0| |
                                        192.0.2.100   +--------+                     /24| |
                                                      |        |        +----------+----+ |
                                                      |h3      |        |          |      |
                                                      |10      |        |  h2      |      |
                                                      +---+----+        |  10      |      |
                                                          |             +----------+      |
                                                          |172.31.2.0/24                  |
                                                          +--------------------------------+
"""

import os
import sys
import json
from functools import partial
import pytest
import functools

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgpcheck import (
    check_show_bgp_vpn_prefix_found,
    check_show_bgp_vpn_prefix_not_found,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.checkping import check_ping


# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Allocate 8 devices
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("h1")
    tgen.add_router("h2")
    tgen.add_router("h3")
    tgen.add_router("rr100")
    tgen.add_router("rs200")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["rr100"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["rs200"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["h2"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["h3"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r3"])


def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "ip link add vrf1 type vrf table 10",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
        "ip link set dev vrf1 up",
        "ip link set dev {0}-eth1 master vrf1",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth0/input",
    ]

    for rname in ("r1", "r3"):
        for cmd in cmds_list:
            input = cmd.format(rname)
            logger.info("input: " + cmd)
            output = tgen.net[rname].cmd(cmd.format(rname))
            logger.info("output: " + output)

    cmds_list = [
        "ip link set dev {0}-eth2 master vrf1",
        "ip link set dev {0}-eth3 master vrf1",
    ]
    for cmd in cmds_list:
        input = cmd.format("r3")
        logger.info("input: " + input)
        output = tgen.net["r3"].cmd(input)
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
        if rname in ("r1", "r2", "r3", "rr100", "rs200"):
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def bgp_vpnv4_prefix_check(router, rd, prefix, label, nexthop):
    """
    Dump and check 'show bgp ipv4 vpn <prefix> json' output. An assert is triggered in case test fails
    * 'router': the router to check
    * 'rd': The route distinguisher expected
    * 'prefix': The prefix expected
    * 'label': The label expected associated with the ('rd','prefix') tuple
    * 'nexthop': The nexthop expected associated with the ('rd','prefix') tuple
    """

    def _check(router, prefix, rd, label, nexthop):
        dump = router.vtysh_cmd("show bgp ipv4 vpn {} json".format(prefix), isjson=True)
        if not dump:
            return "{0}, {1}, route distinguisher {2} not present".format(
                router.name, prefix, rd
            )
        for dumped_rd, pathes in dump.items():
            if dumped_rd != rd:
                continue
            for path in pathes["paths"]:
                if "remoteLabel" not in path.keys():
                    return "{0}, {1}, rd {2}, remoteLabel not present".format(
                        router.name, prefix, rd
                    )
                if str(path["remoteLabel"]) != label:
                    continue

                if "nexthops" not in path.keys():
                    return "{0}, {1}, rd {2}, no nexthops present".format(
                        router.name, prefix, rd
                    )

                for nh in path["nexthops"]:
                    if "ip" not in nh.keys():
                        return "{0}, {1}, rd {2}, no ipv4 nexthop available".format(
                            router.name, prefix, rd
                        )
                    if nh["ip"] != nexthop:
                        continue
                    return None
        return "{0}, {1}, rd {2}, remoteLabel {3}, nexthop {4} not found".format(
            router.name, prefix, rd, label, nexthop
        )

    func = functools.partial(_check, router, prefix, rd, label, nexthop)
    success, result = topotest.run_and_expect(func, None, count=20, wait=0.5)
    assert_msg = "{}, show bgp ipv4 vpn {}, rd {}, label {} nexthop {}".format(
        router.name, prefix, rd, label, nexthop
    )
    assert result is None, assert_msg + " not found"
    logger.info(assert_msg + " found")


def mpls_table_get_entry(router, out_label, out_nexthop):
    """
    Get the in_label from tuple (out_label, out_nexthop)
    * 'router': the router to check
    * 'out_label': The outgoing label expected
    * 'out_nexthop': The outgoing nexthop expected
    """
    dump = router.vtysh_cmd("show mpls table json", isjson=True)
    for in_label, label_info in dump.items():
        for nh in label_info["nexthops"]:
            if nh["type"] != "BGP" or "installed" not in nh.keys():
                continue
            if "nexthop" in nh.keys():
                if nh["nexthop"] != out_nexthop:
                    continue
            if "outLabelStack" in nh.keys():
                if out_label not in nh["outLabelStack"]:
                    continue
            return in_label
    return None


def mpls_table_check_entry(router, out_label, out_nexthop):
    """
    Dump and check 'show mpls table json' output. An assert is triggered in case test fails
    * 'router': the router to check
    * 'out_label': The outgoing label expected
    * 'out_nexthop': The outgoing nexthop expected
    """
    logger.info("Checking MPLS labels on {}".format(router.name))
    dump = router.vtysh_cmd("show mpls table json", isjson=True)
    for in_label, label_info in dump.items():
        for nh in label_info["nexthops"]:
            if nh["type"] != "BGP" or "installed" not in nh.keys():
                continue
            if "nexthop" in nh.keys():
                if nh["nexthop"] != out_nexthop:
                    continue
            if "outLabelStack" in nh.keys():
                if out_label not in nh["outLabelStack"]:
                    continue
            logger.info(
                "{}, show mpls table, entry in_label {} out_label {} out_nexthop {} found".format(
                    router.name, in_label, nh["outLabelStack"], nh["nexthop"]
                )
            )
            return None
    return "{}, show mpls table, entry matching in_label {} out_label {} out_nexthop {} not found".format(
        router.name, in_label, out_label, out_nexthop
    )


def check_show_mpls_table_entry_label_not_found(router, inlabel):
    output = json.loads(router.vtysh_cmd("show mpls table {} json".format(inlabel)))
    expected = {"inLabel": inlabel, "installed": True}
    ret = topotest.json_cmp(output, expected)
    if ret is None:
        return "not good"
    return None


def check_show_bgp_vpn_ok(router, vpnv4_entries):
    """
    Check on router that BGP l3vpn entries are present
    Check there is an MPLS entry bound to that BGP L3VPN entry
    Extract the Label value and check on the distributed router the BGP L3VPN entry
    If check fail, an assert is triggered.
    * 'router': the router to check BGP VPN RIB
    * 'vpnv4_entries': dictionary that contains the list of prefixes, and the distributed router to look after
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vpnv4_nexthops = {"r1": "192.0.2.2", "r3": "192.168.1.2"}
    vpnv4_nht = {"192.0.2.1": "192.168.0.1", "192.168.1.3": "192.168.1.3"}
    label_ip_entries = {}

    def _return_remote_label_nh_rd(router, prefix):
        dump = router.vtysh_cmd("show bgp ipv4 vpn {} json".format(prefix), isjson=True)
        assert_msg = (
            "{}, prefix {} not available or label not found",
            router.name,
            prefix,
        )
        assert dump, assert_msg
        for rd, pathes in dump.items():
            for path in pathes["paths"]:
                if "remoteLabel" not in path.keys():
                    assert 0, assert_msg
                for nh in path["nexthops"]:
                    if "ip" in nh.keys():
                        return path["remoteLabel"], nh["ip"], rd
        assert 0, assert_msg

    def _check_nexthop_available(router, prefix):
        dump = router.vtysh_cmd("show bgp ipv4 vpn {} json".format(prefix), isjson=True)
        if not dump:
            return "{0}, {1}, route distinguisher not present".format(
                router.name, prefix
            )
        for rd, pathes in dump.items():
            for path in pathes["paths"]:
                if "remoteLabel" not in path.keys():
                    return "{0}, {1}, remoteLabel not present".format(
                        router.name, prefix
                    )
                if "nexthops" not in path.keys():
                    return "{0}, {1}, no nexthop available".format(router.name, prefix)
                return None

    for prefix, rname_to_test in vpnv4_entries.items():
        func = functools.partial(_check_nexthop_available, router, prefix)
        success, result = topotest.run_and_expect(func, None, count=20, wait=0.5)
        assert result is None, "Failed to detect prefix {} on router {}".format(
            prefix, router.name
        )

    for prefix, rname_to_test in vpnv4_entries.items():
        l3vpn_label, l3vpn_nh, l3vpn_rd = _return_remote_label_nh_rd(router, prefix)
        logger.info(
            "{0}, {1}, label value is {2}, nh is {3}".format(
                router.name, prefix, l3vpn_label, l3vpn_nh
            )
        )
        test_func = functools.partial(
            mpls_table_check_entry, router, l3vpn_label, vpnv4_nht[l3vpn_nh]
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, result

        in_label = mpls_table_get_entry(router, l3vpn_label, vpnv4_nht[l3vpn_nh])
        label_ip_entries[prefix] = in_label

        bgp_vpnv4_prefix_check(
            tgen.gears[rname_to_test],
            l3vpn_rd,
            prefix,
            in_label,
            vpnv4_nexthops[rname_to_test],
        )

        return label_ip_entries


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    Check that Labels are as expected in r1, r2,and r3
    Check ping connectivity between h1 and h2
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


def test_mpls_setup_ok():
    """
    tests for the r1 to r3 direction: checks for prefix=('172.31.1.0/24','172.31.2.0/24','172.31.3.0/24')
               r2. get label from 'prefix'
    check that r2. show mpls table has an entry with outbound label set to the label from 172.31.1.0/24
               r2. get label from mpls entry
    check that r1: show bgp ipv4 vpn 172.31.1.0/24 has label from r2.mpls entry
    tests for the r3 to r1 direction
               r2. get label from 172.31.0.0/24
    check that r2. show mpls table has an entry with outbound label set that includes the label from 172.31.0.0/24
               r2. get label from mpls entry
    check that r3: show bgp ipv4 vpn 172.31.0.0/24 has label from r2.mpls entry
    check that h1. ping 172.31.1.10 (h2) is ok.
    check that h1. ping 172.31.2.10 (h3) is ok.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r2"]

    # diagnostic
    logger.info("Dumping mplsvpn nexthop table")
    router.vtysh_cmd("show bgp mplsvpn-nh-label-bind detail", isjson=False)

    vpnv4_checks = {
        "172.31.1.0/24": "r1",
        "172.31.2.0/24": "r1",
        "172.31.3.0/24": "r1",
        "172.31.0.0/24": "r3",
    }
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' and 'show mpls table' are set accordingly on all devices".format(
            router.name
        )
    )
    check_show_bgp_vpn_ok(router, vpnv4_checks)

    logger.info("h1, check that ping from h1 to (h2,h3) is ok")
    check_ping("h1", "172.31.1.10", True, 20, 0.5)
    check_ping("h1", "172.31.2.10", True, 20, 0.5)


def test_r3_prefixes_removed():
    """
    Remove BGP redistributed updates from r3.
    Check that the BGP VPN updates from the updates are not present on r2.
    Check that the 'show bgp ipv4 vpn' and 'show mpls table' are ok for 172.31.3.0/24
    Remove the 172.31.3.0/24 update from BGP on r3.
    Check that the BGP VPN updates from r3 are not present on r2.
    Check that the 'show mpls table' entry previously seen disappeared
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r3"]
    logger.info("{}, keeping only 172.31.3.0/24 network".format(router.name))
    router.vtysh_cmd("configure terminal\ninterface r3-eth1 vrf vrf1\nshutdown\n")
    router.vtysh_cmd("configure terminal\ninterface r3-eth2 vrf vrf1\nshutdown\n")

    router = tgen.gears["r2"]
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' has only 172.31.3.0/24 network from r3".format(
            router.name
        )
    )

    for prefix in ("172.31.1.0/24", "172.31.2.0/24"):
        test_func = functools.partial(
            check_show_bgp_vpn_prefix_not_found,
            router,
            "ipv4",
            prefix,
            "444:3",
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, "{}, vpnv4 update {} still present".format(router.name, prefix)

    # diagnostic
    logger.info("Dumping mplsvpn nexthop table")
    router.vtysh_cmd("show bgp mplsvpn-nh-label-bind detail", isjson=False)

    prefix = "172.31.3.0/24"
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' and 'show mpls table' are set accordingly on r2 and on r1".format(
            router.name
        )
    )
    vpnv4_checks = {
        prefix: "r1",
    }
    label_ip_entries = check_show_bgp_vpn_ok(router, vpnv4_checks)

    router = tgen.gears["r3"]
    logger.info("{}, removing {} network".format(router.name, prefix))
    router.vtysh_cmd("configure terminal\ninterface r3-eth3 vrf vrf1\nshutdown\n")

    router = tgen.gears["r2"]
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' has not {} network from r3".format(
            router.name, prefix
        )
    )
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_not_found,
        router,
        "ipv4",
        prefix,
        "444:3",
    )
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {} still present".format(router.name, prefix)

    logger.info(
        "{}, check that 'show mpls table {}' is not present".format(
            router.name, label_ip_entries[prefix]
        )
    )
    test_func = functools.partial(
        check_show_mpls_table_entry_label_not_found, router, label_ip_entries[prefix]
    )
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "r1, mpls entry with in_label {} still present".format(
        label_ip_entries[prefix]
    )


def test_r3_prefixes_added_back():
    """
    Add back the 172.31.3.0/24 network from r3
    Check on r2 that MPLS switching entry appears when the 1st BGP update is received
    Check the IP connectivity (h1,h2) and (h1,h3)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r3"]
    prefix = "172.31.3.0/24"
    logger.info("{}, restoring the {} network from r3".format(router.name, prefix))
    router.vtysh_cmd("configure terminal\ninterface r3-eth3 vrf vrf1\nno shutdown\n")

    router = tgen.gears["r2"]
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' has {} network from r3".format(
            router.name, prefix
        )
    )

    test_func = functools.partial(
        check_show_bgp_vpn_prefix_found,
        router,
        "ipv4",
        prefix,
        "444:3",
    )
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {} not present".format(router.name, prefix)

    logger.info(
        "{}, check that 'show bgp ipv4 vpn' and 'show mpls table' are set accordingly on r2 and on r1".format(
            router.name
        )
    )
    vpnv4_checks = {
        prefix: "r1",
    }
    check_show_bgp_vpn_ok(router, vpnv4_checks)

    router = tgen.gears["r3"]
    logger.info(
        "{}, restoring the redistribute connected prefixes from r3".format(router.name)
    )
    router.vtysh_cmd("configure terminal\ninterface r3-eth1 vrf vrf1\nno shutdown\n")
    router.vtysh_cmd("configure terminal\ninterface r3-eth2 vrf vrf1\nno shutdown\n")
    router = tgen.gears["r2"]
    for prefix in ("172.31.1.0/24", "172.31.2.0/24"):
        test_func = functools.partial(
            check_show_bgp_vpn_prefix_found,
            router,
            "ipv4",
            prefix,
            "444:3",
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, "{}, vpnv4 update {} not present".format(router.name, prefix)

    # diagnostic
    logger.info("Dumping mplsvpn nexthop table")
    tgen.gears["r2"].vtysh_cmd("show bgp mplsvpn-nh-label-bind detail", isjson=False)


def test_unconfigure_nexthop_change_nexthop_self():
    """
    Get the list of labels advertised from r2 to r1
    On r2, disable next-hop-self for 192.0.2.100 neighbor
    Check that the list of labels are not present in 'show mpls table'
    Check that r1 received the prefixes with the original (next-hop,label)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]
    vpnv4_checks = {
        "172.31.1.0/24": "r1",
        "172.31.2.0/24": "r1",
        "172.31.3.0/24": "r1",
    }
    logger.info(
        "{}, Get the list of labels allocated for prefixes from r3".format(router.name)
    )
    label_ip_entries = check_show_bgp_vpn_ok(router, vpnv4_checks)

    logger.info(
        "{}, disable next-hop-self for 192.0.2.100 neighbor".format(router.name)
    )
    router = tgen.gears["r2"]
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65500\naddress-family ipv4 vpn\nno neighbor 192.0.2.100 next-hop-self\n"
    )

    for prefix, label in label_ip_entries.items():
        logger.info(
            "{}, check mpls entry for {} with in_label {} is not present'".format(
                router.name, prefix, label
            )
        )
        test_func = functools.partial(
            check_show_mpls_table_entry_label_not_found, router, label
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, "r1, mpls entry for {} with in_label {} still present".format(
            prefix, label
        )

    router = tgen.gears["r1"]
    for prefix, label in label_ip_entries.items():
        test_func = functools.partial(
            check_show_bgp_vpn_prefix_not_found,
            router,
            "ipv4",
            prefix,
            "444:3",
            label=label,
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, "{}, mpls vpn update {} label {} is present".format(
            router.name, prefix, label
        )
    for prefix, label in label_ip_entries.items():
        test_func = functools.partial(
            check_show_bgp_vpn_prefix_found,
            router,
            "ipv4",
            prefix,
            "444:3",
            nexthop="192.168.1.3",
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, "{}, mpls vpn update {} label {} is present".format(
            router.name, prefix, label
        )

    # diagnostic
    logger.info("Dumping mplsvpn nexthop table")
    tgen.gears["r2"].vtysh_cmd("show bgp mplsvpn-nh-label-bind detail", isjson=False)


def test_reconfigure_nexthop_change_nexthop_self():
    """
    Get the list of labels advertised from r2 to r1
    On r2, enable next-hop-self for 192.0.2.100 neighbor
    Check that the list of labels are present in 'show mpls table'
    Check that r1 received the prefixes with the original (next-hop,label)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]
    logger.info("{}, enable next-hop-self for 192.0.2.100 neighbor".format(router.name))
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65500\naddress-family ipv4 vpn\nneighbor 192.0.2.100 next-hop-self\n"
    )
    vpnv4_checks = {
        "172.31.1.0/24": "r1",
        "172.31.2.0/24": "r1",
        "172.31.3.0/24": "r1",
    }
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' and 'show mpls table' are set accordingly on r2 and on r1".format(
            router.name
        )
    )
    check_show_bgp_vpn_ok(router, vpnv4_checks)

    logger.info("h1, check that ping from h1 to (h2,h3) is ok")
    check_ping("h1", "172.31.1.10", True, 20, 0.5)
    check_ping("h1", "172.31.2.10", True, 20, 0.5)
    # diagnostic
    logger.info("Dumping mplsvpn nexthop table")
    router.vtysh_cmd("show bgp mplsvpn-nh-label-bind detail", isjson=False)


def test_declare_vpn_network_with_different_label():
    """
    declare a vpnv4 network on r3.
    check that a new VPNv4 entry is received on r2.
    Check that the list of labels are present in 'show mpls table'
    Check that r1 received the prefixes with the new (next-hop,label)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r3"]
    logger.info(
        "{}, declare static 33.33.33.33/32 network rd 33:33 label 33".format(
            router.name
        )
    )
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65501\nno bgp network import-check\n"
    )
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65501\naddress-family ipv4 vpn\nnetwork 33.33.33.33/32 rd 444:3 label 33\n"
    )

    router = tgen.gears["r2"]
    vpnv4_entries = {
        "172.31.1.0/24": None,
        "172.31.2.0/24": None,
        "172.31.3.0/24": None,
        "33.33.33.33/32": 33,
    }

    for prefix, label in vpnv4_entries.items():
        test_func = functools.partial(
            check_show_bgp_vpn_prefix_found,
            router,
            "ipv4",
            prefix,
            "444:3",
            label=label,
            nexthop="192.168.1.3",
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, "{}, vpnv4 update {}, label {} not present".format(
            router.name, prefix, label
        )

    vpnv4_checks = {
        "172.31.1.0/24": "r1",
        "172.31.2.0/24": "r1",
        "172.31.3.0/24": "r1",
        "33.33.33.33/32": "r1",
    }
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' and 'show mpls table' are set accordingly on r2 and on r1".format(
            router.name
        )
    )
    check_show_bgp_vpn_ok(router, vpnv4_checks)


def test_filter_vpn_network_from_r1():
    """
    Get the list of labels in 'show mpls table'
    filter network from r1
    check that the vpnv4 entry on r2 is not present
    Check that the associated mpls entry is not present
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]

    vpnv4_checks = {
        "172.31.0.0/24": "r3",
    }
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' and 'show mpls table' are set accordingly on r2 and on r3".format(
            router.name
        )
    )
    label_ip_entries = check_show_bgp_vpn_ok(router, vpnv4_checks)

    for prefix, label in label_ip_entries.items():
        logger.info("{}, filter prefix {} from r1".format(router.name, prefix))
        router.vtysh_cmd(
            "configure terminal\nroute-map rmap deny 1\nmatch ip next-hop address 192.0.2.1\n"
        )
        router.vtysh_cmd(
            "configure terminal\nrouter bgp 65500\naddress-family ipv4 vpn\nneighbor 192.0.2.100 route-map rmap in\n"
        )
        logger.info(
            "{}, check that prefix {} is not present".format(router.name, prefix)
        )
        test_func = functools.partial(
            check_show_bgp_vpn_prefix_not_found,
            router,
            "ipv4",
            "172.31.0.0/24",
            "444:1",
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, "{}, vpnv4 update {}, is still present".format(
            router.name, prefix
        )

        # diagnostic
        logger.info("Dumping mplsvpn nexthop table")
        router.vtysh_cmd("show bgp mplsvpn-nh-label-bind detail", isjson=False)

        logger.info(
            "{}, check that show mpls table {} is not present".format(
                router.name, label
            )
        )
        test_func = functools.partial(
            check_show_mpls_table_entry_label_not_found, router, int(label)
        )
        success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assert success, "r1, mpls entry for {} with in_label {} still present".format(
            prefix, label
        )


def test_unfilter_vpn_network_from_r1():
    """
    unfilter network from r1
    check that the vpnv4 entry on r2 is present
    Check that the list of labels are present in 'show mpls table'
    Check that r3 received the prefixes with the new (next-hop,label)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]
    prefix = "172.31.0.0/24"

    logger.info("{}, filter prefix {} from r1".format(router.name, prefix))
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65500\naddress-family ipv4 vpn\nno neighbor 192.0.2.100 route-map rmap in\n"
    )

    logger.info("{}, check that prefix {} is present".format(router.name, prefix))
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_found, router, "ipv4", prefix, "444:1"
    )
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "{}, vpnv4 update {}, is not present".format(router.name, prefix)

    vpnv4_checks = {
        "172.31.0.0/24": "r3",
    }
    logger.info(
        "{}, check that 'show bgp ipv4 vpn' and 'show mpls table' are set accordingly on all devices".format(
            router.name
        )
    )
    check_show_bgp_vpn_ok(router, vpnv4_checks)

    # diagnostic
    logger.info("Dumping mplsvpn nexthop table")
    router.vtysh_cmd("show bgp mplsvpn-nh-label-bind detail", isjson=False)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
