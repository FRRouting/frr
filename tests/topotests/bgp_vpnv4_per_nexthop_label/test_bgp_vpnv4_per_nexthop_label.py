#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_vpnv4_per_nexthop_label.py
#
# Copyright 2023 6WIND S.A.
#

"""
 test_bgp_vpnv4_per_nexthop_label.py: Test the FRR BGP daemon using EBGP peering
 Let us exchange VPNv4 updates between both devices
 Updates from r1 will originate from the same RD, but will have separate
 label values.

     +----------+
     |   r11    |
     |192.0.2.11+---+
     |          |   |                   +----+--------+              +----------+
     +----------+   |         192.0.2.1 |vrf | r1     |192.168.0.0/24|    r2    |
                    +-------------------+    |       1+--------------+          |
     +----------+   |                   |VRF1|AS65500 |              | AS65501  |
     |   r12    |   |     +-------------+    |   VPNV4|              |VPNV4     |
     |192.0.2.12+---+     |192.168.255.1+-+--+--------+              +----------+
     |          |         |
     +----------+         |
                          |
     +----------+         |
     |   r13    |         |
     |192.168.  +---------+
     | 255.13   |
     +----------+
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.bgpd]

PREFIXES_R11 = ["172.31.0.11/32", "172.31.0.20/32", "172.31.0.111/32"]
PREFIXES_R12 = ["172.31.0.12/32", "172.31.0.15/32"]
PREFIXES_R13 = ["172.31.0.13/32"]
PREFIXES_REDIST = ["172.31.0.14/32"]
PREFIXES_CONNECTED = ["192.168.255.0/24", "192.0.2.0/24"]


def build_topo(tgen):
    "Build function"

    # Create 2 routers.
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r11")
    tgen.add_router("r12")
    tgen.add_router("r13")
    tgen.add_router("r14")
    tgen.add_router("rr")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r11"])
    switch.add_link(tgen.gears["r12"])
    switch.add_link(tgen.gears["rr"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r13"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r14"])


def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "ip link add vrf1 type vrf table 10",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
        "ip link set dev vrf1 up",
        "ip link set dev {0}-eth1 master vrf1",
        "echo 1 > /proc/sys/net/mpls/conf/{0}-eth0/input",
    ]
    cmds_list_plus = [
        "ip link set dev {0}-eth2 master vrf1",
    ]

    for cmd in cmds_list:
        input = cmd.format("r1")
        logger.info("input: " + cmd)
        output = tgen.net["r1"].cmd(cmd.format("r1"))
        logger.info("output: " + output)

    for cmd in cmds_list_plus:
        input = cmd.format("r1")
        logger.info("input: " + cmd)
        output = tgen.net["r1"].cmd(cmd.format("r1"))
        logger.info("output: " + output)

    for cmd in cmds_list:
        input = cmd.format("r2")
        logger.info("input: " + cmd)
        output = tgen.net["r2"].cmd(cmd.format("r2"))
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


def check_bgp_vpnv4_prefix_presence(router, prefix, table_version):
    "Check the presence of a prefix"
    tgen = get_topogen()

    dump = router.vtysh_cmd("show bgp ipv4 vpn {} json".format(prefix), isjson=True)
    if not dump:
        return "{}, prefix ipv4 vpn {} is not installed yet".format(router.name, prefix)

    for _, paths in dump.items():
        for path in paths["paths"]:
            new_version = path["version"]
        if new_version <= table_version:
            return "{}, prefix ipv4 vpn {} has not been updated yet".format(
                router.name, prefix
            )

    return None


def bgp_vpnv4_table_check(
    router, group, label_list=None, label_value_expected=None, table_version=0
):
    """
    Dump and check that vpnv4 entries have the same MPLS label value
    * 'router': the router to check
    * 'group': the list of prefixes to check. a single label value for the group has to be found
    * 'label_list': check that the label values are not present in the vpnv4 entries
    *              that list is updated with the present label value
    * 'label_value_expected': check that the mpls label read is the same as that value
    """

    stored_label_inited = False
    for prefix in group:
        test_func = functools.partial(
            check_bgp_vpnv4_prefix_presence, router, prefix, table_version
        )
        success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
        assert success, "{}, prefix ipv4 vpn {} is not installed yet".format(
            router.name, prefix
        )

        dump = router.vtysh_cmd("show bgp ipv4 vpn {} json".format(prefix), isjson=True)
        assert dump, "{0}, {1}, route distinguisher not present".format(
            router.name, prefix
        )
        for _, pathes in dump.items():
            for path in pathes["paths"]:
                assert (
                    "remoteLabel" in path.keys()
                ), "{0}, {1}, remoteLabel not present".format(router.name, prefix)
                logger.info(
                    "{0}, {1}, label value is {2}".format(
                        router.name, prefix, path["remoteLabel"]
                    )
                )
                if stored_label_inited:
                    assert (
                        path["remoteLabel"] == stored_label
                    ), "{0}, {1}, label value not expected one (expected {2}, observed {3}".format(
                        router.name, prefix, stored_label, path["remoteLabel"]
                    )
                else:
                    stored_label = path["remoteLabel"]
                    stored_label_inited = True
                    if label_list is not None:
                        assert (
                            stored_label not in label_list
                        ), "{0}, {1}, label already detected in a previous prefix".format(
                            router.name, prefix
                        )
                        label_list.add(stored_label)

                if label_value_expected:
                    assert (
                        path["remoteLabel"] == label_value_expected
                    ), "{0}, {1}, label value not expected (expected {2}, observed {3}".format(
                        router.name, prefix, label_value_expected, path["remoteLabel"]
                    )


def bgp_vpnv4_table_check_all(router, label_list=None, same=False, table_version=0):
    """
    Dump and check that vpnv4 entries are correctly configured with specific label values
    * 'router': the router to check
    * 'label_list': check that the label values are not present in the vpnv4 entries
    *              that list is updated with the present label value found.
    * 'same': by default, set to False. Addresses groups are classified by addresses.
    *         if set to True, all entries of all groups should have a unique label value
    """
    if same:
        bgp_vpnv4_table_check(
            router,
            group=PREFIXES_R11
            + PREFIXES_R12
            + PREFIXES_R13
            + PREFIXES_REDIST
            + PREFIXES_CONNECTED,
            label_list=label_list,
            table_version=table_version,
        )
    else:
        for group in (
            PREFIXES_R11,
            PREFIXES_R12,
            PREFIXES_R13,
            PREFIXES_REDIST,
            PREFIXES_CONNECTED,
        ):
            bgp_vpnv4_table_check(
                router, group=group, label_list=label_list, table_version=table_version
            )


def check_show_mpls_table(router, blacklist=None, label_list=None, whitelist=None):
    nexthop_list = []
    if blacklist:
        nexthop_list.append(blacklist)

    dump = router.vtysh_cmd("show mpls table json", isjson=True)
    for in_label, label_info in dump.items():
        if label_list is not None:
            label_list.add(in_label)
        for nh in label_info["nexthops"]:
            if "installed" not in nh.keys():
                return "{} {} is not installed yet on {}".format(
                    in_label, label_info, router.name
                )
            if nh["installed"] != True or nh["type"] != "BGP":
                return "{}, show mpls table, nexthop is not installed".format(
                    router.name
                )
            if "nexthop" in nh.keys():
                if nh["nexthop"] in nexthop_list:
                    return "{}, show mpls table, duplicated or blacklisted nexthop address".format(
                        router.name
                    )
                nexthop_list.append(nh["nexthop"])
            elif "interface" in nh.keys():
                if nh["interface"] in nexthop_list:
                    return "{}, show mpls table, duplicated or blacklisted nexthop interface".format(
                        router.name
                    )
                nexthop_list.append(nh["interface"])
            else:
                return "{}, show mpls table, entry with neither nexthop nor interface".format(
                    router.name
                )

    if whitelist:
        for entry in whitelist:
            if entry not in nexthop_list:
                return "{}, show mpls table, entry with nexthop {} not present in nexthop list".format(
                    router.name, entry
                )
    return None


def mpls_table_check(router, blacklist=None, label_list=None, whitelist=None):
    """
    Dump and check 'show mpls table json' output. An assert is triggered in case test fails
    * 'router': the router to check
    * 'blacklist': the list of nexthops (IP or interface) that should not be on output
    * 'label_list': the list of labels that should be in inLabel value
    * 'whitelist': the list of nexthops (IP or interface) that should be on output
    """
    logger.info("Checking MPLS labels on {}".format(router.name))
    # Check r2 removed 172.31.0.30 vpnv4 update
    test_func = functools.partial(
        check_show_mpls_table, router, blacklist, label_list, whitelist
    )
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "{}, MPLS labels check fail: {}".format(router.name, result)


def check_show_bgp_vpn_prefix_not_found(router, ipversion, prefix, rd, label=None):
    output = json.loads(
        router.vtysh_cmd("show bgp {} vpn {} json".format(ipversion, prefix))
    )
    if label:
        expected = {rd: {"prefix": prefix, "paths": [{"remoteLabel": label}]}}
    else:
        expected = {rd: {"prefix": prefix}}
    ret = topotest.json_cmp(output, expected)
    if ret is None:
        return "not good"
    return None


def check_show_bgp_vpn_prefix_found(router, ipversion, prefix, rd):
    output = json.loads(
        router.vtysh_cmd("show bgp {} vpn {} json".format(ipversion, prefix))
    )
    expected = {rd: {"prefix": prefix}}
    return topotest.json_cmp(output, expected)


def check_show_mpls_table_entry_label_found_nexthop(
    expected_router, get_router, network, nexthop
):
    label = get_mpls_label(get_router, network)
    if label < 0:
        return False

    output = json.loads(
        expected_router.vtysh_cmd("show mpls table {} json".format(label))
    )
    expected = {
        "inLabel": label,
        "installed": True,
        "nexthops": [{"nexthop": nexthop}],
    }
    return topotest.json_cmp(output, expected)


def check_show_mpls_table_entry_label_found(
    expected_router, get_router, interface, network=None, label=None
):
    if not label:
        label = get_mpls_label(get_router, network)
        if label < 0:
            return False

    output = json.loads(
        expected_router.vtysh_cmd("show mpls table {} json".format(label))
    )
    expected = {
        "inLabel": label,
        "installed": True,
        "nexthops": [{"interface": interface}],
    }
    return topotest.json_cmp(output, expected)


def check_show_mpls_table_entry_label_not_found(router, inlabel):
    output = json.loads(router.vtysh_cmd("show mpls table {} json".format(inlabel)))
    expected = {"inlabel": inlabel, "installed": True}
    ret = topotest.json_cmp(output, expected)
    if ret is None:
        return "not good"
    return None


def get_table_version(router):
    table = router.vtysh_cmd("show bgp ipv4 vpn json", isjson=True)
    return table["tableVersion"]


def mpls_entry_get_interface(router, label):
    """
    Assert that the label is in MPLS table
    Assert an outgoing interface is programmed
    return the outgoing interface
    """
    outgoing_interface = None

    logger.info("Checking MPLS labels on {}".format(router.name))
    dump = router.vtysh_cmd("show mpls table {} json".format(label), isjson=True)
    assert dump, "{0}, label {1} not present".format(router.name, label)

    for nh in dump["nexthops"]:
        assert (
            "interface" in nh.keys()
        ), "{}, show mpls table, nexthop interface not present for MPLS entry {}".format(
            router.name, label
        )

        outgoing_interface = nh["interface"]

    return outgoing_interface


def get_mpls_label(router, network):
    label = router.vtysh_cmd(
        "show ip route vrf vrf1 %s json" % network,
        isjson=True,
    )
    label = label.get(f"{network}", [{}])[0].get("nexthops", [{}])[0]
    label = int(label.get("labels", [-1])[0])

    return label


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check BGP IPv4 routing tables on VRF1 of r1
    logger.info("Checking BGP IPv4 routes for convergence on r1 VRF1")
    router = tgen.gears["r1"]
    json_file = "{}/{}/bgp_ipv4_routes_vrf1.json".format(CWD, router.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp vrf vrf1 ipv4 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg

    logger.info("Checking BGP VPNv4 routes for convergence on r2")
    router = tgen.gears["r2"]
    json_file = "{}/{}/bgp_vpnv4_routes.json".format(CWD, router.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show bgp ipv4 vpn json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg

    # Check BGP labels received on r2
    logger.info("Checking BGP VPNv4 labels on r2")
    label_list = set()
    bgp_vpnv4_table_check_all(tgen.gears["r2"], label_list)

    # Check MPLS labels received on r1
    mpls_table_check(tgen.gears["r1"], label_list)


def test_flapping_bgp_vrf_down():
    """
    Turn down a remote BGP session
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Unpeering BGP on r11")
    tgen.gears["r11"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500\nno neighbor 192.0.2.100\n",
        isjson=False,
    )

    def _bgp_prefix_not_found(router, vrf, ipversion, prefix):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp vrf {} {} {} json".format(vrf, ipversion, prefix)
            )
        )
        expected = {"prefix": prefix}
        ret = topotest.json_cmp(output, expected)
        if ret is None:
            return "not good"
        return None

    # Check prefix from r11 is not present
    test_func = functools.partial(
        _bgp_prefix_not_found, tgen.gears["r1"], "vrf1", "ipv4", "172.31.0.11/32"
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert (
        success
    ), "r1, prefix 172.31.0.11/32 from r11 did not disappear. r11 still connected to rr ?"

    # Check BGP updated received on r2 are not from r11
    logger.info("Checking BGP VPNv4 labels on r2")
    for entry in PREFIXES_R11:
        dump = tgen.gears["r2"].vtysh_cmd(
            "show bgp ipv4 vpn {} json".format(entry), isjson=True
        )
        for rd in dump:
            assert False, "r2, {}, route distinguisher {} present".format(entry, rd)

    mpls_table_check(tgen.gears["r1"], blacklist=["192.0.2.11"])


def test_flapping_bgp_vrf_up():
    """
    Turn up a remote BGP session
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Peering BGP on r11")
    tgen.gears["r11"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500\nneighbor 192.0.2.100 remote-as 65500\n",
        isjson=False,
    )

    # Check r2 gets prefix 172.31.0.11/128
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_found,
        tgen.gears["r2"],
        "ipv4",
        "172.31.0.11/32",
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert (
        success
    ), "r2, prefix 172.31.0.11/32 from r11 not present. r11 still disconnected from rr ?"
    bgp_vpnv4_table_check_all(tgen.gears["r2"])


def test_recursive_route():
    """
    Test static recursive route redistributed over BGP
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling recursive static route")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nvrf vrf1\nip route 172.31.0.30/32 172.31.0.20\n",
        isjson=False,
    )
    logger.info("Checking BGP VPNv4 labels on r2")

    # Check r2 received vpnv4 update with 172.31.0.30
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_found,
        tgen.gears["r2"],
        "ipv4",
        "172.31.0.30/32",
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "r2, vpnv4 update 172.31.0.30 not found"

    bgp_vpnv4_table_check(tgen.gears["r2"], group=PREFIXES_R11 + ["172.31.0.30/32"])

    # diagnostic
    logger.info("Dumping label nexthop table")
    tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf1 label-nexthop detail", isjson=False)
    logger.info("Dumping nexthop table")
    tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf1 nexthop detail", isjson=False)

    logger.info("Disabling recursive static route")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nvrf vrf1\nno ip route 172.31.0.30/32 172.31.0.20\n",
        isjson=False,
    )
    logger.info("Checking BGP VPNv4 labels on r2")

    # Check r2 removed 172.31.0.30 vpnv4 update
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_not_found,
        tgen.gears["r2"],
        "ipv4",
        "172.31.0.30/32",
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "r2, vpnv4 update 172.31.0.30 still present"


def test_prefix_changes_interface():
    """
    Test BGP update for a given prefix learnt on different interface
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling a 172.31.0.50/32 prefix for r11")
    tgen.gears["r11"].vtysh_cmd(
        "configure terminal\nrouter bgp\naddress-family ipv4 unicast\nnetwork 172.31.0.50/32",
        isjson=False,
    )

    # Check r2 received vpnv4 update with 172.31.0.50
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_found,
        tgen.gears["r2"],
        "ipv4",
        "172.31.0.50/32",
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "r2, vpnv4 update 172.31.0.50 not found"

    # diagnostic
    logger.info("Dumping label nexthop table")
    tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf1 label-nexthop detail", isjson=False)

    label_list = set()
    bgp_vpnv4_table_check(
        tgen.gears["r2"],
        group=["172.31.0.11/32", "172.31.0.111/32", "172.31.0.50/32"],
        label_list=label_list,
    )

    assert (
        len(label_list) == 1
    ), "Multiple Label values found for updates from r11 found"

    oldlabel = label_list.pop()
    logger.info("r1, getting the outgoing interface used by label {}".format(oldlabel))
    old_outgoing_interface = mpls_entry_get_interface(tgen.gears["r1"], oldlabel)
    logger.info(
        "r1, outgoing interface used by label {} is {}".format(
            oldlabel, old_outgoing_interface
        )
    )

    logger.info("Moving the 172.31.0.50/32 prefix from r11 to r13")
    tgen.gears["r11"].vtysh_cmd(
        "configure terminal\nrouter bgp\naddress-family ipv4 unicast\nno network 172.31.0.50/32",
        isjson=False,
    )
    tgen.gears["r13"].vtysh_cmd(
        "configure terminal\nrouter bgp\naddress-family ipv4 unicast\nnetwork 172.31.0.50/32",
        isjson=False,
    )

    # Check r2 removed 172.31.0.50 vpnv4 update with old label
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_not_found,
        tgen.gears["r2"],
        "ipv4",
        "172.31.0.50/32",
        "444:1",
        label=oldlabel,
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert (
        success
    ), "r2, vpnv4 update 172.31.0.50 with old label {0} still present".format(oldlabel)

    # diagnostic
    logger.info("Dumping label nexthop table")
    tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf1 label-nexthop detail", isjson=False)

    # Check r2 received new 172.31.0.50 vpnv4 update
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_found,
        tgen.gears["r2"],
        "ipv4",
        "172.31.0.50/32",
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "r2, vpnv4 update 172.31.0.50 not found"

    label_list = set()
    bgp_vpnv4_table_check(
        tgen.gears["r2"],
        group=PREFIXES_R13 + ["172.31.0.50/32"],
        label_list=label_list,
    )
    assert (
        len(label_list) == 1
    ), "Multiple Label values found for updates from r13 found"

    newlabel = label_list.pop()
    logger.info("r1, getting the outgoing interface used by label {}".format(newlabel))
    new_outgoing_interface = mpls_entry_get_interface(tgen.gears["r1"], newlabel)
    logger.info(
        "r1, outgoing interface used by label {} is {}".format(
            newlabel, new_outgoing_interface
        )
    )
    if old_outgoing_interface == new_outgoing_interface:
        assert 0, "r1, outgoing interface did not change whereas BGP update moved"

    logger.info("Restoring state by removing the 172.31.0.50/32 prefix from r13")
    tgen.gears["r13"].vtysh_cmd(
        "configure terminal\nrouter bgp\naddress-family ipv4 unicast\nno network 172.31.0.50/32",
        isjson=False,
    )


def test_changing_default_label_value():
    """
    Change the MPLS default value
    Check that r1 VPNv4 entries have the 222 label value
    Check that MPLS entry with old label value is no more present
    Check that MPLS entry for local traffic has inLabel set to 222
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    # counting the number of labels used in the VPNv4 table
    label_list = set()
    logger.info("r1, vpnv4 table, check the number of labels used before modification")
    bgp_vpnv4_table_check_all(router, label_list)
    old_len = len(label_list)
    assert (
        old_len != 1
    ), "r1, number of labels used should be greater than 1, oberved {} ".format(old_len)

    table_version = get_table_version(router)
    logger.info("r1, vrf1, changing the default MPLS label value to export to 222")
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\nlabel vpn export 222\n",
        isjson=False,
    )

    # Check r1 updated the MPLS entry with the 222 label value
    logger.info(
        "r1, mpls table, check that MPLS entry with inLabel set to 222 has vrf1 interface"
    )
    test_func = functools.partial(
        check_show_mpls_table_entry_label_found,
        tgen.gears["r1"],
        router,
        "vrf1",
        label=222,
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "r1, mpls entry with label 222 not found"

    # check label repartition is ok
    logger.info("r1, vpnv4 table, check the number of labels used after modification")
    label_list = set()
    bgp_vpnv4_table_check_all(router, label_list, table_version=table_version)
    new_len = len(label_list)
    assert (
        old_len == new_len
    ), "r1, number of labels after modification differ from previous, observed {}, expected {} ".format(
        new_len, old_len
    )

    logger.info(
        "r1, vpnv4 table, check that prefixes that were using the vrf label have refreshed the label value to 222"
    )
    bgp_vpnv4_table_check(
        router, group=["192.168.255.0/24", "192.0.2.0/24"], label_value_expected=222
    )


def test_unconfigure_allocation_mode_nexthop():
    """
    Test unconfiguring allocation mode per nexthop
    Check that show mpls table has no entry with label 17 (previously used)
    Check that all VPN updates on r1 should have label value moved to 222
    Check that show mpls table will only have 222 label value
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Unconfiguring allocation mode per nexthop")
    router = tgen.gears["r1"]
    table_version = get_table_version(router)
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\nno label vpn export allocation-mode per-nexthop\n",
        isjson=False,
    )

    # Check r1 updated the MPLS entry with the 222 label value
    logger.info(
        "r1, mpls table, check that MPLS entry with inLabel set to 17 is not present"
    )
    test_func = functools.partial(
        check_show_mpls_table_entry_label_not_found, router, 17
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "r1, mpls entry with label 17 still present"

    # Check vpnv4 routes from r1
    logger.info("Checking vpnv4 routes on r1")
    label_list = set()
    bgp_vpnv4_table_check_all(
        router, label_list=label_list, same=True, table_version=table_version
    )
    assert len(label_list) == 1, "r1, multiple Label values found for vpnv4 updates"

    new_label = label_list.pop()
    assert (
        new_label == 222
    ), "r1, wrong label value in VPNv4 table, expected 222, observed {}".format(
        new_label
    )

    # Check mpls table with 222 value
    logger.info("Checking MPLS values on show mpls table of r1")
    label_list = set()
    label_list.add(222)
    mpls_table_check(router, label_list=label_list)


def test_reconfigure_allocation_mode_nexthop():
    """
    Test re-configuring allocation mode per nexthop
    Check that show mpls table has no entry with label 17
    Check that all VPN updates on r1 should have multiple label values and not only 222
    Check that show mpls table will have multiple label values and not only 222
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Reconfiguring allocation mode per nexthop")
    router = tgen.gears["r1"]

    table_version = get_table_version(router)
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\nlabel vpn export allocation-mode per-nexthop\n",
        isjson=False,
    )

    # Check that show mpls table has no entry with label 17
    logger.info(
        "r1, mpls table, check that MPLS entry with inLabel set to 17 is present"
    )
    test_func = functools.partial(
        check_show_mpls_table_entry_label_not_found, router, 17
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "r1, mpls entry with label 17 still present"

    # Check vpnv4 routes from r1
    logger.info("Checking vpnv4 routes on r1")
    label_list = set()
    bgp_vpnv4_table_check_all(
        router, label_list=label_list, table_version=table_version
    )
    assert len(label_list) != 1, "r1, only 1 label values found for vpnv4 updates"

    # Check mpls table with all values
    logger.info("Checking MPLS values on show mpls table of r1")
    mpls_table_check(router, label_list=label_list)


def test_network_command():
    """
    Test with network declaration
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Disabling redistribute static")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\nno redistribute static\n",
        isjson=False,
    )
    logger.info("Checking BGP VPNv4 labels on r2")
    for p in ["172.31.0.24/32", "172.31.0.15/32"]:
        test_func = functools.partial(
            check_show_bgp_vpn_prefix_not_found, tgen.gears["r2"], "ipv4", p, "444:1"
        )
        success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
        assert success, "network %s should not present on r2" % p

    logger.info("Use network command for host networks declared in static instead")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\nnetwork 172.31.0.14/32\n",
        isjson=False,
    )
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\nnetwork 172.31.0.15/32\n",
        isjson=False,
    )
    logger.info("Checking BGP VPNv4 labels on r2")
    bgp_vpnv4_table_check(tgen.gears["r2"], group=["172.31.0.12/32", "172.31.0.15/32"])
    bgp_vpnv4_table_check(tgen.gears["r2"], group=["172.31.0.14/32"])
    mpls_table_check(tgen.gears["r1"], whitelist=["192.0.2.14"])

    logger.info(" Remove network to 172.31.0.14/32")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\nno network 172.31.0.14/32\n",
        isjson=False,
    )
    test_func = functools.partial(
        check_show_bgp_vpn_prefix_not_found,
        tgen.gears["r2"],
        "ipv4",
        "172.31.0.14/32",
        "444:1",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "network 172.31.0.14/32 should not present on r2"
    mpls_table_check(tgen.gears["r1"], blacklist=["192.0.2.14"])

    logger.info("Disabling redistribute connected and enabling redistribute static")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\n"
        "redistribute static\n no redistribute connected",
        isjson=False,
    )
    logger.info("Use network command for connect network 192.168.255.0/24 in vrf")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\n"
        "network 192.168.255.0/24\n",
        isjson=False,
    )
    logger.info("Checking BGP VPNv4 labels on r2")
    bgp_vpnv4_table_check(tgen.gears["r2"], group=["192.168.255.0/24"])
    logger.info("Checking no mpls entry associated to 192.168.255.0/24")
    mpls_table_check(tgen.gears["r1"], blacklist=["192.168.255.0"])
    logger.info("Checking 192.168.255.0/24 fallback to vrf")
    test_func = functools.partial(
        check_show_mpls_table_entry_label_found,
        tgen.gears["r1"],
        tgen.gears["r2"],
        "vrf1",
        network="192.168.255.0/24",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "192.168.255.0/24 does not fallback to vrf"

    logger.info(
        "Use network command for statically routed network 192.168.3.0/24 in vrf"
    )
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nvrf vrf1\n" "ip route 192.168.3.0/24 192.0.2.11\n"
    )
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\n"
        "network 192.168.3.0/24\n",
        isjson=False,
    )
    logger.info("Checking 192.168.3.0/24 route on r2")
    test_func = functools.partial(
        check_show_mpls_table_entry_label_found_nexthop,
        tgen.gears["r1"],
        tgen.gears["r2"],
        "192.168.3.0/24",
        "192.0.2.11",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=3)
    assert success, "label from r2 is not present on r1 for 192.168.3.0/24"

    # diagnostic
    logger.info("Dumping label nexthop table")
    tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf1 label-nexthop detail", isjson=False)
    logger.info("Dumping bgp network import-check-table")
    tgen.gears["r1"].vtysh_cmd(
        "show bgp vrf vrf1 import-check-table detail", isjson=False
    )

    logger.info("Restoring 172.31.0.14 prefix on r1")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\nnetwork 172.31.0.14/32\n",
        isjson=False,
    )
    logger.info("Restoring redistribute connected")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 65500 vrf vrf1\naddress-family ipv4 unicast\n"
        "no redistribute static\n redistribute connected",
        isjson=False,
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
