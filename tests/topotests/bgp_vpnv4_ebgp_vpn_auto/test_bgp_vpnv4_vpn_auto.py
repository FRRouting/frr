#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_vpnv4_vpn_auto.py
#
# Copyright (c) 2024 by Varun Hegde
#

"""
 test_bgp_vpnv4_vpn_auto.py: Test the FRR BGP daemon with BGP VPN session with label export auto
"""

import os
import sys
import json
import functools
import pytest

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

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 3 routers.
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")


    for i in range(6):
        switch = tgen.add_switch("s{0}".format(i))
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

    #create a singiluar link between R2 -- R3
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    for i in range(7, 9):
        switch = tgen.add_switch("s{0}".format(i))
        switch.add_link(tgen.gears["r3"])



def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "ip link add vrf{} type vrf table {}",
        "ip link set dev vrf{} up",
        "ip link set dev r1-eth{} master vrf{}",
        "echo 1 > /proc/sys/net/mpls/conf/r1-eth{}/input",
    ]
    cmds_list2 = [
        "ip link add vrf{} type vrf table {}",
        "ip link set dev vrf{} up",
        "ip link set dev r2-eth{} master vrf{}",
        "echo 1 > /proc/sys/net/mpls/conf/r2-eth{}/input",
    ]

    for i in range(1, 6):
        for cmd in cmds_list:
            input = cmd.format(i, i)
            logger.info("input: " + cmd)
            output = tgen.net["r1"].cmd(cmd.format(i, i))
            logger.info("output: " + output)

        for cmd in cmds_list2:
            input = cmd.format(i, i)
            logger.info("input: " + cmd)
            output = tgen.net["r2"].cmd(cmd.format(i, i))
            logger.info("output: " + output)

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def test_labelpool_release():
    """
    Check that once we remove BGP VPN sesson
    label pool structure ( allocated_map ) gets released properly or not
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Just waiting for BGP VPN session to converge
    logger.info("Waiting for BGP VPN sessions to converge and label pools to get initialised")
    router = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(
            router.vtysh_cmd("show bgp labelpool summary json")
        )
        expected = {"ledger":5,"inUse":5,"requests":0,"labelChunks":1,"pending":0,"reconnects":1}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to see BGP Labelpool initialised"


    # checking the initial label pool chunk's free labels
    logger.info("checking the initial label pool chunk's free labels")
    expected = [{"first":80,"last":207,"size":128,"numberFree":123}]
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp label chunks json",
        expected,
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


    # Test case : check whether label got released or not
    logger.info(
        "Remove multiple vpn session and check whether label got released or no"
    )
    router.vtysh_cmd(
        """
        configure terminal
        no router bgp 65500 vrf vrf1
        no router bgp 65500 vrf vrf2
        """
    )
    expected = [{"first":80,"last":207,"size":128,"numberFree":125}]
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp label chunks json",
        expected,
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg



def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
