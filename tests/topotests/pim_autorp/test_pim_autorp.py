#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_autorp.py
#
# Copyright (c) 2024 ATCorp
# Nathan Bahr
#

import os
import sys
import pytest
from functools import partial

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.pim import (
    scapy_send_autorp_raw_packet,
    verify_pim_rp_info,
    verify_pim_rp_info_is_empty,
)
from lib.common_config import step, write_test_header

from time import sleep

"""
test_pim_autorp.py: Test general PIM AutoRP functionality
"""

TOPOLOGY = """
   Basic AutoRP functionality

    +---+---+                      +---+---+
    |       |    10.10.76.0/24     |       |
    +  R1   + <------------------> +  R2   |
    |       | .1                .2 |       |
    +---+---+                      +---+---+
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.pimd]


def build_topo(tgen):
    "Build function"

    # Create routers
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Create link between router 1 and 2
    switch = tgen.add_switch("s1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    logger.info("PIM AutoRP basic functionality:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Router 1 will be the router configured with "fake" autorp configuration, so give it a default route
    # to router 2 so that routing to the RP address is not an issue
    # r1_defrt_setup_cmds = [
    #     "ip route add default via 10.10.76.1 dev r1-eth0",
    # ]
    # for cmd in r1_defrt_setup_cmds:
    #     tgen.net["r1"].cmd(cmd)

    logger.info("Testing PIM AutoRP support")
    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_pim_autorp_discovery_single_rp(request):
    "Test PIM AutoRP Discovery with single RP"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Start with no RP configuration")
    result = verify_pim_rp_info_is_empty(tgen, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Send AutoRP packet from r1 to r2")
    # 1 RP(s), hold time 5 secs, 10.10.76.1, group(s) 224.0.0.0/4
    data = "01005e00012800127f55cfb1080045c00030700c000008110abe0a0a4c01e000012801f001f0001c798b12010005000000000a0a4c0103010004e0000000"
    scapy_send_autorp_raw_packet(tgen, "r1", "r1-eth0", data)

    step("Verify rp-info from AutoRP packet")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r2",
        "224.0.0.0/4",
        "r2-eth0",
        "10.10.76.1",
        "AutoRP",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify AutoRP configuration times out")
    result = verify_pim_rp_info_is_empty(tgen, "r2")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_autorp_discovery_multiple_rp(request):
    "Test PIM AutoRP Discovery with multiple RP's"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    step("Start with no RP configuration")
    result = verify_pim_rp_info_is_empty(tgen, "r2")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Send AutoRP packet from r1 to r2")
    # 2 RP(s), hold time 5 secs, 10.10.76.1, group(s) 224.0.0.0/8, 10.10.76.3, group(s) 225.0.0.0/8
    data = "01005e00012800127f55cfb1080045c0003c700c000008110ab20a0a4c01e000012801f001f000283f5712020005000000000a0a4c0103010008e00000000a0a4c0303010008e1000000"
    scapy_send_autorp_raw_packet(tgen, "r1", "r1-eth0", data)

    step("Verify rp-info from AutoRP packet")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r2",
        "224.0.0.0/8",
        "r2-eth0",
        "10.10.76.1",
        "AutoRP",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    result = verify_pim_rp_info(
        tgen,
        None,
        "r2",
        "225.0.0.0/8",
        "r2-eth0",
        "10.10.76.3",
        "AutoRP",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_autorp_discovery_static(request):
    "Test PIM AutoRP Discovery with Static RP"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    step("Start with no RP configuration")
    result = verify_pim_rp_info_is_empty(tgen, "r2")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Add static RP configuration to r2")
    rnode = tgen.routers()["r2"]
    rnode.cmd("vtysh -c 'conf t' -c 'router pim' -c 'rp 10.10.76.3 224.0.0.0/4'")

    step("Verify static rp-info from r2")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r2",
        "224.0.0.0/4",
        "r2-eth0",
        "10.10.76.3",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Send AutoRP packet from r1 to r2")
    # 1 RP(s), hold time 5 secs, 10.10.76.1, group(s) 224.0.0.0/4
    data = "01005e00012800127f55cfb1080045c00030700c000008110abe0a0a4c01e000012801f001f0001c798b12010005000000000a0a4c0103010004e0000000"
    scapy_send_autorp_raw_packet(tgen, "r1", "r1-eth0", data)

    step("Verify rp-info from AutoRP packet")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r2",
        "224.0.0.0/4",
        "r2-eth0",
        "10.10.76.1",
        "AutoRP",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_autorp_announce_cli(request):
    "Test PIM AutoRP Announcement CLI commands"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    step("Add AutoRP announcement configuration to r1")
    r1 = tgen.routers()["r1"]
    r1.vtysh_cmd(
        """
        conf
         router pim
          autorp announce holdtime 90
          autorp announce interval 120
          autorp announce scope 5
          autorp announce 10.2.3.4 225.0.0.0/24
"""
    )

    expected = {
        "discoveryEnabled": True,
        "announce": {
            "scope": 5,
            "interval": 120,
            "holdtime": 90,
            "rpList": [
                {"rpAddress": "10.2.3.4", "group": "225.0.0.0/24", "prefixList": ""}
            ],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim autorp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg

    r1.vtysh_cmd(
        """
        conf
         router pim
          autorp announce 10.2.3.4 group-list ListA
"""
    )
    expected = {
        "discoveryEnabled": True,
        "announce": {
            "scope": 5,
            "interval": 120,
            "holdtime": 90,
            "rpList": [{"rpAddress": "10.2.3.4", "group": "", "prefixList": "ListA"}],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim autorp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg


def test_pim_autorp_announce_group(request):
    "Test PIM AutoRP Announcement with a single group"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    step("Add candidate RP configuration to r1")
    rnode = tgen.routers()["r1"]
    rnode.cmd(
        "vtysh -c 'conf t' -c 'router pim' -c 'send-rp-announce 10.10.76.1 224.0.0.0/4'"
    )
    step("Verify Announcement sent data")
    # TODO: Verify AutoRP mapping agent receives candidate RP announcement
    # Mapping agent is not yet implemented
    # sleep(10)
    step("Change AutoRP Announcement packet parameters")
    rnode.cmd(
        "vtysh -c 'conf t' -c 'router pim' -c 'send-rp-announce scope 8 interval 10 holdtime 60'"
    )
    step("Verify Announcement sent data")
    # TODO: Verify AutoRP mapping agent receives updated candidate RP announcement
    # Mapping agent is not yet implemented
    # sleep(10)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
