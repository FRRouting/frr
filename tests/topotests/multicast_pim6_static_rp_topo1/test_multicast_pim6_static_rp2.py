# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test Multicast basic functionality:

Topology:

                 _______r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5
                |             |
                |_____________|
                        r4

Test steps
- Create topology (setup module)
- Bring up topology

1. Configure multiple  groups (10 grps) with same RP address
2. Verify IIF and OIL in updated in mroute when upstream interface
   configure as RP
3. Verify RP info and (*,G) mroute after deleting the RP and shut /
    no shut the RPF interface.
"""

import os
import sys
import time

import pytest
from lib.common_config import (
    create_debug_log_config,
    reset_config_on_routers,
    shutdown_bringup_interface,
    start_topology,
    step,
    write_test_footer,
    write_test_header,
)
from lib.pim import (
    McastTesterHelper,
    create_pim_config,
    verify_join_state_and_timer,
    verify_mld_groups,
    verify_mroutes,
    verify_pim6_neighbors,
    verify_pim_rp_info,
    verify_upstream_iif,
)
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json, build_topo_from_json
from lib.topolog import logger

# Global variables
GROUP_RANGE_1 = "ff08::/64"
GROUP_ADDRESS_1 = "ff08::1"
GROUP_RANGE_3 = "ffaa::/64"
GROUP_ADDRESS_3 = "ffaa::1"
GROUP_RANGE_LIST_1 = [
    "ffaa::1/128",
    "ffaa::2/128",
    "ffaa::3/128",
    "ffaa::4/128",
    "ffaa::5/128",
]
GROUP_RANGE_LIST_2 = [
    "ffaa::6/128",
    "ffaa::7/128",
    "ffaa::8/128",
    "ffaa::9/128",
    "ffaa::10/128",
]
GROUP_ADDRESS_LIST_1 = ["ffaa::1", "ffaa::2", "ffaa::3", "ffaa::4", "ffaa::5"]
GROUP_ADDRESS_LIST_2 = ["ffaa::6", "ffaa::7", "ffaa::8", "ffaa::9", "ffaa::10"]
STAR = "*"
SOURCE = "Static"
ASSERT_MSG = "Testcase {} : Failed Error: {}"

pytestmark = [pytest.mark.pim6d]


def build_topo(tgen):
    """Build function"""

    # Building topology from json file
    build_topo_from_json(tgen, TOPO)


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: %s", testsuite_run_time)
    logger.info("=" * 40)

    topology = """

                 _______r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5
                |             |
                |_____________|
                        r4

    """
    logger.info("Master Topology: \n %s", topology)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "multicast_pim6_static_rp.json"
    tgen = Topogen(json_file, mod.__name__)
    global TOPO
    TOPO = tgen.json_topo

    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, TOPO)

    # Verify PIM6 neighbors
    result = verify_pim6_neighbors(tgen, TOPO)
    assert result is True, "setup_module :Failed \n Error:" " {}".format(result)

    global app_helper
    app_helper = McastTesterHelper(tgen)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")
    tgen = get_topogen()

    app_helper.cleanup()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info("Testsuite end time: %s", time.asctime(time.localtime(time.time())))
    logger.info("=" * 40)


#####################################################
#
#   Local API
#
#####################################################


def verify_state_incremented(state_before, state_after):
    """
    API to compare interface traffic state incrementing

    Parameters
    ----------
    * `state_before` : State dictionary for any particular instance
    * `state_after` : State dictionary for any particular instance
    """

    for router, state_data in state_before.items():
        for state, value in state_data.items():
            if state_before[router][state] >= state_after[router][state]:
                errormsg = (
                    "[DUT: %s]: state %s value has not"
                    " incremented, Initial value: %s, "
                    "Current value: %s [FAILED!!]"
                    % (
                        router,
                        state,
                        state_before[router][state],
                        state_after[router][state],
                    )
                )
                return errormsg

            logger.info(
                "[DUT: %s]: State %s value is "
                "incremented, Initial value: %s, Current value: %s"
                " [PASSED!!]",
                router,
                state,
                state_before[router][state],
                state_after[router][state],
            )

    return True


#####################################################
#
#   Testcases
#
#####################################################


def test_pim6_multiple_groups_same_RP_address_p2(request):
    """
    Configure multiple  groups (10 grps) with same RP address

    Topology used:
                ________r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5

    r1 : LHR
    r2 : RP
    r3 : FHR
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Creating configuration from JSON")
    reset_config_on_routers(tgen)

    app_helper.stop_all_hosts()

    input_dict = {
        "r1": {"debug": {"log_file": "r1_debug.log", "enable": ["pim6d"]}},
        "r2": {"debug": {"log_file": "r2_debug.log", "enable": ["pim6d"]}},
        "r3": {"debug": {"log_file": "r3_debug.log", "enable": ["pim6d"]}},
        "r4": {"debug": {"log_file": "r4_debug.log", "enable": ["pim6d"]}},
    }

    result = create_debug_log_config(tgen, input_dict)

    step("Enable MLD on r1 interface")
    step("Enable the PIM6 on all the interfaces of r1, r2, r3 and r4 routers")
    step("r2: Configure r2 as RP")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r2: verify rp-info")
    dut = "r2"
    oif = "lo"
    rp_address = TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(tgen, TOPO, dut, GROUP_RANGE_3, oif, rp_address, SOURCE)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    group_address_list = GROUP_ADDRESS_LIST_1 + GROUP_ADDRESS_LIST_2
    step("r0: Send MLD join for 10 groups")
    intf = TOPO["routers"]["r0"]["links"]["r1"]["interface"]
    result = app_helper.run_join("r0", group_address_list, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r5: Send multicast traffic for group {}".format(group_address_list))
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = app_helper.run_traffic("r5", group_address_list, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, STAR, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, group_address_list, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, group_address_list, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        group_address_list,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    dut = "r2"
    iif = TOPO["routers"]["r2"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, joinState="NotJoined"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        group_address_list,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Delete RP configuration")
    input_dict = {
        "r1": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r1: Shut the interface r1-r2-eth1 from R1 to R2")
    dut = "r1"
    intf = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No Shut the interface r1-r2-eth1 from R1 to R2")
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Configure RP")
    input_dict = {
        "r1": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r1: Shut the interface r1-r0-eth0 from R1 to R2")
    intf = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No Shut the interface r1-r0-eth0 from R1 to R2")
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, STAR, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, group_address_list, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, group_address_list, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        group_address_list,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_multiple_groups_different_RP_address_p2(request):
    """
    Verify IIF and OIL in updated in mroute when upstream interface
    configure as RP

    Topology used:
                ________r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5
                |             |
                |_____________|
                        r4
    r1 : LHR
    r2 & r4 : RP
    r3 : FHR
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Creating configuration from JSON")
    reset_config_on_routers(tgen)

    app_helper.stop_all_hosts()

    step("Enable MLD on r1 interface")
    step("Enable the PIM6 on all the interfaces of r1, r2, r3 and r4 routers")
    step("r2: Configure r2 as RP")
    step("r4: Configure r4 as RP")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_LIST_1,
                    }
                ]
            }
        },
        "r4": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r4"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_LIST_2,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r2: Verify RP info")
    dut = "r2"
    oif = "lo"
    rp_address = TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_LIST_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify RP info")
    dut = "r4"
    rp_address = TOPO["routers"]["r4"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_LIST_2, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    group_address_list = GROUP_ADDRESS_LIST_1 + GROUP_ADDRESS_LIST_2
    step("r0: Send MLD join for 10 groups")
    result = app_helper.run_join("r0", group_address_list, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, group_address_list)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r5: Send multicast traffic for group {}".format(group_address_list))
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = app_helper.run_traffic("r5", group_address_list, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif1 = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    iif2 = TOPO["routers"]["r1"]["links"]["r4"]["interface"]

    for _iif, _group in zip([iif1, iif2], [GROUP_ADDRESS_LIST_1, GROUP_ADDRESS_LIST_2]):
        result = verify_upstream_iif(tgen, dut, _iif, STAR, _group)
        assert result is True, ASSERT_MSG.format(tc_name, result)

        step("r1: Verify (*, G) upstream join state and join timer")
        result = verify_join_state_and_timer(
            tgen, dut, _iif, STAR, _group, addr_type="ipv6"
        )
        assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r2"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, joinState="NotJoined"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        GROUP_ADDRESS_LIST_1,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        GROUP_ADDRESS_LIST_1,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r4"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (*, G) upstream IIF interface")
    dut = "r4"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r4"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r4"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, joinState="NotJoined"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        GROUP_ADDRESS_LIST_2,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r4: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r4: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        GROUP_ADDRESS_LIST_2,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, result
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("Delete RP configuration")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_LIST_1,
                        "delete": True,
                    }
                ]
            }
        },
        "r4": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r4"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_LIST_2,
                        "delete": True,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r1, r2, r3, r4: Re-configure RP")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_LIST_1,
                    }
                ]
            }
        },
        "r4": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r4"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_LIST_2,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r1: Shut/No Shut the interfacesfrom R1 to R2, R4 and R0")
    dut = "r1"
    intf1 = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    intf2 = TOPO["routers"]["r1"]["links"]["r4"]["interface"]
    intf3 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    for intf in [intf1, intf2, intf3]:
        shutdown_bringup_interface(tgen, dut, intf, False)
        shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r2"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, joinState="NotJoined"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        GROUP_ADDRESS_LIST_1,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        GROUP_ADDRESS_LIST_1,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r4"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (*, G) upstream IIF interface")
    dut = "r4"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r4"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r4"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, joinState="NotJoined"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r4: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        GROUP_ADDRESS_LIST_2,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r4: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r4: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen,
        dut,
        iif,
        SOURCE_ADDRESS,
        GROUP_ADDRESS_LIST_2,
        addr_type="ipv6",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_delete_RP_shut_noshut_upstream_interface_p1(request):
    """
    Verify RP info and (*,G) mroute after deleting the RP and shut /
    no shut the RPF interface.

    Topology used:
                ________r2_____
                |             |
      iperf     |             |
        r0-----r1-------------r3
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Creating configuration from JSON")
    reset_config_on_routers(tgen)

    app_helper.stop_all_hosts()

    step("Enable MLD on r1 interface")
    step("Enable the PIM6 on all the interfaces of r1, r2, r3 and r4 routers")
    step("r2: Configure r2 as RP")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r2: verify rp-info")
    dut = "r2"
    oif = "lo"
    rp_address = TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_ADDRESS_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r0: Send MLD join")
    result = app_helper.run_join("r0", GROUP_ADDRESS_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes created")
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes created")
    dut = "r2"
    iif = "lo"
    oif = TOPO["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Delete RP configuration")
    input_dict = {
        "r1": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r1: Shut/No Shut the interface r1-r2-eth1/r1-r0-eth0 from R1 to R2")
    dut = "r1"
    intf1 = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    intf2 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    for intf in [intf1, intf2]:
        shutdown_bringup_interface(tgen, dut, intf, False)
        shutdown_bringup_interface(tgen, dut, intf, True)

    step("r2: Shut the RP interface lo")
    dut = "r2"
    intf = "lo"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: Shut the interface r1-r2-eth1/r1-r3-eth2 towards RP")
    intf3 = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    for intf in [intf1, intf3]:
        shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: Verify (*, G) ip mroutes cleared")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: (*,G) mroutes are not cleared after shut of R1 to R0 link\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (*, G) ip mroutes cleared")
    dut = "r2"
    iif = "lo"
    oif = TOPO["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (*,G) mroutes are not cleared after shut of R1 to R0 link\n Error: {}".format(
            tc_name, result
        )
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
