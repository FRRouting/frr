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

1. Verify upstream interfaces(IIF) and join state are updated
    properly after adding and deleting the static RP
2. Verify IIF and OIL in "show ipv6 PIM6 state" updated properly when
    RP becomes unreachable
3. Verify RP becomes reachable after MLD join received, PIM6 join
    towards RP is sent immediately
4. Verify (*,G) and (S,G) populated correctly when SPT and RPT
    share the same path
5. Verify OIF and RPF for (*,G) and (S,G) when static RP configure
    in LHR router
6. Verify OIF and RFP for (*,G) and (S,G) when static RP configure
    in FHR router
7. Verify (*,G) and (S,G) populated correctly when RPT and SPT path
    are different
8. Verify PIM6 join send towards the higher preferred RP
9. Verify PIM6 prune send towards the lower preferred RP
"""
import sys
import time

import pytest
from lib.common_config import (
    check_router_status,
    reset_config_on_routers,
    shutdown_bringup_interface,
    start_topology,
    step,
    write_test_footer,
    write_test_header,
)
from lib.pim import (
    McastTesterHelper,
    clear_pim6_interface_traffic,
    create_pim_config,
    get_pim6_interface_traffic,
    verify_join_state_and_timer,
    verify_mld_groups,
    verify_mroutes,
    verify_pim6_neighbors,
    verify_pim_interface_traffic,
    verify_pim_rp_info,
    verify_pim_state,
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
GROUP_RANGE_4 = "ff00::/8"
GROUP_ADDRESS_4 = "ff00::1"
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


def test_pim6_add_delete_static_RP_p0(request):
    """
    Verify upstream interfaces(IIF) and join state are updated
        properly after adding and deleting the static RP
    Verify IIF and OIL in "show ipv6 PIM6 state" updated properly when
        RP becomes unreachable
    Verify RP becomes reachable after MLD join received, PIM6 join
               towards RP is sent immediately

    TOPOlogy used:
         r0------r1-----r2
       iperf    DUT     RP
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Creating configuration from JSON")
    reset_config_on_routers(tgen)

    app_helper.stop_all_hosts()

    step("Shut link b/w R1 and R3 and R1 and R4 as per testcase topology")
    intf_r1_r3 = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    intf_r1_r4 = TOPO["routers"]["r1"]["links"]["r4"]["interface"]
    for intf in [intf_r1_r3, intf_r1_r4]:
        shutdown_bringup_interface(tgen, "r1", intf, ifaceaction=False)

    step("Enable PIM6 between r1 and r2")
    step(
        "Enable MLD on r1 interface and send MLD " "join {} to r1".format(GROUP_RANGE_1)
    )
    step("Configure r2 loopback interface as RP")
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
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify show ipv6 mld group without any MLD join")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, GROUP_ADDRESS_1, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: mld group present without any MLD join \n Error: {}".format(
            tc_name, result
        )
    )

    step("Verify show ipv6 PIM6 interface traffic without any mld join")
    state_dict = {
        "r1": {TOPO["routers"]["r1"]["links"]["r2"]["interface"]: ["pruneTx"]}
    }

    state_before = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("send mld join {} to R1".format(GROUP_ADDRESS_1))
    result = app_helper.run_join("r0", GROUP_ADDRESS_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    result = verify_mld_groups(tgen, dut, intf_r1_r0, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify RP info")
    dut = "r1"
    oif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    iif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    rp_address = TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(tgen, TOPO, dut, GROUP_RANGE_1, oif, rp_address, SOURCE)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, oif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, oif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify PIM6 state")
    result = verify_pim_state(tgen, dut, oif, iif, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, oif, iif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Delete RP configuration")
    input_dict = {
        "r2": {
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

    step("r1: Verify RP info")
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_1, oif, rp_address, SOURCE, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} :Failed \n " "RP: {} info is still present \n Error: {}".format(
        tc_name, rp_address, result
    )

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, oif, STAR, GROUP_ADDRESS_1, expected=False)
    assert result is not True, (
        "Testcase {} :Failed \n "
        "Upstream ({}, {}) is still in join state \n Error: {}".format(
            tc_name, STAR, GROUP_ADDRESS_1, result
        )
    )

    step("r1: Verify upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, oif, STAR, GROUP_ADDRESS_1, expected=False
    )
    assert result is not True, (
        "Testcase {} :Failed \n "
        "Upstream ({}, {}) timer is still running \n Error: {}".format(
            tc_name, STAR, GROUP_ADDRESS_1, result
        )
    )

    step("r1: Verify PIM6 state")
    result = verify_pim_state(tgen, dut, oif, iif, GROUP_ADDRESS_1, expected=False)
    assert result is not True, (
        "Testcase {} :Failed \n "
        "PIM state for group: {} is still Active \n Error: {}".format(
            tc_name, GROUP_ADDRESS_1, result
        )
    )

    step("r1: Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, oif, iif, expected=False)
    assert result is not True, (
        "Testcase {} :Failed \n "
        "mroute ({}, {}) is still present \n Error: {}".format(
            tc_name, STAR, GROUP_ADDRESS_1, result
        )
    )

    step("r1: Verify show ipv6 PIM6 interface traffic without any MLD join")
    state_after = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_SPT_RPT_path_same_p1(request):
    """
    Verify (*,G) and (S,G) populated correctly when SPT and RPT
        share the same path

    Topology used:
                ________r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1             r3-----r5

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

    step("Shut link b/w R1->R3, R1->R4 and R3->R1, R3->R4 as per " "testcase topology")
    intf_r1_r3 = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    intf_r1_r4 = TOPO["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r3_r1 = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    intf_r3_r4 = TOPO["routers"]["r3"]["links"]["r4"]["interface"]
    for intf in [intf_r1_r3, intf_r1_r4]:
        shutdown_bringup_interface(tgen, "r1", intf, ifaceaction=False)

    for intf in [intf_r3_r1, intf_r3_r4]:
        shutdown_bringup_interface(tgen, "r3", intf, ifaceaction=False)

    step("Enable the PIM6 on all the interfaces of r1, r2, r3 and r4 routers")
    step(
        "Configure RP on r2 (loopback interface) for the group range {}".format(
            GROUP_ADDRESS_1
        )
    )
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

    step(
        "Enable MLD on r1 interface and send MLD join {} to R1".format(GROUP_ADDRESS_1)
    )
    result = app_helper.run_join("r0", GROUP_ADDRESS_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("Send multicast traffic from R5")
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = app_helper.run_traffic("r5", GROUP_ADDRESS_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r2: Verify RP info")
    dut = "r2"
    oif = "lo"
    rp_address = TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(tgen, TOPO, dut, GROUP_RANGE_1, oif, rp_address, SOURCE)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r2"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S, G) upstream join state is up and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r2"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_RP_configured_as_LHR_p1(request):
    """
    Verify OIF and RPF for (*,G) and (S,G) when static RP configure
        in LHR router

    Topology used:
                ________r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5

    r1 : LHR/RP
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

    step("r1: Configure r1(LHR) as RP")
    input_dict = {
        "r1": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r1"]["links"]["lo"]["ipv6"].split(
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

    step("r1: Shut not Shut loopback interface")
    shutdown_bringup_interface(tgen, "r1", "lo", False)
    shutdown_bringup_interface(tgen, "r1", "lo", True)

    step("r1: Verify RP info")
    dut = "r1"
    iif = "lo"
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    rp_address = TOPO["routers"]["r1"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(tgen, TOPO, dut, GROUP_RANGE_1, iif, rp_address, SOURCE)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("send mld join {} to R1".format(GROUP_ADDRESS_1))
    result = app_helper.run_join("r0", GROUP_ADDRESS_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r5: Send multicast traffic for group {}".format(GROUP_ADDRESS_1))
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = app_helper.run_traffic("r5", GROUP_ADDRESS_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S, G) upstream join state is joined and join"
        " timer is running \n Error: {}".format(tc_name, result)
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_RP_configured_as_FHR_p1(request):
    """
    Verify OIF and RFP for (*,G) and (S,G) when static RP configure
        in FHR router

    Topology used:
                ________r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5

    r1 : LHR
    r3 : FHR/RP
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
    step("r3: Configure r3(FHR) as RP")
    input_dict = {
        "r3": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r3"]["links"]["lo"]["ipv6"].split(
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

    step("r1: Verify RP info")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    rp_address = TOPO["routers"]["r3"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(tgen, TOPO, dut, GROUP_RANGE_1, iif, rp_address, SOURCE)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("send mld join {} to R1".format(GROUP_ADDRESS_1))
    result = app_helper.run_join("r0", GROUP_ADDRESS_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r5: Send multicast traffic for group {}".format(GROUP_ADDRESS_1))
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = app_helper.run_traffic("r5", GROUP_ADDRESS_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_SPT_RPT_path_different_p1(request):
    """
    Verify (*,G) and (S,G) populated correctly when RPT and SPT path
        are different

    Topology used:
                ________r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5

    r1: LHR
    r2: RP
    r3: FHR
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

    step("r2: Verify RP info")
    dut = "r2"
    iif = "lo"
    rp_address = TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_ADDRESS_1, iif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("send mld join {} to R1".format(GROUP_ADDRESS_1))
    result = app_helper.run_join("r0", GROUP_ADDRESS_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r5: Send multicast traffic for group {}".format(GROUP_ADDRESS_1))
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = app_helper.run_traffic("r5", GROUP_ADDRESS_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    iif = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    SOURCE_ADDRESS = TOPO["routers"]["r5"]["links"]["r3"]["ipv6"].split("/")[0]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = TOPO["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = TOPO["routers"]["r3"]["links"]["r5"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    dut = "r2"
    iif = TOPO["routers"]["r2"]["links"]["r3"]["interface"]
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1, joinState="NotJoined"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_1, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_send_join_on_higher_preffered_rp_p1(request):
    """
    Verify PIM6 join send towards the higher preferred RP
    Verify PIM6 prune send towards the lower preferred RP

    Topology used:
                  _______r2
                 |
       iperf     |
         r0-----r1
                 |
                 |_______r4
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
    step("Enable the PIM66 on all the interfaces of r1, r2, r3 and r4 routers")
    step(
        "Configure RP on r2 (loopback interface) for the group range {}".format(
            GROUP_RANGE_4
        )
    )
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_4,
                    }
                ]
            }
        }
    }
    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r3 : Make all interface not reachable")
    intf_r3_r1 = TOPO["routers"]["r3"]["links"]["r1"]["interface"]
    intf_r3_r2 = TOPO["routers"]["r3"]["links"]["r2"]["interface"]
    intf_r3_r4 = TOPO["routers"]["r3"]["links"]["r4"]["interface"]
    intf_r1_r3 = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    intf_r2_r3 = TOPO["routers"]["r2"]["links"]["r3"]["interface"]
    intf_r4_r3 = TOPO["routers"]["r4"]["links"]["r3"]["interface"]

    for dut, intf in zip(["r1", "r2", "r3"], [intf_r1_r3, intf_r2_r3, intf_r4_r3]):
        shutdown_bringup_interface(tgen, dut, intf, ifaceaction=False)

    for intf in [intf_r3_r1, intf_r3_r4, intf_r3_r4]:
        shutdown_bringup_interface(tgen, "r3", intf, ifaceaction=False)

    step("Verify show ipv6 PIM6 interface traffic without any mld join")
    state_dict = {"r1": {TOPO["routers"]["r1"]["links"]["r4"]["interface"]: ["joinTx"]}}

    state_before = get_pim6_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("r0: send mld join {} to R1".format(GROUP_ADDRESS_3))
    result = app_helper.run_join("r0", GROUP_ADDRESS_3, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify MLD groups")
    dut = "r1"
    intf_r1_r0 = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mld_groups(tgen, dut, intf_r1_r0, GROUP_ADDRESS_3)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("Configure RP on r4 (loopback interface) for the group range " "ffaa::/128")
    input_dict = {
        "r4": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r4"]["links"]["lo"]["ipv6"].split(
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

    step("r1 : Verify RP info for group {}".format(GROUP_ADDRESS_4))
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    rp_address_1 = TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_ADDRESS_4, iif, rp_address_1, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1 : Verify RP info for group {}".format(GROUP_ADDRESS_3))
    dut = "r1"
    iif = TOPO["routers"]["r1"]["links"]["r4"]["interface"]
    rp_address_2 = TOPO["routers"]["r4"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_ADDRESS_3, iif, rp_address_2, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1 : Verify join is sent to higher preferred RP")
    step("r1 : Verify prune is sent to lower preferred RP")
    state_after = get_pim6_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("r1 : Verify ip mroutes")
    oif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_3, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1 : Verify PIM6 state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS_3)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1 : Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_3)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1 : Verify upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_3)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    clear_pim6_interface_traffic(tgen, TOPO)

    step("r1 : Verify joinTx, pruneTx count before RP gets deleted")
    state_dict = {
        "r1": {
            TOPO["routers"]["r1"]["links"]["r2"]["interface"]: ["joinTx"],
            TOPO["routers"]["r1"]["links"]["r4"]["interface"]: ["pruneTx"],
        }
    }
    state_before = get_pim6_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("r1 : Delete RP configuration for {}".format(GROUP_RANGE_3))
    input_dict = {
        "r4": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r4"]["links"]["lo"]["ipv6"].split(
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

    step("r1 : Verify rp-info for group {}".format(GROUP_RANGE_3))
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_3, iif, rp_address_1, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step("r1 : Verify rp-info for group {}".format(GROUP_RANGE_4))
    iif = TOPO["routers"]["r1"]["links"]["r4"]["interface"]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_4, oif, rp_address_2, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: rp-info is present for group {} \n Error: {}".format(
            tc_name, GROUP_RANGE_4, result
        )
    )

    step(
        "r1 : Verify RPF interface updated in mroute when higher preferred"
        "RP gets deleted"
    )
    iif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS_3, iif, oif)
    assert result is True, ASSERT_MSG.format(tc_name, result)
    logger.info("Expected behavior: %s", result)

    step(
        "r1 : Verify IIF and OIL in show ipv6 PIM6 state updated when higher"
        "preferred overlapping RP is deleted"
    )
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS_3)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "r1 : Verify upstream IIF updated when higher preferred overlapping"
        "RP deleted"
    )
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_3)
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "r1 : Verify upstream join state and join timer updated when higher"
        "preferred overlapping RP deleted"
    )
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS_3, addr_type="ipv6"
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "r1 : Verify join is sent to lower preferred RP, when higher"
        "preferred RP gets deleted"
    )
    step(
        "r1 : Verify prune is sent to higher preferred RP when higher"
        " preferred RP gets deleted"
    )
    state_after = get_pim6_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
