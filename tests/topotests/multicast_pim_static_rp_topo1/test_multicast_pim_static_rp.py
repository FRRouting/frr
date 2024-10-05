#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
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

TC_1 : Verify upstream interfaces(IIF) and join state are updated properly
       after adding and deleting the static RP
TC_2 : Verify IIF and OIL in "show ip pim state" updated properly after
       adding and deleting the static RP
TC_3: (*, G) Mroute entry are cleared when static RP gets deleted
TC_4: Verify (*,G) prune is send towards the RP after deleting the static RP
TC_5: Verify OIF entry for RP is cleared when RP becomes unreachable
TC_6: Verify IIF and OIL in "show ip pim state" updated properly when RP
      becomes unreachable
TC_7 : Verify upstream interfaces(IIF) and join state are updated properly
       after adding and deleting the static RP
TC_8: Verify (*,G) prune is send towards the RP when RP becomes unreachable
TC_9 : Verify RP configured after IGMP join received, PIM join towards RP is
       sent immediately
TC_10 : Verify RP becomes reachable after IGMP join received, PIM join
        towards RP is sent immediately
TC_11 : Verify PIM join send towards the higher preferred RP
TC_12 : Verify PIM prune send towards the lower preferred RP
TC_13 : Verify RPF interface is updated in mroute (kernel) when higher
        preferred overlapping RP configured
TC_14 : Verify IIF and OIL in "show ip pim state" updated properly when higher
        preferred overlapping RP configured
TC_15 : Verify upstream interfaces(IIF) and join state are updated when higher
        preferred overlapping RP is configured
TC_16 : Verify join is send to lower preferred RP, when higher preferred RP
        gets deleted
TC_17 : Verify prune is send to higher preferred RP when higher preferred RP
        gets deleted
TC_18 : Verify RPF interface updated in mroute when higher preferred RP gets
        deleted
TC_19 : Verify IIF and OIL in "show ip pim state" updated when higher
        preferred overlapping RP is deleted
TC_20 : Verify PIM upstream IIF updated when higher preferred overlapping RP
        deleted
TC_21_1 : Verify OIF and RFP for (*,G) and (S,G) when static RP configure in
          LHR router
TC_21_2 : Verify OIF and RFP for (*,G) and (S,G) when static RP configure in
          LHR router
TC_22_1 : Verify OIF and RPF for (*,G) and (S,G) when static RP configure in
          FHR router
TC_22_2 : Verify OIF and RPF for (*,G) and (S,G) when static RP configure in
          FHR router
TC_23 : Verify (*,G) and (S,G) populated correctly when RPT and SPT path are
        different
TC_24 : Verify (*,G) and (S,G) populated correctly when SPT and RPT share the
        same path
TC_25 : Verify (*,G) and (S,G) populated correctly after clearing the PIM ,
        IGMP and mroutes joins
TC_26 : Restart the PIMd process and verify PIM joins , and mroutes entries
TC_27 : Configure multiple  groups (10 grps) with same RP address
TC_28 : Configure multiple  groups (10 grps) with different RP address
TC_29 : Verify IIF and OIL in updated in mroute when upstream interface
        configure as RP
TC_30 : Verify IIF and OIL change to other path after shut the primary path
TC_31 : Verify RP info and (*,G) mroute after deleting the RP and shut / no
        shut the RPF interface.
TC_32 : Verify RP info and (*,G) mroute after deleting the RP and shut / no
        shut the RPF interface
"""

import os
import sys
import time
import datetime
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json

from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    step,
    shutdown_bringup_interface,
    create_static_routes,
)
from lib.pim import (
    create_pim_config,
    verify_igmp_groups,
    verify_upstream_iif,
    verify_join_state_and_timer,
    verify_mroutes,
    verify_pim_neighbors,
    get_pim_interface_traffic,
    verify_pim_rp_info,
    verify_pim_state,
    clear_pim_interface_traffic,
    clear_mroute,
    McastTesterHelper,
)

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]


# Global variables
GROUP_RANGE_ALL = "224.0.0.0/4"
GROUP_RANGE = "225.1.1.1/32"
GROUP_RANGE_LIST_1 = [
    "225.1.1.1/32",
    "225.1.1.2/32",
    "225.1.1.3/32",
    "225.1.1.4/32",
    "225.1.1.5/32",
]
GROUP_RANGE_LIST_2 = [
    "225.1.1.6/32",
    "225.1.1.7/32",
    "225.1.1.8/32",
    "225.1.1.9/32",
    "225.1.1.10/32",
]
GROUP_ADDRESS = "225.1.1.1"
GROUP_ADDRESS_LIST_1 = ["225.1.1.1", "225.1.1.2", "225.1.1.3", "225.1.1.4", "225.1.1.5"]
GROUP_ADDRESS_LIST_2 = [
    "225.1.1.6",
    "225.1.1.7",
    "225.1.1.8",
    "225.1.1.9",
    "225.1.1.10",
]
STAR = "*"
SOURCE_ADDRESS = "10.0.6.2"
SOURCE = "Static"


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
    json_file = "{}/multicast_pim_static_rp.json".format(CWD)
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

    # Verify PIM neighbors
    result = verify_pim_neighbors(tgen, TOPO)
    assert result is True, "setup_module :Failed \n Error:" " {}".format(result)

    # XXX Replace this using "with McastTesterHelper()... " in each test if possible.
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
#   Testcases
#
#####################################################


def verify_mroute_repopulated(uptime_before, uptime_after):
    """
    API to compare uptime for mroutes

    Parameters
    ----------
    * `uptime_before` : Uptime dictionary for any particular instance
    * `uptime_after` : Uptime dictionary for any particular instance
    """

    for group in uptime_before.keys():
        for source in uptime_before[group].keys():
            if set(uptime_before[group]) != set(uptime_after[group]):
                errormsg = (
                    "mroute (%s, %s) has not come"
                    " up after mroute clear [FAILED!!]" % (source, group)
                )
                return errormsg

            d_1 = datetime.datetime.strptime(uptime_before[group][source], "%H:%M:%S")
            d_2 = datetime.datetime.strptime(uptime_after[group][source], "%H:%M:%S")
            if d_2 >= d_1:
                errormsg = "mroute (%s, %s) is not " "repopulated [FAILED!!]" % (
                    source,
                    group,
                )
                return errormsg

            logger.info("mroute (%s, %s) is " "repopulated [PASSED!!]", source, group)

    return True


def verify_state_incremented(state_before, state_after):
    """
    API to compare interface traffic state incrementing

    Parameters
    ----------
    * `state_before` : State dictionary for any particular instance
    * `state_after` : State dictionary for any particular instance
    """

    for router, state_data in state_before.items():
        for state, _ in state_data.items():
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


def test_add_delete_static_RP_p0(request):
    """
    TC_1_P0 : Verify upstream interfaces(IIF) and join state are updated
              properly after adding and deleting the static RP
    TC_2_P0 : Verify IIF and OIL in "show ip pim state" updated properly
              after adding and deleting the static RP
    TC_3_P0: (*, G) Mroute entry are cleared when static RP gets deleted
    TC_4_P0: Verify (*,G) prune is send towards the RP after deleting the
             static RP

    Topology used:
         r0------r1-----r2
       iperf    DUT     RP
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("pre-configuration to send IGMP join and multicast traffic")

    step("Enable IGMP on r1 interface and send IGMP " "join (225.1.1.1) to r1")
    step("Configure r2 loopback interface as RP")
    step("Enable PIM between r1 and r3")

    step("r1: Verify show ip igmp group without any IGMP join")
    dut = "r1"
    interface = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, interface, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: IGMP groups should not be present without any IGMP join\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: Verify show ip pim interface traffic without any IGMP join")
    state_dict = {"r1": {"r1-r2-eth1": ["pruneTx"]}}

    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase {} : Failed \n state_before is not dictionary\n Error: {}".format(
        tc_name, result
    )

    step("r0 : Send IGMP join")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups")
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify RP info")
    dut = "r1"
    iif = "r1-r2-eth1"
    rp_address = "1.0.2.17"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    step("r1: Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify ip pim join")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    step("r1: Delete RP configuration")

    # Delete RP configuration
    input_dict = {
        "r1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify RP info")
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: RP info should not be present \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream IIF interface {} should not be present\n "
        "Found: {}".format(tc_name, dut, iif, result)
    )

    step("r1: Verify upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream Join State timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    # 20
    step("r1: Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: PIM state should not be up \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (*, G) should not be present \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: Verify show ip pim interface traffic without any IGMP join")
    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_SPT_RPT_path_same_p1(request):
    """
    TC_24_P1 : Verify (*,G) and (S,G) populated correctly when SPT and RPT
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    dut = "r1"
    intf = "r1-r3-eth2"
    shutdown_bringup_interface(tgen, dut, intf, False)
    intf = "r1-r4-eth3"
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r3"
    intf = "r3-r1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)
    intf = "r3-r4-eth2"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("Enable IGMP on r1 interface and send IGMP join (225.1.1.1) to R1")
    step("Configure RP on r2 (loopback interface) for the group range" " 224.0.0.0/4")
    step("Enable the PIM on all the interfaces of r1, r2, r3 and r4 routers")
    step("Send multicast traffic from R3")

    step("r2: Verify RP info")
    dut = "r2"
    rp_address = "1.0.2.17"
    iif = "lo"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r0: Send IGMP join")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups")
    dut = "r1"
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r5: Send multicast traffic for group 225.1.1.1")
    result = app_helper.run_traffic("r5", GROUP_ADDRESS, "r3")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = "r1-r2-eth1"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r2-eth1"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = "r2-r1-eth0"
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    iif = "r2-r3-eth1"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) ip mroutes")
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = "r3-r5-eth3"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream Join State timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r2-eth1"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_not_reachable_static_RP_p0(request):
    """
    TC_5_P0: Verify OIF entry for RP is cleared when RP becomes unreachable
    TC_6_P0: Verify IIF and OIL in "show ip pim state" updated properly when
             RP becomes unreachable
    TC_7_P0 : Verify upstream interfaces(IIF) and join state are updated
              properly after adding and deleting the static RP
    TC_8_P0: Verify (*,G) prune is send towards the RP when RP becomes
             unreachable

    Topology used:
         r0------r1-----r2
       iperf    DUT     RP
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    dut = "r1"
    intf = "r1-r3-eth2"
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r1"
    intf = "r1-r4-eth3"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "r1: (*,G) prune is not sent towards the RP interface, verify using"
        "show ip pim interface traffic"
    )
    state_dict = {"r1": {"r1-r2-eth1": ["pruneTx"]}}
    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, state_before
    )

    step("Enable IGMP on r1 interface and send IGMP " "join (225.1.1.1) to r1")
    step("Configure r2 loopback interface as RP")
    step("Enable PIM between r1 and r2")

    step("r0 : Send IGMP join")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify rp info")
    dut = "r1"
    iif = "r1-r2-eth1"
    rp_address = "1.0.2.17"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups")
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 :Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Make RP un-reachable")
    dut = "r1"
    input_dict = {
        dut: {
            "static_routes": [
                {"network": "1.0.2.17/32", "next_hop": "10.0.1.2", "delete": True}
            ]
        }
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("r1: Check RP detail using show ip pim rp-info OIF should be unknown")
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, "Unknown", rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "r1 : OIL should be same and IIF should be cleared on R1 verify"
        "using show ip pim state"
    )
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: OIL should be same and IIF should be cleared\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: upstream IIF should be unknown , verify using show ip pim" "upstream")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream IIF interface {} should be unknown \n "
        "Found: {}".format(tc_name, dut, iif, result)
    )

    step(
        "r1: join state should not be joined and join timer should stop,"
        "verify using show ip pim upstream"
    )
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream Join State timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step(
        "r1: (*,G) prune is sent towards the RP interface, verify using"
        "show ip pim interface traffic"
    )
    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("r1: (*, G) cleared from mroute table using show ip mroute")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (*, G) should be cleared from mroute table\n "
        "Found: {}".format(tc_name, dut, result)
    )

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_add_RP_after_join_received_p1(request):
    """
    TC_9_P1 : Verify RP configured after IGMP join received, PIM join towards
              RP is sent immediately

    Topology used:
         r0------r1-----r2
       iperf    DUT     RP
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on R1 interface")
    step("Configure r2 loopback interface as RP")
    step("Enable PIM between r1 and r2")
    step("Delete RP configuration from r1")

    step("r1: Delete RP configuration")
    input_dict = {
        "r1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify rp-info")
    dut = "r1"
    rp_address = "1.0.2.17"
    iif = "r1-r2-eth1"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: RP-info should not be present \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("joinTx value before join sent")
    state_dict = {"r1": {"r1-r2-eth1": ["joinTx"]}}
    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("r0 : Send IGMP join (225.1.1.1) to r1, when rp is not configured" "in r1")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: IGMP group is received on R1 verify using show ip igmp groups")
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream IIF interface {} should not be present \n "
        "Found: {}".format(tc_name, dut, iif, result)
    )

    step("r1: Verify upstream join state and join timer")

    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream Join State timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: PIM state should not be up\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (*, G) should not be present in mroute table \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: Configure static RP")
    input_dict = {
        "r1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify rp-info")
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    logger.info("Expected behavior: %s", result)

    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_reachable_static_RP_after_join_p0(request):
    """
    TC_10_P0 : Verify RP becomes reachable after IGMP join received, PIM join
               towards RP is sent immediately

    Topology used:
         r0------r1-----r3
       iperf    DUT     RP
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface and send IGMP " "join (225.1.1.1) to r1")
    step("Configure r2 loopback interface as RP")
    step("Enable PIM between r1 and r2")

    step("r1 : Verify pim interface traffic")
    state_dict = {"r1": {"r1-r2-eth1": ["joinTx"]}}
    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, state_before
    )

    step("r1: Make RP un-reachable")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)
    intf = "r1-r3-eth2"
    shutdown_bringup_interface(tgen, dut, intf, False)
    intf = "r1-r4-eth3"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: Verify rp-info")
    rp_address = "1.0.2.17"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_ADDRESS, "Unknown", rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Send IGMP join for 225.1.1.1")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify IGMP groups")
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify upstream IIF interface")
    iif = "r1-r2-eth1"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream IIF interface {} should not be present \n "
        "Found: {}".format(tc_name, dut, iif, result)
    )

    step("r1 : Verify upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream Join State timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1 : Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: PIM state should not be up \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1 : Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (*, G) should not be present \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r1: Make RP reachable")
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, True)
    intf = "r1-r3-eth2"
    shutdown_bringup_interface(tgen, dut, intf, True)
    intf = "r1-r4-eth3"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1 : Verify rp-info")
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    logger.info("Expected behavior: %s", result)

    step("r1 : Verify pim interface traffic")
    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_send_join_on_higher_preffered_rp_p1(request):
    """
     TC_11_P1 : Verify PIM join send towards the higher preferred RP
     TC_12_P1 : Verify PIM prune send towards the lower preferred RP
     TC_13_P1 : Verify RPF interface is updated in mroute (kernel) when higher
                preferred overlapping RP configured
     TC_14_P1 : Verify IIF and OIL in "show ip pim state" updated properly when
                higher preferred overlapping RP configured
     TC_15_P1 : Verify upstream interfaces(IIF) and join state are updated when
                higher preferred overlapping RP is configured
     TC_16_P1 : Verify join is send to lower preferred RP, when higher
                preferred RP gets deleted
     TC_17_P1 : Verify prune is send to higher preferred RP when higher
                preferred RP gets deleted
     TC_18_P1 : Verify RPF interface updated in mroute when higher preferred RP
                gets deleted
     TC_19_P1 : Verify IIF and OIL in "show ip pim state" updated when higher
                preferred overlapping RP is deleted
     TC_20_P1 : Verify PIM upstream IIF updated when higher preferred
                overlapping RP deleted

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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface")
    step("Configure RP on r2 (loopback interface) for the group range " "224.0.0.0/4")
    step("Configure RP on r4 (loopback interface) for the group range " "225.1.1.1/32")

    step("r3 : Make all interface not reachable")
    dut = "r3"
    intf = "r3-r1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)
    intf = "r3-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)
    intf = "r3-r4-eth2"
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    intf = "r2-r3-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r4"
    intf = "r4-r3-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r1"
    intf = "r1-r3-eth2"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1 : Verify joinTx count before sending join")
    state_dict = {"r1": {"r1-r4-eth3": ["joinTx"], "r1-r2-eth1": ["pruneTx"]}}

    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, state_before
    )

    step("r0 : Send IGMP join for 225.1.1.1")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify IGMP groups")
    dut = "r1"
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure static RP for group 225.1.1.1/32")
    input_dict = {
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.4.17",
                        "group_addr_range": ["225.1.1.1/32"],
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify RP info for group 224.0.0.0/4")
    rp_address_1 = "1.0.2.17"
    iif = "r1-r2-eth1"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address_1, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify RP info for group 225.1.1.1")
    rp_address_2 = "1.0.4.17"
    iif = "r1-r4-eth3"
    result = verify_pim_rp_info(tgen, TOPO, dut, GROUP_RANGE, iif, rp_address_2, SOURCE)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify join is sent to higher preferred RP")
    step("r1 : Verify prune is sent to lower preferred RP")
    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("r1 : Verify ip mroutes")
    iif = "r1-r4-eth3"
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    clear_pim_interface_traffic(tgen, TOPO)

    step("r1 : Verify joinTx, pruneTx count before RP gets deleted")
    state_dict = {"r1": {"r1-r2-eth1": ["joinTx"], "r1-r4-eth3": ["pruneTx"]}}

    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("r1 : Delete RP configuration for 225.1.1.1")
    input_dict = {
        "r1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.4.17",
                        "group_addr_range": ["225.1.1.1/32"],
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify rp-info for group 224.0.0.0/4")
    iif = "r1-r2-eth1"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address_1, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1 : Verify rp-info for group 225.1.1.1")
    iif = "r1-r4-eth3"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE, oif, rp_address_2, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: RP-info should not be present \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step(
        "r1 : Verify RPF interface updated in mroute when higher preferred"
        "RP gets deleted"
    )
    iif = "r1-r2-eth1"
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    logger.info("Expected behavior: %s", result)

    step(
        "r1 : Verify IIF and OIL in show ip pim state updated when higher"
        "preferred overlapping RP is deleted"
    )
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "r1 : Verify upstream IIF updated when higher preferred overlapping"
        "RP deleted"
    )
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "r1 : Verify upstream join state and join timer updated when higher"
        "preferred overlapping RP deleted"
    )
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "r1 : Verify join is sent to lower preferred RP, when higher"
        "preferred RP gets deleted"
    )
    step(
        "r1 : Verify prune is sent to higher preferred RP when higher"
        " preferred RP gets deleted"
    )
    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


if __name__ == "__main__":
    ARGS = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(ARGS))
