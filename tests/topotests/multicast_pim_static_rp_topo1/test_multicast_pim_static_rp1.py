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
from time import sleep
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
)
from lib.pim import (
    create_pim_config,
    verify_igmp_groups,
    verify_upstream_iif,
    verify_join_state_and_timer,
    verify_mroutes,
    verify_pim_neighbors,
    verify_pim_rp_info,
    clear_pim_interface_traffic,
    clear_igmp_interfaces,
    clear_pim_interfaces,
    clear_mroute,
    clear_mroute_verify,
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


def test_RP_configured_as_LHR_1_p1(request):
    """
    TC_21_1_P1: Verify OIF and RPF for (*,G) and (S,G) when static RP configure
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface")
    step("Configure RP on r1 (loopback interface) for the group range" " 224.0.0.0/4")
    step("Enable the PIM on all the interfaces of r1, r2, r3 and r4 routers")
    step("Send the IGMP join from r0")
    step("Send multicast traffic from r5")

    step("r1 , r2, r3, r4: Delete existing RP configuration" "configure r1(LHR) as RP")
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
        },
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Configure r1(LHR) as RP")
    input_dict = {
        "r1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.1.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.1.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.1.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.1.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    shutdown_bringup_interface(tgen, "r1", "lo", False)
    sleep(5)
    shutdown_bringup_interface(tgen, "r1", "lo", True)
    sleep(5)

    step("r1: Verify RP info")
    dut = "r1"
    rp_address = "1.0.1.17"
    iif = "lo"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r0: Send IGMP join")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups")
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r5: Send multicast traffic for group 225.1.1.1")
    result = app_helper.run_traffic("r5", GROUP_ADDRESS, "r3")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
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
        "Expected: [{}]: Upstream Join State should not be Joined and "
        "join timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_RP_configured_as_LHR_2_p1(request):
    """
    TC_21_2_P1: Verify OIF and RPF for (*,G) and (S,G) when static RP configure
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface")
    step("Configure RP on r1 (loopback interface) for the group range" " 224.0.0.0/4")
    step("Enable the PIM on all the interfaces of r1, r2, r3 and r4 routers")
    step("Send multicast traffic from r5")
    step("Send the IGMP join from r0")

    step("r1, r2, r3, r4: Delete existing RP configuration," "configure r1(LHR) as RP")
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
        },
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1, r2, r3, r4: Configure r1(LHR) as RP")
    input_dict = {
        "r1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.1.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.1.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.1.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.1.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify RP info")
    dut = "r1"
    rp_address = "1.0.1.17"
    iif = "lo"
    result = verify_pim_rp_info(tgen, TOPO, dut, GROUP_ADDRESS, iif, rp_address, SOURCE)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r5: Send multicast traffic for group 225.1.1.1")
    result = app_helper.run_traffic("r5", GROUP_ADDRESS, "r3")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r0: Send IGMP join")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups")
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
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
        "Expected: [{}]: Upstream Join State should not be Joined and "
        "join timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_RP_configured_as_FHR_1_p1(request):
    """
    TC_22_1_P1: Verify OIF and RFP for (*,G) and (S,G) when static RP configure
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface")
    step("Configure RP on r2 (loopback interface) for the group range" " 225.1.1.0/24")
    step("Enable the PIM on all the interfaces of r1, r2, r3 and r4 routers")
    step("Send the IGMP join from r0")
    step("Send multicast traffic from r5")

    step("r1, r2, r3, r4: Delete existing RP configuration" "configure r3(FHR) as RP")
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
        },
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
    }
    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1, r2, r3, r4: Configure r3(FHR) as RP")
    input_dict = {
        "r1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.3.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.3.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.3.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.3.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify RP info")
    dut = "r1"
    rp_address = "1.0.3.17"
    iif = "r1-r3-eth2"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r0: Send IGMP join")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r0: Verify IGMP groups")
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r5: Send multicast traffic for group 225.1.1.1")
    result = app_helper.run_traffic("r5", GROUP_ADDRESS, "r3")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
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
        "Expected: [{}]: Upstream Join State should not be Joined and "
        "join timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_RP_configured_as_FHR_2_p2(request):
    """
    TC_22_2_P2: Verify OIF and RFP for (*,G) and (S,G) when static RP configure
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface")
    step("Configure RP on r2 (loopback interface) for the group range" " 225.1.1.0/24")
    step("Enable the PIM on all the interfaces of r1, r2, r3 and r4 routers")
    step("Send multicast traffic from r5")
    step("Send the IGMP join from r0")

    step("r1, r2, r3, r4: Delete existing RP configuration" "configure r3(FHR) as RP")
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
        },
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                        "delete": True,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1, r2, r3, r4: Configure r3(FHR) as RP")
    input_dict = {
        "r1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.3.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.3.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.3.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.3.17",
                        "group_addr_range": GROUP_RANGE_ALL,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify RP info")
    dut = "r1"
    rp_address = "1.0.3.17"
    iif = "r1-r3-eth2"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, iif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r5: Send multicast traffic for group 225.1.1.1")
    result = app_helper.run_traffic("r5", GROUP_ADDRESS, "r3")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r0: Send IGMP join")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r0: Verify IGMP groups")
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
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
        "Expected: [{}]: Upstream Join State should not be Joined and "
        "join timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_SPT_RPT_path_different_p1(request):
    """
    TC_23_P1: Verify (*,G) and (S,G) populated correctly when RPT and SPT path
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
    clear_mroute(tgen)
    clear_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface and send IGMP join (225.1.1.1) to r1")
    step("Configure RP on r2 (loopback interface) for the group range" " 224.0.0.0/4")
    step("Enable the PIM on all the interfaces of r1, r2, r3 and r4 routers")
    step("Send multicast traffic from r3")

    step("r2: Verify RP info")
    dut = "r2"
    rp_address = "1.0.2.17"
    iif = "lo"
    result = verify_pim_rp_info(tgen, TOPO, dut, GROUP_ADDRESS, iif, rp_address, SOURCE)
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
    iif = "r1-r3-eth2"
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
        "Expected: [{}]: Upstream Join State should not be Joined and "
        "join timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    dut = "r2"
    iif = "r2-r3-eth1"
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS, joinState="NotJoined"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream Join State should not be Joined and "
        "join timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_clear_pim_configuration_p1(request):
    """
    TC_25_P1: Verify (*,G) and (S,G) populated correctly after clearing the
              PIM,IGMP and mroutes joins

    Topology used:
                ________r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5
                |             |
                |_____________|
                        r4
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

    step("Enable IGMP on r1 interface")
    step("Configure RP on r2 (loopback interface) for the group range" " 224.0.0.0/4")
    step("Enable the PIM on all the interfaces of r1, r2, r3 and r4 routers")
    step("Send the IGMP join from r0")
    step("Send multicast traffic from r5")

    step("r2: Verify RP info")
    dut = "r2"
    rp_address = "1.0.2.17"
    oif = "lo"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, oif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r0: Send IGMP join")
    result = app_helper.run_join("r0", GROUP_ADDRESS, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups")
    dut = "r1"
    iif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, iif, GROUP_ADDRESS)
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
    oif = "r1-r0-eth0"
    result = verify_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups timer restarted")
    result = clear_igmp_interfaces(tgen, dut)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify PIM neighbor timer restarted")
    result = clear_pim_interfaces(tgen, dut)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify PIM mroute timer restarted")
    result = clear_mroute_verify(tgen, dut)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


if __name__ == "__main__":
    ARGS = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(ARGS))
