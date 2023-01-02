#!/usr/bin/env python

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
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
TC_20 : Verfiy PIM upstream IIF updated when higher preferred overlapping RP
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
        shut the RPF inteface
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
    kill_router_daemons,
    start_router_daemons,
    create_static_routes,
    topo_daemons,
)
from lib.pim import (
    create_pim_config,
    verify_igmp_groups,
    verify_upstream_iif,
    verify_join_state_and_timer,
    verify_ip_mroutes,
    verify_pim_neighbors,
    verify_pim_interface_traffic,
    verify_pim_rp_info,
    verify_pim_state,
    clear_ip_pim_interface_traffic,
    clear_ip_igmp_interfaces,
    clear_ip_pim_interfaces,
    clear_ip_mroute,
    clear_ip_mroute_verify,
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

    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen, TOPO)

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen, daemons)

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
        "r1: igmp group present without any IGMP join \n Error: {}".format(
            tc_name, result
        )
    )

    step("r1: Verify show ip pim interface traffic without any IGMP join")
    state_dict = {"r1": {"r1-r2-eth1": ["pruneTx"]}}

    state_before = verify_pim_interface_traffic(tgen, state_dict)
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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
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
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "r1: RP info present \n Error: {}".format(
        tc_name, result
    )

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: upstream IIF interface present \n Error: {}".format(tc_name, result)
    )

    step("r1: Verify upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: upstream join state is up and join timer is running \n Error: {}".format(
            tc_name, result
        )
    )

    # 20
    step("r1: Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS, expected=False)
    assert result is not True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, result
    )

    step("r1: Verify ip mroutes")
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "r1: mroutes are still present \n Error: {}".format(
        tc_name, result
    )

    step("r1: Verify show ip pim interface traffic without any IGMP join")
    state_after = verify_pim_interface_traffic(tgen, state_dict)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r2-eth1"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    iif = "r2-r3-eth1"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
        "r3: (S, G) upstream join state is up and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r2-eth1"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    state_before = verify_pim_interface_traffic(tgen, state_dict)
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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
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
        "OIL is not same and IIF is not cleared on R1 \n Error: {}".format(
            tc_name, result
        )
    )

    step("r1: upstream IIF should be unknown , verify using show ip pim" "upstream")
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: upstream IIF is not unknown \n Error: {}".format(tc_name, result)
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
        "r1: join state is joined and timer is not stopped \n Error: {}".format(
            tc_name, result
        )
    )

    step(
        "r1: (*,G) prune is sent towards the RP interface, verify using"
        "show ip pim interface traffic"
    )
    state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("r1: (*, G) cleared from mroute table using show ip mroute")
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: (*, G) are not cleared from mroute table \n Error: {}".format(
            tc_name, result
        )
    )
    logger.info("Expected behavior: %s", result)

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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "r1: rp-info is present \n Error: {}".format(
        tc_name, result
    )

    step("joinTx value before join sent")
    state_dict = {"r1": {"r1-r2-eth1": ["joinTx"]}}
    state_before = verify_pim_interface_traffic(tgen, state_dict)
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
        "r1: upstream IFF interface is present \n Error: {}".format(tc_name, result)
    )

    step("r1: Verify upstream join state and join timer")

    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: upstream join state is joined and timer is running \n Error: {}".format(
            tc_name, result
        )
    )

    step("r1: Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "r1: PIM state is up\n Error: {}".format(
        tc_name, result
    )

    step("r1: Verify ip mroutes")
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "r1: mroutes are still present\n Error: {}".format(
        tc_name, result
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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    logger.info("Expected behavior: %s", result)

    state_after = verify_pim_interface_traffic(tgen, state_dict)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface and send IGMP " "join (225.1.1.1) to r1")
    step("Configure r2 loopback interface as RP")
    step("Enable PIM between r1 and r2")

    step("r1 : Verify pim interface traffic")
    state_dict = {"r1": {"r1-r2-eth1": ["joinTx"]}}
    state_before = verify_pim_interface_traffic(tgen, state_dict)
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
        "r1: upstream IIF interface is present\n Error: {}".format(tc_name, result)
    )

    step("r1 : Verify upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, STAR, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: upstream join state is joined and timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r1 : Verify PIM state")
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "r1: PIM state is up\n Error: {}".format(
        tc_name, result
    )

    step("r1 : Verify ip mroutes")
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "r1: mroutes are still present\n Error: {}".format(
        tc_name, result
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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    logger.info("Expected behavior: %s", result)

    step("r1 : Verify pim interface traffic")
    state_after = verify_pim_interface_traffic(tgen, state_dict)
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
     TC_20_P1 : Verfiy PIM upstream IIF updated when higher preferred
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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

    state_before = verify_pim_interface_traffic(tgen, state_dict)
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
    state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("r1 : Verify ip mroutes")
    iif = "r1-r4-eth3"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
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

    clear_ip_pim_interface_traffic(tgen, TOPO)

    step("r1 : Verify joinTx, pruneTx count before RP gets deleted")
    state_dict = {"r1": {"r1-r2-eth1": ["joinTx"], "r1-r4-eth3": ["pruneTx"]}}

    state_before = verify_pim_interface_traffic(tgen, state_dict)
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
        "r1: rp-info is present for group 225.1.1.1 \n Error: {}".format(
            tc_name, result
        )
    )

    step(
        "r1 : Verify RPF interface updated in mroute when higher preferred"
        "RP gets deleted"
    )
    iif = "r1-r2-eth1"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    logger.info("Expected behavior: %s", result)

    step(
        "r1 : Verify IIF and OIL in show ip pim state updated when higher"
        "preferred overlapping RP is deleted"
    )
    result = verify_pim_state(tgen, dut, iif, oif, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "r1 : Verfiy upstream IIF updated when higher preferred overlapping"
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
    state_after = verify_pim_interface_traffic(tgen, state_dict)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
        "r3: (S, G) upstream join state is joined and join"
        " timer is running \n Error: {}".format(tc_name, result)
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
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
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups timer restarted")
    result = clear_ip_igmp_interfaces(tgen, dut)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify PIM neighbor timer restarted")
    result = clear_ip_pim_interfaces(tgen, dut)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify PIM mroute timer restarted")
    result = clear_ip_mroute_verify(tgen, dut)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

    write_test_footer(tc_name)


def test_restart_pimd_process_p2(request):
    """
    TC_26_P2: Restart the PIMd process and verify PIM upstream and mroutes
              entries
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface and send IGMP join (225.1.1.1) to R1")
    step("Configure RP on r3 (loopback interface) for the group range" " 224.0.0.0/4")
    step("Enable the PIM on all the interfaces of r1, r2, r3 and r4 routers")
    step("Send multicast traffic from R3")
    step("Restart the PIMd process")

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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
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
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
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
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    iif = "r1-r2-eth1"
    oil = "r1-r0-eth0"
    logger.info("waiting for 10 sec to make sure old mroute time is higher")
    sleep(10)
    # Why do we then wait 60 seconds below before checking the routes?
    uptime_before = verify_ip_mroutes(
        tgen, dut, STAR, GROUP_ADDRESS, iif, oil, return_uptime=True, mwait=60
    )
    assert isinstance(uptime_before, dict), "Testcase{} : Failed Error: {}".format(
        tc_name, result
    )

    step("r1: Kill pimd process")
    kill_router_daemons(tgen, "r1", ["pimd"])

    step("r1 : Start pimd process")
    start_router_daemons(tgen, "r1", ["pimd"])

    logger.info("Waiting for 5sec to get PIMd restarted and mroute" " re-learned..")
    sleep(5)

    # Why do we then wait 10 seconds below before checking the routes?
    uptime_after = verify_ip_mroutes(
        tgen, dut, STAR, GROUP_ADDRESS, iif, oil, return_uptime=True, mwait=10
    )
    assert isinstance(uptime_after, dict), "Testcase{} : Failed Error: {}".format(
        tc_name, result
    )

    result = verify_mroute_repopulated(uptime_before, uptime_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_multiple_groups_same_RP_address_p2(request):
    """
    TC_27_P2: Configure multiple  groups (10 grps) with same RP address

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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface and send IGMP join (225.1.1.1) to r1")
    step("Configure RP on r2 (loopback interface) for the group range" "225.1.1.0/24")
    step("Enable the PIM on all the interfaces of r1-r2-r3")
    step("Send multicast traffic from r5 to all the groups")
    step("r1 : Remove the groups to RP mapping one by one")
    step("r1: Shut the upstream interfaces")
    step("r1: No shut the upstream interfaces")
    step("r1: Configure the RP again")
    step("r1: Shut the receiver interfaces")
    step("r1: No Shut the receiver interfaces")
    step("r2: Verify RP info")

    step("r2: verify rp-info")
    dut = "r2"
    rp_address = "1.0.2.17"
    oif = "lo"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_ALL, oif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    group_address_list = GROUP_ADDRESS_LIST_1 + GROUP_ADDRESS_LIST_2
    step("r0: Send IGMP join for 10 groups")
    result = app_helper.run_join("r0", group_address_list, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups")
    dut = "r1"
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r5: Send multicast traffic for group 225.1.1.1")
    result = app_helper.run_traffic("r5", group_address_list, "r3")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = "r1-r2-eth1"
    result = verify_upstream_iif(tgen, dut, iif, STAR, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = "r3-r5-eth3"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    dut = "r2"
    iif = "r2-r3-eth1"
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, joinState="NotJoined"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

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

    step("r1: Shut the interface r1-r2-eth1 from R1 to R2")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No Shut the interface r1-r2-eth1 from R1 to R2")
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Configure RP")
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

    step("r1: Shut the interface r1-r0-eth0 from R1 to R2")
    intf = "r1-r0-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No Shut the interface r1-r0-eth0 from R1 to R2")
    intf = "r1-r0-eth0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = "r1-r2-eth1"
    result = verify_upstream_iif(tgen, dut, iif, STAR, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    dut = "r2"
    iif = "r2-r3-eth1"
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, joinState="NotJoined"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = "r3-r5-eth3"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, group_address_list, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, SOURCE_ADDRESS, group_address_list, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_multiple_groups_different_RP_address_p2(request):
    """
    TC_28_P2: Verify IIF and OIL in updated in mroute when upstream interface
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

    step("Delete existing RP configuration")
    input_dict = {
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
        }
    }
    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_LIST_1,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.4.17",
                        "group_addr_range": GROUP_RANGE_LIST_2,
                    }
                ]
            }
        },
    }
    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify RP info")
    dut = "r2"
    rp_address = "1.0.2.17"
    oif = "lo"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_LIST_1, oif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify RP info")
    dut = "r4"
    rp_address = "1.0.4.17"
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_LIST_2, oif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    group_address_list = GROUP_ADDRESS_LIST_1 + GROUP_ADDRESS_LIST_2
    step("r0: Send IGMP join")
    result = app_helper.run_join("r0", group_address_list, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify IGMP groups")
    dut = "r1"
    oif = "r1-r0-eth0"
    result = verify_igmp_groups(tgen, dut, oif, group_address_list)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r5: Send multicast traffic for group 225.1.1.1")
    result = app_helper.run_traffic("r5", group_address_list, "r3")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = "r1-r2-eth1"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    iif = "r2-r3-eth1"
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, joinState="NotJoined"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = "r3-r5-eth3"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = "r1-r4-eth3"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (*, G) upstream IIF interface")
    dut = "r4"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (*, G) ip mroutes")
    oif = "r4-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (S, G) upstream IIF interface")
    iif = "r4-r3-eth1"
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, joinState="NotJoined"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r4: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r4: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = "r3-r5-eth3"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, expected=False
    )
    assert result is not True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, result
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Delete RP configuration")
    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_LIST_1,
                        "delete": True,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.4.17",
                        "group_addr_range": GROUP_RANGE_LIST_2,
                        "delete": True,
                    }
                ]
            }
        },
    }
    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1, r2, r3, r4: Re-configure RP")
    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.2.17",
                        "group_addr_range": GROUP_RANGE_LIST_1,
                    }
                ]
            }
        },
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "1.0.4.17",
                        "group_addr_range": GROUP_RANGE_LIST_2,
                    }
                ]
            }
        },
    }
    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Shut the interface r1-r2-eth1 from R1 to R2")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No shut the interface r1-r2-eth1 from R1 to R2")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Shut the interface r1-r2-eth1 from R1 to R4")
    dut = "r1"
    intf = "r1-r4-eth3"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No shut the interface r1-r2-eth1 from R1 to r4")
    dut = "r1"
    intf = "r1-r4-eth3"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Shut the interface r1-r0-eth0 from R1 to R0")
    dut = "r1"
    intf = "r1-r0-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No Shut the interface r1-r0-eth0 from R1 to R0")
    dut = "r1"
    intf = "r1-r0-eth0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = "r1-r2-eth1"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream IIF interface")
    dut = "r2"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_1, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream IIF interface")
    iif = "r2-r3-eth1"
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, joinState="NotJoined"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = "r3-r5-eth3"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_1, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream IIF interface")
    dut = "r1"
    iif = "r1-r4-eth3"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (*, G) ip mroutes")
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream IIF interface")
    iif = "r1-r3-eth2"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify (S, G) ip mroutes")
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (*, G) upstream IIF interface")
    dut = "r4"
    iif = "lo"
    result = verify_upstream_iif(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (*, G) upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, iif, STAR, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (*, G) ip mroutes")
    oif = "r4-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS_LIST_2, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (S, G) upstream IIF interface")
    iif = "r4-r3-eth1"
    result = verify_upstream_iif(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, joinState="NotJoined"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r4: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r4: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r4: Verify (S, G) ip mroutes")
    oif = "none"
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream IIF interface")
    dut = "r3"
    iif = "r3-r5-eth3"
    result = verify_upstream_iif(tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (S, G) upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, iif, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (S,G) upstream state is joined and join timer is running\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (S, G) ip mroutes")
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(
        tgen, dut, SOURCE_ADDRESS, GROUP_ADDRESS_LIST_2, iif, oif
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_shutdown_primary_path_p1(request):
    """
    TC_30_P1: Verify IIF and OIL change to other path after shut the primary
              path

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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

    # Steps to execute
    step("Enable IGMP on r1 interface")
    step("Configure RP on r2 (loopback interface) for the group range" " 224.0.0.0/4")
    step("r1: Shut the link from r1 to r2")
    step("r3: Shut the link from r1 to r3")
    step("r1: No shut the link from r1 to r2")
    step("r3: No shut the link from r1 to r3")

    step("r1: Verify RP info")
    dut = "r1"
    rp_address = "1.0.2.17"
    iif = "r1-r2-eth1"
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

    step("r1: Verify (*, G) ip mroutes")
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    dut = "r2"
    iif = "lo"
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Shut the interface r1-r2-eth1 from R1 to R2")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "Verify after shut the R1 to R2 link , verify join is reaching to RP"
        "via other path"
    )

    logger.info("Waiting for 110 sec only if test run with crucible")

    step("r1: Verify (*, G) ip mroutes")
    dut = "r1"
    iif = "r1-r3-eth2"
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    dut = "r2"
    iif = "lo"
    oif = "r2-r3-eth1"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (*, G) ip mroutes")
    dut = "r3"
    iif = "r3-r2-eth1"
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Shut the link from R1 to R3 from R3 node")
    dut = "r3"
    intf = "r3-r1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "Verify after shut of R1 to R3 link , verify (*,G) entries got"
        " cleared from all the node R1, R2, R3"
    )

    step("r1: Verify (*, G) ip mroutes")
    dut = "r1"
    iif = "r1-r3-eth2"
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: (*,G) mroutes are not cleared after shut of R1 to R3 link\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (*, G) ip mroutes")
    dut = "r2"
    iif = "lo"
    oif = "r2-r3-eth1"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (*,G) mroutes are not cleared after shut of R1 to R3 link\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: Verify (*, G) ip mroutes")
    dut = "r3"
    iif = "r3-r2-eth1"
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r3: (*,G) mroutes are not cleared after shut of R1 to R3 link\n Error: {}".format(
            tc_name, result
        )
    )

    step("r3: No shutdown the link from R1 to R3 from R3 node")
    dut = "r3"
    intf = "r3-r1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Verify (*, G) ip mroutes")
    dut = "r1"
    iif = "r1-r3-eth2"
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    dut = "r2"
    iif = "lo"
    oif = "r2-r3-eth1"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r3: Verify (*, G) ip mroutes")
    dut = "r3"
    iif = "r3-r2-eth1"
    oif = "r3-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: No shutdown the link from R1 to R2 from R1 node")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Verify (*, G) ip mroutes")
    dut = "r1"
    iif = "r1-r2-eth1"
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes")
    dut = "r2"
    iif = "lo"
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_delete_RP_shut_noshut_upstream_interface_p1(request):
    """
    TC_31_P1: Verify RP info and (*,G) mroute after deleting the RP and shut /
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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface")
    step("Configure RP on r2 (loopback interface) for the group range" " 224.0.0.0/4")
    step("r1: Delete the RP config")
    step("r1: Shut and no shut the upstream interface (R1-R2) connected link")
    step("r1: Shut and no shut the OIL interface")

    step("r1: Verify RP info")
    dut = "r1"
    rp_address = "1.0.2.17"
    iif = "r1-r2-eth1"
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

    step("r1: Verify (*, G) ip mroutes created")
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes created")
    dut = "r2"
    iif = "lo"
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

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

    step("r1: Shut the interface r1-r2-eth1 from R1 to R2")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No shutdown the interface r1-r2-eth1 from R1 to R2")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Shutdown the OIL interface r1-r0-eth0 from R1 to R0 ")
    dut = "r1"
    intf = "r1-r0-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: No shutdown the OIL interface r1-r0-eth0 from R1 to R0")
    dut = "r1"
    intf = "r1-r0-eth0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("r1: Verify (*, G) ip mroutes cleared")
    dut = "r1"
    iif = "r1-r2-eth1"
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: (*,G) mroutes are not cleared after shut of R1 to R0 link\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (*, G) ip mroutes cleared")
    dut = "r2"
    iif = "lo"
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (*,G) mroutes are not cleared after shut of R1 to R0 link\n Error: {}".format(
            tc_name, result
        )
    )

    write_test_footer(tc_name)


def test_delete_RP_shut_noshut_RP_interface_p1(request):
    """
    TC_32_P1: Verify RP info and (*,G) mroute after deleting the RP and shut/
           no shut the RPF inteface

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
    clear_ip_mroute(tgen)
    clear_ip_pim_interface_traffic(tgen, TOPO)

    step("Enable IGMP on r1 interface")
    step("Configure RP on r2 (lo) for the group range" " 224.0.0.0/4")
    step("r2: Delete the RP configuration")
    step("r2: Shut the RP interface (lo)")
    step("r1: Shut the interface(r1-r2-eth1, r1-r3-eth2) towards rp")

    step("r1: Verify RP info")
    dut = "r1"
    rp_address = "1.0.2.17"
    iif = "r1-r2-eth1"
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

    step("r1: Verify (*, G) ip mroutes created")
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Verify (*, G) ip mroutes created")
    dut = "r2"
    iif = "lo"
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Delete RP configuration")

    # Delete RP configuration
    input_dict = {
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
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r2: Shut the RP interface lo")
    dut = "r2"
    intf = "lo"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: Shut the interface r1-r2-eth1 towards RP")
    dut = "r1"
    intf = "r1-r2-eth1"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: Shut the interface r1-r3-eth2 towards RP")
    dut = "r1"
    intf = "r1-r3-eth2"
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("r1: Verify (*, G) ip mroutes cleared")
    dut = "r1"
    iif = "r1-r2-eth1"
    oif = "r1-r0-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: (*,G) mroutes are not cleared after shut of R1 to R2 and R3 link\n Error: {}".format(
            tc_name, result
        )
    )

    step("r2: Verify (*, G) ip mroutes cleared")
    dut = "r2"
    iif = "lo"
    oif = "r2-r1-eth0"
    result = verify_ip_mroutes(tgen, dut, STAR, GROUP_ADDRESS, iif, oif, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r2: (*,G) mroutes are not cleared after shut of R1 to R2 and R3 link\n Error: {}".format(
            tc_name, result
        )
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    ARGS = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(ARGS))
