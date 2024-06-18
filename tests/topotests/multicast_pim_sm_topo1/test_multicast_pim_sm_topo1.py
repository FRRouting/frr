#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test multicast pim sm:

Test steps
- Create topology (setup module)
- Bring up topology

Following tests are covered:
1. TC_1_1: Verify Multicast data traffic with static RP, (*,g) and
   (s,g) OIL updated correctly
2. TC_1_2: Verify Multicast data traffic with static RP, (*,g) and
   (s,g) OIL updated correctly
3. TC_4: Verify removing the RP should not impact the multicast
   data traffic
4. TC_5: Verify (*,G) and (S,G) entry populated again after clear the
   PIM nbr and mroute from FRR node
5. TC_9: Verify (s,g) timeout from FHR and RP when same receive
   exist in LHR , FHR and RP
6. TC_19: Verify mroute detail when same receiver joining 5
    different sources
7. TC_16: Verify (*,G) and (S,G) populated correctly
    when FRR is the transit router
8. TC_23: Verify (S,G) should not create if RP is not reachable
9. TC_24: Verify modification of IGMP query timer should get update
    accordingly
10. TC_25: Verify modification of IGMP max query response timer
    should get update accordingly
"""

import os
import sys
import time
from time import sleep
import pytest

pytestmark = [pytest.mark.pimd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    step,
    apply_raw_config,
    reset_config_on_routers,
    shutdown_bringup_interface,
    required_linux_kernel_version,
)
from lib.pim import (
    create_pim_config,
    create_igmp_config,
    verify_igmp_groups,
    verify_mroutes,
    get_pim_interface_traffic,
    verify_upstream_iif,
    verify_pim_join,
    clear_mroute,
    clear_pim_interface_traffic,
    verify_igmp_config,
    McastTesterHelper,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json


TOPOLOGY = """


    i4-----c1-------------c2---i5
            |              |
            |              |
    i1-----l1------r2-----f1---i2
       |    |      |       |
       |    |      |       |
      i7    i6     i3     i8

    Description:
    i1, i2, i3. i4, i5, i6, i7, i8 - FRR running iperf to send IGMP
                                     join and traffic
    l1 - LHR (last hop router)
    f1 - FHR (first hop router)
    r2 - FRR router
    c1 - FRR router
    c2 - FRR router
"""

# Global variables
GROUP_RANGE = "225.0.0.0/8"
IGMP_JOIN = "225.1.1.1"
GROUP_RANGE_1 = [
    "225.1.1.1/32",
    "225.1.1.2/32",
    "225.1.1.3/32",
    "225.1.1.4/32",
    "225.1.1.5/32",
]
IGMP_JOIN_RANGE_1 = ["225.1.1.1", "225.1.1.2", "225.1.1.3", "225.1.1.4", "225.1.1.5"]
GROUP_RANGE_2 = [
    "226.1.1.1/32",
    "226.1.1.2/32",
    "226.1.1.3/32",
    "226.1.1.4/32",
    "226.1.1.5/32",
]
IGMP_JOIN_RANGE_2 = ["226.1.1.1", "226.1.1.2", "226.1.1.3", "226.1.1.4", "226.1.1.5"]

GROUP_RANGE_3 = [
    "227.1.1.1/32",
    "227.1.1.2/32",
    "227.1.1.3/32",
    "227.1.1.4/32",
    "227.1.1.5/32",
]
IGMP_JOIN_RANGE_3 = ["227.1.1.1", "227.1.1.2", "227.1.1.3", "227.1.1.4", "227.1.1.5"]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel version should be >= 4.19")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)
    logger.info("Master Topology: \n {}".format(TOPOLOGY))

    logger.info("Running setup_module to create topology")

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/multicast_pim_sm_topo1.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, tgen.json_topo)

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

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#   Testcases
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


def test_multicast_data_traffic_static_RP_send_join_then_traffic_p0(request):
    """
    TC_1_1: Verify Multicast data traffic with static RP, (*,g) and
    (s,g) OIL updated correctly
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable IGMP on FRR1 interface and send IGMP join (225.1.1.1)")

    step("get joinRx value before join")
    intf_r2_l1 = topo["routers"]["r2"]["links"]["l1"]["interface"]
    state_dict = {"r2": {intf_r2_l1: ["joinRx"]}}
    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, state_before
    )

    result = app_helper.run_join("i1", IGMP_JOIN, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send the IGMP join first and then start the traffic")

    step("Configure RP on R2 (loopback interface) for the" " group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to 225.1.1.1 receiver")
    result = app_helper.run_traffic("i2", IGMP_JOIN, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    intf_r2_l1 = topo["routers"]["r2"]["links"]["l1"]["interface"]
    intf_r2_f1 = topo["routers"]["r2"]["links"]["f1"]["interface"]
    intf_f1_i2 = topo["routers"]["f1"]["links"]["i2"]["interface"]
    intf_f1_r2 = topo["routers"]["f1"]["links"]["r2"]["interface"]
    input_dict = [
        {"dut": "l1", "src_address": "*", "iif": intf_l1_r2, "oil": intf_l1_i1},
        {"dut": "l1", "src_address": source, "iif": intf_l1_r2, "oil": intf_l1_i1},
        {"dut": "r2", "src_address": "*", "iif": "lo", "oil": intf_r2_l1},
        {"dut": "r2", "src_address": source, "iif": intf_r2_f1, "oil": intf_r2_l1},
        {"dut": "f1", "src_address": source, "iif": intf_f1_i2, "oil": intf_f1_r2},
    ]

    for data in input_dict:
        result = verify_mroutes(
            tgen, data["dut"], data["src_address"], IGMP_JOIN, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct OIL and IIF" " on all the nodes"
    )
    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("joinRx value after join sent")
    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, result
    )

    step(
        "l1 sent PIM (*,G) join to r2 verify using"
        "'show ip pim interface traffic' on RP connected interface"
    )
    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("l1 sent PIM (S,G) join to f1 , verify using 'show ip pim join'")
    dut = "f1"
    interface = intf_f1_r2
    result = verify_pim_join(tgen, topo, dut, interface, IGMP_JOIN)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_multicast_data_traffic_static_RP_send_traffic_then_join_p0(request):
    """
    TC_1_2: Verify Multicast data traffic with static RP, (*,g) and
    (s,g) OIL updated correctly
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure RP on R2 (loopback interface) for the" " group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Start traffic first and then send the IGMP join")

    step("Send multicast traffic from FRR3 to 225.1.1.1 receiver")
    result = app_helper.run_traffic("i2", IGMP_JOIN, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Enable IGMP on FRR1 interface and send IGMP join (225.1.1.1)")
    step("joinRx value before join sent")
    state_dict = {"r2": {"r2-l1-eth2": ["joinRx"]}}
    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, result
    )

    result = app_helper.run_join("i1", IGMP_JOIN, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "l1", "src_address": "*", "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "r2", "src_address": "*", "iif": "lo", "oil": "r2-l1-eth2"},
        {"dut": "r2", "src_address": source, "iif": "r2-f1-eth0", "oil": "r2-l1-eth2"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-r2-eth3"},
    ]
    # On timeout change from default of 80 to 120: failures logs indicate times 90+
    # seconds for success on the 2nd entry in the above table. Using 100s here restores
    # previous 80 retries with 2s wait if we assume .5s per vtysh/show ip mroute runtime
    # (41 * (2 + .5)) == 102.
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN,
            data["iif"],
            data["oil"],
            retry_timeout=102,
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct OIL and IIF" " on all the nodes"
    )
    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("joinRx value after join sent")
    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, result
    )

    step(
        "l1 sent PIM (*,G) join to r2 verify using"
        "'show ip pim interface traffic' on RP connected interface"
    )
    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("l1 sent PIM (S,G) join to f1 , verify using 'show ip pim join'")
    dut = "f1"
    interface = "f1-r2-eth3"
    result = verify_pim_join(tgen, topo, dut, interface, IGMP_JOIN)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_clear_pim_neighbors_and_mroute_p0(request):
    """
    TC_5: Verify (*,G) and (S,G) entry populated again after clear the
    PIM nbr and mroute from FRR node
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP on c1 for group (225.1.1.1-5)")
    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Enable IGMP on FRR1 interface and send IGMP join 225.1.1.1 "
        "to 225.1.1.5 from different interfaces"
    )
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3, wait for SPT switchover")
    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify clear ip mroute (*,g) entries are populated by using "
        "'show ip mroute' cli"
    )

    input_dict = [
        {"dut": "l1", "src_address": "*", "iif": "l1-c1-eth0", "oil": "l1-i1-eth1"}
    ]

    for data in input_dict:
        result = verify_mroutes(
            tgen, data["dut"], data["src_address"], IGMP_JOIN, data["iif"], data["oil"]
        )
        assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("Clear mroutes on l1")
    clear_mroute(tgen, "l1")

    step(
        "After clear ip mroute (*,g) entries are re-populated again"
        " with same OIL and IIF, verify using 'show ip mroute' and "
        " 'show ip pim upstream' "
    )

    for data in input_dict:
        result = verify_mroutes(
            tgen, data["dut"], data["src_address"], IGMP_JOIN, data["iif"], data["oil"]
        )
        assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct OIL and IIF" " on all the nodes"
    )
    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN
        )
        assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_mroute_when_same_receiver_in_FHR_LHR_and_RP_p0(request):
    """
    TC_9: Verify (s,g) timeout from FHR and RP when same receive
    exist in LHR , FHR and RP
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure RP on R2 (loopback interface) for the" " group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1) to R1")

    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        },
        "r2": {
            "igmp": {
                "interfaces": {
                    "r2-i3-eth1": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        },
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i1": "i1-l1-eth0", "i8": "i8-f1-eth0", "i3": "i3-r2-eth0"}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from R3 to 225.1.1.1 receiver")
    result = app_helper.run_traffic("i2", IGMP_JOIN, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("IGMP is received on FRR1 , FRR2 , FRR3, using " "'show ip igmp groups'")
    igmp_groups = {"l1": "l1-i1-eth1", "r2": "r2-i3-eth1", "f1": "f1-i8-eth2"}
    for dut, interface in igmp_groups.items():
        result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN, retry_timeout=80)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) present on all the node with correct OIL" " using 'show ip mroute'")

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "l1", "src_address": "*", "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "r2", "src_address": "*", "iif": "lo", "oil": "r2-i3-eth1"},
        {"dut": "r2", "src_address": source, "iif": "r2-f1-eth0", "oil": "r2-i3-eth1"},
        {"dut": "f1", "src_address": "*", "iif": "f1-r2-eth3", "oil": "f1-i8-eth2"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-i8-eth2"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen, data["dut"], data["src_address"], IGMP_JOIN, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_mroute_when_same_receiver_joining_5_diff_sources_p0(request):
    """
    TC_19: Verify mroute detail when same receiver joining 5
    different sources
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for (226.1.1.1-5) and (232.1.1.1-5)" " in c1")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": _GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Configure IGMP interface on FRR1 and FRR3 and send IGMP join"
        "for group (226.1.1.1-5, 232.1.1.1-5)"
    )

    result = app_helper.run_join("i1", _IGMP_JOIN_RANGE, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_join("i8", _IGMP_JOIN_RANGE, "f1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Send multicast traffic from all the sources to all the "
        "receivers (226.1.1.1-5, 232.1.1.1-5)"
    )

    input_traffic = {
        "i6": "i6-l1-eth0",
        "i7": "i7-l1-eth0",
        "i3": "i3-r2-eth0",
        "i4": "i4-c1-eth0",
        "i5": "i5-c2-eth0",
    }

    for src, src_intf in input_traffic.items():
        result = app_helper.run_traffic(src, _IGMP_JOIN_RANGE, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify (*,G) are created on FRR1 and FRR3 node " " 'show ip mroute' ")

    source_i7 = topo["routers"]["i7"]["links"]["l1"]["ipv4"].split("/")[0]
    source_i6 = topo["routers"]["i6"]["links"]["l1"]["ipv4"].split("/")[0]
    source_i5 = topo["routers"]["i5"]["links"]["c2"]["ipv4"].split("/")[0]
    source_i3 = topo["routers"]["i3"]["links"]["r2"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "l1", "src_address": "*", "iif": "l1-c1-eth0", "oil": "l1-i1-eth1"},
        {
            "dut": "l1",
            "src_address": source_i5,
            "iif": "l1-c1-eth0",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i3,
            "iif": "l1-r2-eth4",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i6,
            "iif": "l1-i6-eth2",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i7,
            "iif": "l1-i7-eth3",
            "oil": "l1-i1-eth1",
        },
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {
            "dut": "f1",
            "src_address": source_i5,
            "iif": "f1-c2-eth0",
            "oil": "f1-i8-eth2",
        },
        {
            "dut": "f1",
            "src_address": source_i3,
            "iif": "f1-r2-eth3",
            "oil": "f1-i8-eth2",
        },
        {
            "dut": "f1",
            "src_address": source_i6,
            "iif": "f1-r2-eth3",
            "oil": "f1-i8-eth2",
        },
        {
            "dut": "f1",
            "src_address": source_i7,
            "iif": "f1-r2-eth3",
            "oil": "f1-i8-eth2",
        },
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop the source one by one on FRR1")
    input_intf = {"i6": "i6-l1-eth0", "i7": "i7-l1-eth0"}
    for dut, intf in input_intf.items():
        shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "After removing the source verify traffic is stopped"
        " immediately and (S,G) got timeout in sometime"
    )

    logger.info("After shut, waiting for SG timeout")

    input_dict = [
        {
            "dut": "l1",
            "src_address": source_i6,
            "iif": "l1-i6-eth2",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i7,
            "iif": "l1-i7-eth3",
            "oil": "l1-i1-eth1",
        },
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    step(
        "Source which is stopped got removed , other source"
        " after still present verify using 'show ip mroute' "
    )
    input_dict = [
        {"dut": "l1", "src_address": "*", "iif": "l1-c1-eth0", "oil": "l1-i1-eth1"},
        {
            "dut": "l1",
            "src_address": source_i5,
            "iif": "l1-c1-eth0",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i3,
            "iif": "l1-r2-eth4",
            "oil": "l1-i1-eth1",
        },
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {
            "dut": "f1",
            "src_address": source_i5,
            "iif": "f1-c2-eth0",
            "oil": "f1-i8-eth2",
        },
        {
            "dut": "f1",
            "src_address": source_i3,
            "iif": "f1-r2-eth3",
            "oil": "f1-i8-eth2",
        },
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Start all the source again for all the receivers")
    input_intf = {"i6": "i6-l1-eth0", "i7": "i7-l1-eth0"}
    for dut, intf in input_intf.items():
        shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "After starting source all the mroute entries got populated, "
        "no duplicate entries present in mroute verify 'show ip mroute'"
    )

    input_dict = [
        {"dut": "l1", "src_address": "*", "iif": "l1-c1-eth0", "oil": "l1-i1-eth1"},
        {
            "dut": "l1",
            "src_address": source_i5,
            "iif": "l1-c1-eth0",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i3,
            "iif": "l1-r2-eth4",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i6,
            "iif": "l1-i6-eth2",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i7,
            "iif": "l1-i7-eth3",
            "oil": "l1-i1-eth1",
        },
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {
            "dut": "f1",
            "src_address": source_i5,
            "iif": "f1-c2-eth0",
            "oil": "f1-i8-eth2",
        },
        {
            "dut": "f1",
            "src_address": source_i3,
            "iif": "f1-r2-eth3",
            "oil": "f1-i8-eth2",
        },
        {
            "dut": "f1",
            "src_address": source_i6,
            "iif": "f1-r2-eth3",
            "oil": "f1-i8-eth2",
        },
        {
            "dut": "f1",
            "src_address": source_i7,
            "iif": "f1-r2-eth3",
            "oil": "f1-i8-eth2",
        },
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_mroute_when_frr_is_transit_router_p2(request):
    """
    TC_16: Verify (*,G) and (S,G) populated correctly
    when FRR is the transit router
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for (226.1.1.1-5) in c2")
    input_dict = {
        "c2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1-5) to FRR1")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to 225.1.1.1-5 receivers")
    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # Stop r2 router to make r2 router disabled from topology
    input_intf = {"l1": "l1-r2-eth4", "f1": "f1-r2-eth3"}
    for dut, intf in input_intf.items():
        shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "FRR4 has (S,G) and (*,G) ,created where incoming interface"
        " toward FRR3 and OIL toward R2, verify using 'show ip mroute'"
        " 'show ip pim state' "
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "c2", "src_address": "*", "iif": "lo", "oil": "c2-c1-eth0"},
        {"dut": "c2", "src_address": source, "iif": "c2-f1-eth1", "oil": "c2-c1-eth0"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen, data["dut"], data["src_address"], IGMP_JOIN, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop multicast traffic from FRR3")
    dut = "i2"
    intf = "i2-f1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)

    logger.info("Waiting for 20 sec to get traffic to be stopped..")
    sleep(20)

    step("top IGMP receiver from FRR1")
    dut = "i1"
    intf = "i1-l1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)

    logger.info("Waiting for 20 sec to get mroutes to be flused out..")
    sleep(20)

    step(
        "After stopping receiver (*,G) also got timeout from transit"
        " router 'show ip mroute'"
    )

    result = verify_mroutes(
        tgen, "c1", "*", IGMP_JOIN, "c1-c2-eth1", "c1-l1-eth0", expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (*, G) should not be present in mroute table \n "
        "Found: {}".format(tc_name, "c1", result)
    )

    write_test_footer(tc_name)


def test_verify_mroute_when_RP_unreachable_p1(request):
    """
    TC_23: Verify (S,G) should not create if RP is not reachable
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure RP on FRR2 (loopback interface) for " "the group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Enable IGMP on FRR1 interface and send IGMP join (225.1.1.1)")

    result = app_helper.run_join("i1", IGMP_JOIN, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to 225.1.1.1 receiver")
    result = app_helper.run_traffic("i2", IGMP_JOIN, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure one IGMP interface on FRR3 node and send IGMP" " join (225.1.1.1)")
    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_join("i8", IGMP_JOIN, "f1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    # Verify mroutes are present in FRR3(f1)
    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "f1", "src_address": "*", "iif": "f1-r2-eth3", "oil": "f1-i8-eth2"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-i8-eth2"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen, data["dut"], data["src_address"], IGMP_JOIN, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the RP connected interface from f1 ( r2 to f1) link")
    dut = "f1"
    intf = "f1-r2-eth3"
    shutdown_bringup_interface(tgen, dut, intf, False)

    logger.info("Waiting for 20 sec to get mroutes to be flushed out..")
    sleep(20)

    step("Clear the mroute on f1")
    clear_mroute(tgen, "f1")

    step(
        "After Shut the RP interface and clear the mroute verify all "
        "(*,G) and (S,G) got timeout from FRR3 node , verify using "
        " 'show ip mroute' "
    )

    result = verify_mroutes(
        tgen, "f1", "*", IGMP_JOIN, "f1-r2-eth3", "f1-i8-eth2", expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (*, G) should not be present in mroute table \n "
        "Found: {}".format(tc_name, "f1", result)
    )

    step("IGMP groups are present verify using 'show ip igmp group'")
    dut = "l1"
    interface = "l1-i1-eth1"
    result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_modify_igmp_query_timer_p0(request):
    """
    TC_24:
    Verify modification of IGMP query timer should get update
    accordingly
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Enable IGMP on FRR1 interface and send IGMP join (225.1.1.1)")
    result = app_helper.run_join("i1", IGMP_JOIN, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on R2 (loopback interface) for the" " group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to 225.1.1.1 receiver")
    result = app_helper.run_traffic("i2", IGMP_JOIN, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_4 = [
        {"dut": "l1", "src_address": "*", "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-r2-eth3"},
    ]
    for data in input_dict_4:
        result = verify_mroutes(
            tgen, data["dut"], data["src_address"], IGMP_JOIN, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct OIL and IIF" " on all the nodes"
    )
    for data in input_dict_4:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Modify IGMP query interval default to other timer on FRR1" "3 times")
    input_dict_1 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {"igmp": {"query": {"query-interval": 20}}}
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {"igmp": {"query": {"query-interval": 25}}}
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {"igmp": {"query": {"query-interval": 30}}}
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_modify_igmp_max_query_response_timer_p0(request):
    """
    TC_25:
    Verify modification of IGMP max query response timer
    should get update accordingly
    """

    tgen = get_topogen()
    topo = tgen.json_topo
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Enable IGMP on FRR1 interface and send IGMP join (225.1.1.1)")
    result = app_helper.run_join("i1", IGMP_JOIN, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure IGMP query response time to 10 deci-sec on FRR1")
    input_dict_1 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "version": "2",
                            "query": {"query-max-response-time": 10},
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on R2 (loopback interface) for the" " group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to 225.1.1.1 receiver")
    result = app_helper.run_traffic("i2", IGMP_JOIN, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_5 = [
        {"dut": "l1", "src_address": "*", "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-r2-eth3"},
    ]
    for data in input_dict_5:
        result = verify_mroutes(
            tgen, data["dut"], data["src_address"], IGMP_JOIN, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct OIL and IIF" " on all the nodes"
    )
    for data in input_dict_5:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Delete the PIM and IGMP on FRR1")
    raw_config = {"l1": {"raw_config": ["interface l1-i1-eth1", "no ip pim"]}}
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "version": "2",
                            "delete": True,
                            "query": {"query-max-response-time": 10, "delete": True},
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure PIM on FRR")
    result = create_pim_config(tgen, topo["routers"])
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure max query response timer 100 decisec on FRR1")
    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "version": "2",
                            "query": {"query-max-response-time": 100},
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Remove and add max query response timer cli with different"
        "timer 5 times on FRR1 Enable IGMP and IGMP version 2 on FRR1"
        " on FRR1"
    )

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "version": "2",
                            "query": {"query-max-response-time": 105},
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "version": "2",
                            "query": {"query-max-response-time": 110},
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "version": "2",
                            "query": {"query-max-response-time": 115},
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "version": "2",
                            "query": {"query-max-response-time": 120},
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable IGMP and IGMP version 2 on FRR1 on FRR1")

    input_dict_4 = {
        "l1": {"igmp": {"interfaces": {"l1-i1-eth1": {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict_4)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
