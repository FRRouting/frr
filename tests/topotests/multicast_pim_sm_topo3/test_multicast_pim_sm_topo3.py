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

1.  verify oil when join prune sent scenario_1 p0
2.  verify oil when join prune sent scenario_2 p0
3.  shut noshut source interface when upstream cleared from LHR p0(
4.  shut noshut receiver interface when upstream cleared from LHR p0(
5.  verify igmp clis p0
6.  verify igmp cli generate query once p0
7.  verify remove add igmp config to receiver interface p0
8.  verify remove add igmp commands when pim configured p0
9.  verify remove add pim commands when igmp configured p0
10. pim dr priority p0
11. pim hello timer p0
12. Verify mroute after removing RP sending IGMP prune p2
13. Verify prune is sent to LHR and FHR when PIM nbr went down
14. Verify mroute flag in LHR and FHR node
15. Verify IGMP prune processed correctly when same join received from IGMP and PIM
16. Verify multicast traffic flowing fine, when LHR connected to RP
17. Verify multicast traffic is flowing fine when FHR is connected to RP
"""

import os
import re
import sys
import time
import datetime
import pytest
from time import sleep
import json
import functools

pytestmark = [pytest.mark.pimd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    step,
    reset_config_on_routers,
    shutdown_bringup_interface,
    apply_raw_config,
    check_router_status,
    required_linux_kernel_version,
    topo_daemons,
)
from lib.pim import (
    create_pim_config,
    create_igmp_config,
    verify_igmp_groups,
    verify_mroutes,
    clear_mroute,
    clear_pim_interface_traffic,
    verify_igmp_config,
    verify_pim_config,
    verify_pim_interface,
    verify_upstream_iif,
    verify_multicast_traffic,
    verify_pim_rp_info,
    verify_multicast_flag_state,
    McastTesterHelper,
    verify_pim_interface_traffic,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

CWD = os.path.dirname(os.path.realpath(__file__))

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
    l1 - LHR
    f1 - FHR
    r2 - FRR router
    c1 - FRR router
    c2 - FRR router
"""

# Global variables
VLAN_1 = 2501
GROUP_RANGE = "225.0.0.0/8"
IGMP_GROUP = "225.1.1.1/32"
IGMP_JOIN = "225.1.1.1"
VLAN_INTF_ADRESS_1 = "10.0.8.3/24"
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

SAME_VLAN_IP_1 = {"ip": "10.1.1.1", "subnet": "255.255.255.0", "cidr": "24"}
SAME_VLAN_IP_2 = {"ip": "10.1.1.2", "subnet": "255.255.255.0", "cidr": "24"}
SAME_VLAN_IP_3 = {"ip": "10.1.1.3", "subnet": "255.255.255.0", "cidr": "24"}
SAME_VLAN_IP_4 = {"ip": "10.1.1.4", "subnet": "255.255.255.0", "cidr": "24"}


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

    json_file = "{}/multicast_pim_sm_topo3.json".format(CWD)
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
    build_config_from_json(tgen, topo)

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

            d1 = datetime.datetime.strptime(uptime_before[group][source], "%H:%M:%S")
            d2 = datetime.datetime.strptime(uptime_after[group][source], "%H:%M:%S")
            if d2 >= d1:
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

    for ttype, v1 in state_before.items():
        for intf, v2 in v1.items():
            for state, value in v2.items():
                if value >= state_after[ttype][intf][state]:
                    errormsg = (
                        "[DUT: %s]: state %s value has not incremented, Initial value: %s, Current value: %s [FAILED!!]"
                        % (
                            intf,
                            state,
                            value,
                            state_after[ttype][intf][state],
                        )
                    )
                    return errormsg

                logger.info(
                    "[DUT: %s]: State %s value is incremented, Initial value: %s, Current value: %s [PASSED!!]",
                    intf,
                    state,
                    value,
                    state_after[ttype][intf][state],
                )

    return True


def find_v2_query_msg_in_tcpdump(tgen, router, message, count, cap_file):
    """
    Find v2 query messages in tcpdump file

    Parameters
    ----------
    * `tgen` : Topology handler
    * `router` : Device under test
    * `cap_file` : tcp dump file name

    """

    filepath = os.path.join(tgen.logdir, router, cap_file)
    with open(filepath) as f:
        if len(re.findall("{}".format(message), f.read())) < count:
            errormsg = "[DUT: %s]: Verify Message: %s in tcpdump" " [FAILED!!]" % (
                router,
                message,
            )
            return errormsg

        logger.info(
            "[DUT: %s]: Found message: %s in tcpdump " " count: %s [PASSED!!]",
            router,
            message,
            count,
        )
    return True


def find_tos_in_tcpdump(tgen, router, message, cap_file):
    """
    Find v2 query messages in tcpdump file

    Parameters
    ----------
    * `tgen` : Topology handler
    * `router` : Device under test
    * `cap_file` : tcp dump file name

    """

    filepath = os.path.join(tgen.logdir, router, cap_file)
    with open(filepath) as f:
        if len(re.findall(message, f.read())) < 1:
            errormsg = "[DUT: %s]: Verify Message: %s in tcpdump" " [FAILED!!]" % (
                router,
                message,
            )
            return errormsg

        logger.info(
            "[DUT: %s]: Found message: %s in tcpdump " "[PASSED!!]", router, message
        )
    return True


def verify_pim_stats_increament(stats_before, stats_after):
    """
    API to compare pim interface control plane traffic

    Parameters
    ----------
    * `stats_before` : Stats dictionary for any particular instance
    * `stats_after` : Stats dictionary for any particular instance
    """

    for router, stats_data in stats_before.items():
        for stats, value in stats_data.items():
            if stats_before[router][stats] >= stats_after[router][stats]:
                errormsg = (
                    "[DUT: %s]: state %s value has not"
                    " incremented, Initial value: %s, "
                    "Current value: %s [FAILED!!]"
                    % (
                        router,
                        stats,
                        stats_before[router][stats],
                        stats_after[router][stats],
                    )
                )
                return errormsg

            logger.info(
                "[DUT: %s]: State %s value is "
                "incremented, Initial value: %s, Current value: %s"
                " [PASSED!!]",
                router,
                stats,
                stats_before[router][stats],
                stats_after[router][stats],
            )

    return True


def test_verify_oil_when_join_prune_sent_scenario_1_p1(request):
    """
    TC_21_1:
    Verify OIL detail updated in (S,G) and (*,G) mroute when IGMP
    join/prune is sent
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (226.1.1.1-5)"
    )
    step(
        "Enable IGMP of FRR3 interface and send IGMP joins "
        " from FRR3 node for group range (226.1.1.1-5)"
    )

    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    intf_f1_i8: {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {
        "i1": topo["routers"]["i1"]["links"]["l1"]["interface"],
        "i8": topo["routers"]["i8"]["links"]["f1"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (226.1.1.1-5) in R2")

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

    step(
        "Configure one source on FRR3 for all the groups and send" " multicast traffic"
    )

    input_src = {"i2": topo["routers"]["i2"]["links"]["f1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": "*",
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send the IGMP prune from ixia to (226.1.1.1-5) receiver on " "FRR1 node")

    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, False)

    step(
        "After receiving the IGMP prune from FRR1 , verify traffic "
        "immediately stopped for this receiver 'show ip multicast'"
    )

    input_traffic = {"l1": {"traffic_sent": [intf_l1_i1]}}
    result = verify_multicast_traffic(tgen, input_traffic, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Multicast traffic should be stopped \n "
        "Found: {}".format(tc_name, "l1", result)
    )

    step(
        "IGMP groups are remove from FRR1 node 'show ip igmp groups'"
        " FRR3 IGMP still present"
    )

    dut = "l1"
    result = verify_igmp_groups(
        tgen, dut, intf_l1_i1, IGMP_JOIN_RANGE_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: IGMP groups should be deleted \n "
        "Found: {}".format(tc_name, dut, result)
    )

    dut = "f1"
    result = verify_igmp_groups(tgen, dut, intf_f1_i8, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(*,G) and (S,G) OIL got removed immediately after receiving"
        " prune 'show ip pim state' and 'show ip mroute' on FRR1 node,"
        " no impact on FRR3 receiver"
    )

    input_dict_l1 = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_l1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    for data in input_dict_l1:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: Upstream IIF {} should not be present \n "
            "Found: {}".format(tc_name, data["dut"], data["iif"], result)
        )

    input_dict_f1 = [
        {
            "dut": "f1",
            "src_address": "*",
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_f1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_f1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send the IGMP prune from ixia to (226.1.1.1-5) receiver on " " FRR3 node")

    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    shutdown_bringup_interface(tgen, "f1", intf_f1_i8, False)

    step(
        "After receiving the IGMP prune from FRR3s , verify traffic "
        "immediately stopped for this receiver 'show ip multicast'"
    )

    input_traffic = {"f1": {"traffic_sent": [intf_f1_i8]}}
    result = verify_multicast_traffic(tgen, input_traffic, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Multicast traffic should be stopped \n "
        "Found: {}".format(tc_name, "f1", result)
    )

    step(
        "IGMP groups are remove from FRR1 node 'show ip igmp groups'"
        " FRR3 IGMP still present"
    )

    dut = "f1"
    result = verify_igmp_groups(
        tgen, dut, intf_f1_i8, IGMP_JOIN_RANGE_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: IGMP groups should be deleted \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step(
        "(*,G) and (S,G) OIL got prune state (none) from all the nodes"
        "FRR1, FRR3 verify using 'show ip mroute'"
    )

    input_dict_l1 = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_l1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    for data in input_dict_l1:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: Upstream IIF {} should not be present \n "
            "Found: {}".format(tc_name, data["dut"], data["iif"], result)
        )

    shutdown_bringup_interface(tgen, "f1", intf_f1_i8, True)
    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, True)

    for data in input_dict_l1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_oil_when_join_prune_sent_scenario_2_p1(request):
    """
    TC_21_2: Verify OIL detail updated in (S,G) and (*,G) mroute when IGMP
    join/prune is sent
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Removing FRR3 to simulate topo " "FHR(FRR1)---LHR(FRR2)")

    intf_l1_c1 = topo["routers"]["l1"]["links"]["c1"]["interface"]
    intf_f1_c2 = topo["routers"]["f1"]["links"]["c2"]["interface"]
    intf_f1_r2 = topo["routers"]["f1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_c1, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_c2, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_r2, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (226.1.1.1-5)"
    )
    step(
        "Enable IGMP of FRR3 interface and send IGMP joins "
        " from FRR3 node for group range (226.1.1.1-5)"
    )

    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]
    input_dict = {
        "r2": {
            "igmp": {
                "interfaces": {
                    intf_r2_i3: {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {
        "i1": topo["routers"]["i1"]["links"]["l1"]["interface"],
        "i3": topo["routers"]["i3"]["links"]["r2"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (226.1.1.1-5) in R2")

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
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send the IGMP prune from ixia to (226.1.1.1-5) receiver on " "FRR3(r2) node")

    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_i3, False)

    step(
        "After sending IGMP prune from FRR3(r2) node verify (*,G) OIL "
        "immediately removed for local receiver mroute should have "
        " PIM protocol , IGMP should be removed verify using "
        "'show ip mroute' no impact seen on FRR1(l1) (*,G)"
    )

    input_dict_r2 = [
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        }
    ]

    for data in input_dict_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    input_dict_l1_r2 = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_l1_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send the IGMP prune from ixia to (226.1.1.1-5) receiver on " "FRR1(l1) node")

    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, False)

    step(
        "After sending IGMP prune from FRR1 node verify (*,G) OIL"
        "got removed immediately from FRR1 node"
    )

    input_dict_l1 = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_l1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    step("After prune is sent verify upstream got removed in FRR1 node")

    for data in input_dict_l1:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: Upstream IIF {} should not be present \n "
            "Found: {}".format(tc_name, data["dut"], data["iif"], result)
        )

    write_test_footer(tc_name)


def test_shut_noshut_source_interface_when_upstream_cleared_from_LHR_p1(request):
    """
    TC_26: Verify shut/no shut of source interface after upstream got cleared
    from LHR
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Enable the PIM on all the interfaces of FRR1, R2 and FRR3" " routers")
    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1-225.1.1.10)")

    input_join = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on R2 (loopback interface) for " "the group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
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

    step("Send multicast traffic from FRR3 to 225.1.1.1-225.1.1.10" " receiver")

    input_src = {"i2": topo["routers"]["i2"]["links"]["f1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "'show ip mroute' showing correct RPF and OIF interface for (*,G)"
        " and (S,G) entries on all the nodes"
    )

    source_i2 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    step(
        "'show ip pim upstream' and 'show ip pim upstream-rpf' showing"
        " correct OIL and IIF on all the nodes"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the source interface from FRR3")
    intf_f1_i2 = topo["routers"]["f1"]["links"]["i2"]["interface"]
    shutdown_bringup_interface(tgen, "f1", intf_f1_i2, False)

    step(
        "After shut of source interface verify (S,G) mroutes are cleared"
        " from all the nodes"
    )

    intf_f1_r2 = topo["routers"]["f1"]["links"]["r2"]["interface"]
    result = verify_mroutes(
        tgen, "f1", source_i2, IGMP_JOIN_RANGE_1, intf_f1_i2, intf_f1_r2, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
        "Found: {}".format(tc_name, "f1", result)
    )

    step(
        "After waiting for (S,G) timeout from FRR1 for same"
        " source verify that (S,G) is flushed from FRR1 node"
        " 'show ip pim upstream' 'show ip mroute' "
    )

    result = verify_upstream_iif(
        tgen, "l1", "Unknown", source_i2, IGMP_JOIN_RANGE_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream IIF should be Unknown \n "
        "Found: {}".format(tc_name, "l1", result)
    )

    step("No shut the Source interface just after the upstream is expired" " from FRR1")
    shutdown_bringup_interface(tgen, "f1", intf_f1_i2, True)

    step(
        "After no shut of source interface , verify all the (S,G) is "
        " populated again on 'show ip mroute' 'show ip pim upstream' "
        " with proper OIL and IIF detail"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("shut and no shut the source interface immediately")
    shutdown_bringup_interface(tgen, "f1", intf_f1_i2, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_i2, True)

    step(
        "All the mroutes got updated with proper OIL after no shut of"
        "interface verify using 'show ip mroute'"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_shut_noshut_receiver_interface_when_upstream_cleared_from_LHR_p1(request):
    """
    TC_27: Verify shut/no shut of receiver interface after upstream got
    cleared from LHR
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Enable the PIM on all the interfaces of FRR1, R2 and FRR3" " routers")
    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1-225.1.1.10)")

    input_join = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on R2 (loopback interface) for " "the group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
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

    step("Send multicast traffic from FRR3 to 225.1.1.1-225.1.1.10" " receiver")

    input_src = {"i2": topo["routers"]["i2"]["links"]["f1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "'show ip mroute' showing correct RPF and OIF interface for (*,G)"
        " and (S,G) entries on all the nodes"
    )

    source_i2 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "'show ip pim upstream' and 'show ip pim upstream-rpf' showing"
        " correct OIL and IIF on all the nodes"
    )

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the source interface FRR1")
    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    intf_f1_i2 = topo["routers"]["f1"]["links"]["i2"]["interface"]
    intf_f1_r2 = topo["routers"]["f1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, False)

    step(
        "After waiting for (S,G) timeout from FRR1 for same"
        " source verify that (S,G) is flushed from FRR1 node"
        " 'show ip pim upstream' 'show ip mroute' "
    )

    result = verify_upstream_iif(
        tgen, "l1", "Unknown", source_i2, IGMP_JOIN_RANGE_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream IIF should be Unknown \n "
        "Found: {}".format(tc_name, "l1", result)
    )

    step("No shut the Source interface just after the upstream is expired" " from FRR1")
    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, True)

    step(
        "After no shut of source interface , verify all the (S,G) is "
        " populated again on 'show ip mroute' 'show ip pim upstream' "
        " with proper OIL and IIF detail"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("shut and no shut the source interface immediately")
    shutdown_bringup_interface(tgen, "f1", intf_f1_i2, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_i2, True)

    step(
        "After no shut of receiver interface , verify all the (S,G) is "
        "populated again on 'show ip mroute' 'show ip pim upstream' "
        "with proper OIL and IIF detail"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_remove_add_igmp_config_to_receiver_interface_p0(request):
    """
    TC_33: Verify removing and adding IGMP config from the receiver interface
    """
    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Enable PIM on all routers")
    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1-225.1.1.10)")

    input_join = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (226.1.1.1-5) and (232.1.1.1-5) in cisco-1(f1)")

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

    step("Configure source on FRR3 and start the traffic for" " (225.1.1.1-225.1.1.10)")

    input_src = {"i2": topo["routers"]["i2"]["links"]["f1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure source on FRR1 and start the traffic for" " (225.1.1.1-225.1.1.10)")

    input_src = {"i6": topo["routers"]["i6"]["links"]["l1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i6 = topo["routers"]["i6"]["links"]["l1"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i6,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # IGMP JSON verification
    step("Verify IGMP group and source JSON for single interface and group")
    router = tgen.gears["l1"]

    reffile = os.path.join(CWD, "igmp_group_all_detail.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip igmp vrf default groups detail json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "IGMP group detailed output on l1 for all interfaces and all groups is not as expected. Expected: {}".format(
        expected
    )
    assert res is None, assertmsg

    reffile = os.path.join(CWD, "igmp_single_if_group_all_brief.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip igmp vrf default groups l1-i1-eth1 json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "IGMP group output on l1 for all groups in interface l1-i1-eth1 is not as expected. Expected: {}".format(
        expected
    )
    assert res is None, assertmsg

    reffile = os.path.join(CWD, "igmp_single_if_group_all_detail.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip igmp vrf default groups l1-i1-eth1 detail json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "IGMP group detailed output on l1 for all groups in interface l1-i1-eth1 is not as expected. Expected: {}".format(
        expected
    )
    assert res is None, assertmsg

    reffile = os.path.join(CWD, "igmp_single_if_single_group_brief.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip igmp vrf default groups l1-i1-eth1 225.1.1.5 json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "IGMP group output on l1 for interface l1-i1-eth1 and group 225.1.1.5 is not as expected. Expected: {}".format(
        expected
    )
    assert res is None, assertmsg

    reffile = os.path.join(CWD, "igmp_single_if_single_group_detail.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip igmp vrf default groups l1-i1-eth1 225.1.1.5 detail json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "IGMP group detailed output on l1 for interface l1-i1-eth1 and group 225.1.1.5 is not as expected. Expected: {}".format(
        expected
    )
    assert res is None, assertmsg

    reffile = os.path.join(CWD, "igmp_source_single_if_group_all.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip igmp sources l1-i1-eth1 json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "IGMP source output on l1 for interface l1-i1-eth1 is not as expected. Expected: {}".format(
        expected
    )
    assert res is None, assertmsg

    reffile = os.path.join(CWD, "igmp_source_single_if_single_group.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ip igmp sources l1-i1-eth1 225.1.1.4 json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "IGMP source output on l1 for interface l1-i1-eth1 and group 225.1.1.4 is not as expected. Expected: {}".format(
        expected
    )
    assert res is None, assertmsg

    step(
        "Remove igmp 'no ip igmp' and 'no ip igmp version 2' from"
        " receiver interface of FRR1"
    )

    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    intf_l1_i1: {
                        "igmp": {
                            "version": "2",
                            "delete": True,
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("IGMP join removed from FRR1 , verify using " "'show ip igmp groups json'")

    dut = "l1"
    interface = topo["routers"]["l1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: IGMP groups should not be present \n "
        "Found: {}".format(tc_name, dut, result)
    )

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    intf_f1_r2 = topo["routers"]["f1"]["links"]["r2"]["interface"]
    intf_f1_i2 = topo["routers"]["f1"]["links"]["i2"]["interface"]
    input_traffic = {
        "l1": {"traffic_received": [intf_l1_r2], "traffic_sent": [intf_l1_i1]},
        "f1": {"traffic_sent": [intf_f1_r2], "traffic_received": [intf_f1_i2]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Configure igmp 'ip igmp' and 'ip igmp version 2' from "
        "receiver interface of FRR1"
    )

    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    intf_l1_i1: {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "After adding IGMP on receiver interface verify (S,G) and (*,G)"
        " entries got populated and traffic is resumed on FRR1 and FRR3 node"
    )

    step(
        "Verify OIL/IIF and drJoinDesired using 'show ip mroute , and traffic"
        " using show ip pim upstream and show ip multicast'"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Remove igmp 'no ip igmp' and 'no ip igmp version 2' from"
        " receiver interface of FRR1"
    )

    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    intf_l1_i1: {
                        "igmp": {
                            "version": "2",
                            "delete": True,
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("IGMP join removed from FRR1 , verify using " "'show ip igmp groups json'")

    dut = "l1"
    interface = topo["routers"]["l1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: IGMP groups should not be present \n "
        "Found: {}".format(tc_name, dut, result)
    )

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Configure igmp 'ip igmp' and 'ip igmp version 2' from "
        "receiver interface of FRR1"
    )

    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    intf_l1_i1: {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "After adding IGMP on receiver interface verify (S,G) and (*,G)"
        " entries got populated and traffic is resumed on FRR1 and FRR3 node"
    )

    step(
        "Verify OIL/IIF and drJoinDesired using 'show ip mroute , and traffic"
        " using show ip pim upstream and show ip multicast'"
    )

    input_dict_l1_f1 = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i6,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    for data in input_dict_l1_f1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_l1_f1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Remove ip igmp and send igmp prune from FRR1 interface")

    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    intf_l1_i1: {
                        "igmp": {
                            "version": "2",
                            "delete": True,
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)
    step(
        "Verification: After removing igmp 'no ip igmp' and "
        " sending prune verify mroute and upstream got removed"
        " from FRR1 verify using 'show ip mroute' and "
        "'show ip pim upstream'"
    )

    dut = "l1"
    iif = topo["routers"]["l1"]["links"]["i6"]["interface"]
    oil = topo["routers"]["l1"]["links"]["i1"]["interface"]
    source = source_i6
    result = verify_mroutes(
        tgen, dut, source, IGMP_JOIN_RANGE_1, iif, oil, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
        "Found: {}".format(tc_name, dut, result)
    )

    write_test_footer(tc_name)


def test_verify_remove_add_igmp_commands_when_pim_configured_p0(request):
    """
    TC_34: Verify removing and adding IGMP commands when PIM is already
    configured
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Enable PIM on all routers")
    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1-225.1.1.10)")

    input_join = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (226.1.1.1-5) and (232.1.1.1-5) in cisco-1(f1)")

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

    step("Configure source on FRR3 and start the traffic for" " (225.1.1.1-225.1.1.10)")

    input_src = {"i2": topo["routers"]["i2"]["links"]["f1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure source on FRR1 and start the traffic for" " (225.1.1.1-225.1.1.10)")

    input_src = {"i6": topo["routers"]["i6"]["links"]["l1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i6 = topo["routers"]["i6"]["links"]["l1"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i6,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verification: After configuring IGMP related config , "
        "verify config is present in the interface "
        "'show ip igmp interface ensxx json'"
    )

    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    input_dict_1 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    intf_l1_i1: {
                        "igmp": {
                            "version": "2",
                            "query": {
                                "query-max-response-time": 40,
                                "query-interval": 5,
                            },
                        }
                    }
                }
            }
        }
    }

    result = verify_igmp_config(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Remove igmp 'no ip igmp' and 'no ip igmp version 2' from"
        " receiver interface of FRR1"
    )

    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    intf_l1_i1: {
                        "igmp": {
                            "version": "2",
                            "delete": True,
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Verification: After removing the config CLI got removed "
        "'show ip igmp interface ensxx json'"
    )

    result = verify_igmp_config(tgen, input_dict_1, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: IGMP interface should be removed \n "
        "Found: {}".format(tc_name, data["dut"], result)
    )

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure 'ip igmp last-member-query-count 10' on FRR1" " receiver interface")

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {"igmp": {"query": {"last-member-query-count": 5}}}
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Remove 'ip igmp last-member-query-count 10' on FRR1" " receiver interface")

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "query": {"last-member-query-count": "", "delete": True}
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {"igmp": {"query": {"last-member-query-count": 2}}}
                }
            }
        }
    }
    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Configure 'ip igmp last-member-query-interval 20' on FRR1"
        " receiver interface"
    )

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {"query": {"last-member-query-interval": 20}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Remove 'ip igmp last-member-query-count 10' on FRR1" " receiver interface")

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "query": {"last-member-query-interval": "", "delete": True}
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {"query": {"last-member-query-interval": 10}}
                    }
                }
            }
        }
    }
    result = verify_igmp_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_remove_add_pim_commands_when_igmp_configured_p1(request):
    """
    TC_35: Verify removing and adding PIM commands when IGMP is already
    configured
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Configure 'ip pim' on receiver interface on FRR1")
    step("Enable PIM on all routers")
    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1-225.1.1.10)")

    input_join = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (226.1.1.1-5) and (232.1.1.1-5) in cisco-1(f1)")

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

    step("Remove 'no ip pim' on receiver interface on FRR1")

    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_i1), "no ip pim"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure 'ip pim bsm' on receiver interface on FRR1")

    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_i1), "ip pim bsm"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove 'no ip pim bsm' on receiver interface on FRR1")

    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_i1), "no ip pim bsm"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure 'ip pim drpriority' on receiver interface on FRR1")

    raw_config = {
        "l1": {
            "raw_config": ["interface {}".format(intf_l1_i1), "ip pim drpriority 10"]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verification: After configuring PIM related config, "
        "verify config is present in the interface "
        "'show ip pim interface ensxx json'"
    )

    input_dict_dr = {"l1": {"pim": {"interfaces": {intf_l1_i1: {"drPriority": 10}}}}}
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove 'no ip pim drpriority' on receiver interface on FRR1")

    raw_config = {
        "l1": {
            "raw_config": ["interface {}".format(intf_l1_i1), "no ip pim drpriority 10"]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verification: After removing the config CLI got removed "
        "'show ip pim interface ensxx json'"
    )

    input_dict_dr = {"l1": {"pim": {"interfaces": {intf_l1_i1: {"drPriority": 1}}}}}
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure 'ip pim hello' on receiver interface on FRR1")

    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_i1), "ip pim hello 50"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verification: After configuring PIM related config, "
        "verify config is present in the interface "
        "'show ip pim interface ensxx json'"
    )

    input_dict_dr = {"l1": {"pim": {"interfaces": {intf_l1_i1: {"helloPeriod": 50}}}}}
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove 'no ip pim hello' on receiver interface on FRR1")

    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_i1), "no ip pim hello"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verification: After removing the config CLI got removed "
        "'show ip pim interface ensxx json'"
    )

    input_dict_dr = {"l1": {"pim": {"interfaces": {intf_l1_i1: {"helloPeriod": 30}}}}}
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure 'ip pim unicast-bsm' on receiver interface on FRR1")

    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_i1), "ip pim unicast-bsm"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove 'no ip pim hello' on receiver interface on FRR1")

    raw_config = {
        "l1": {
            "raw_config": ["interface {}".format(intf_l1_i1), "no ip pim unicast-bsm"]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_pim_dr_priority_p0(request):
    """
    TC_36: Verify highest DR priority become the PIM DR
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Configure 'ip pim' on receiver interface on FRR1")
    step("Enable PIM on all routers")
    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1-225.1.1.10)")

    input_join = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (226.1.1.1-5) and (232.1.1.1-5) in cisco-1(f1)")

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

    input_src = {"i2": topo["routers"]["i2"]["links"]["f1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure 'ip pim drpriority 10' on receiver interface on FRR1(LHR)")

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    raw_config = {
        "l1": {
            "raw_config": ["interface {}".format(intf_l1_r2), "ip pim drpriority 10"]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "DR config is successful on FRR1 node , verify using "
        " 'show ip pim interface json'"
    )

    input_dict_dr = {"l1": {"pim": {"interfaces": {intf_l1_r2: {"drPriority": 10}}}}}
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure 'ip pim drpriority 20' on receiver interface on FRR3(FHR)")

    intf_f1_r2 = topo["routers"]["f1"]["links"]["r2"]["interface"]
    raw_config = {
        "f1": {
            "raw_config": ["interface {}".format(intf_f1_r2), "ip pim drpriority 20"]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "DR config is successful on FRR3 node , verify using "
        " 'show ip pim interface json'"
    )

    input_dict_dr = {"f1": {"pim": {"interfaces": {intf_f1_r2: {"drPriority": 20}}}}}
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "PIM is enable on FRR1, FRR2 interface and neighbor is up, "
        " verify using 'show ip pim interface'"
    )

    result = verify_pim_interface(tgen, topo, "l1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_pim_interface(tgen, topo, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Highet IP become PIM DR , verify using "
        "'show ip pim interface json' and 'show ip pim neighbor'"
    )
    step("Highest priority become PIM DR")

    dr_address = topo["routers"]["l1"]["links"]["r2"]["ipv4"].split("/")[0]
    input_dict_dr = {
        "l1": {"pim": {"interfaces": {intf_l1_r2: {"drAddress": dr_address}}}}
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    dr_address = topo["routers"]["f1"]["links"]["r2"]["ipv4"].split("/")[0]
    input_dict_dr = {
        "f1": {"pim": {"interfaces": {intf_f1_r2: {"drAddress": dr_address}}}}
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove 'no ip pim drpriority' on receiver interface on FRR1")

    raw_config = {
        "l1": {
            "raw_config": ["interface {}".format(intf_l1_r2), "no ip pim drpriority 10"]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove 'no ip pim drpriority' on receiver interface on FRR3")

    raw_config = {
        "f1": {
            "raw_config": ["interface {}".format(intf_f1_r2), "no ip pim drpriority 20"]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After removing drpriority , config got removed from both the "
        "nodes and highest IP become PIM DR"
    )

    input_dict_dr = {"l1": {"pim": {"interfaces": {intf_l1_r2: {"drPriority": 1}}}}}
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_dr = {"f1": {"pim": {"interfaces": {intf_f1_r2: {"drPriority": 1}}}}}
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    dr_address = topo["routers"]["r2"]["links"]["l1"]["ipv4"].split("/")[0]
    input_dict_dr = {
        "l1": {"pim": {"interfaces": {intf_l1_r2: {"drAddress": dr_address}}}}
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    dr_address = topo["routers"]["r2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_dr = {
        "f1": {"pim": {"interfaces": {intf_f1_r2: {"drAddress": dr_address}}}}
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_pim_hello_timer_p1(request):
    """
    TC_37: Verify PIM hello is sent on configured timer
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step("Configure 'ip pim' on receiver interface on FRR1")
    step("Enable PIM on all routers")
    step("Enable IGMP on FRR1 interface and send IGMP join " "(225.1.1.1-225.1.1.10)")

    input_join = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (226.1.1.1-5) and (232.1.1.1-5) in cisco-1(f1)")

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

    step("Configure PIM hello interval timer 100 on FRR1 node (FRR1-FRR2 link)")

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_r2), "ip pim hello 100"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "PIM hello interval is configured on interface verify using "
        "'show ip pim interface'"
    )

    input_dict_hello = {
        "l1": {"pim": {"interfaces": {intf_l1_r2: {"helloPeriod": 100}}}}
    }
    result = verify_pim_config(tgen, input_dict_hello)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Modify hello timer to 180 and then 50sec")

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_r2), "ip pim hello 180"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "PIM hello interval is configured on interface verify using "
        "'show ip pim interface'"
    )

    input_dict_hello = {
        "l1": {"pim": {"interfaces": {intf_l1_r2: {"helloPeriod": 180}}}}
    }
    result = verify_pim_config(tgen, input_dict_hello)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    raw_config = {
        "l1": {"raw_config": ["interface {}".format(intf_l1_r2), "ip pim hello 50"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "PIM hello interval is configured on interface verify using "
        "'show ip pim interface'"
    )

    input_dict_hello = {
        "l1": {"pim": {"interfaces": {intf_l1_r2: {"helloPeriod": 50}}}}
    }
    result = verify_pim_config(tgen, input_dict_hello)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_mroute_after_removing_RP_sending_IGMP_prune_p2(request):
    """
    TC_39 Verify mroute after removing the RP and sending IGMP prune
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step(
        "Remove cisco connected link to simulate topo "
        "LHR(FRR1(f1))----RP(cisco(f1)---FHR(FRR3(l1))"
    )

    intf_l1_c1 = topo["routers"]["l1"]["links"]["c1"]["interface"]
    intf_f1_c2 = topo["routers"]["f1"]["links"]["c2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_c1, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_c2, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (225.1.1.1-5)"
    )

    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    intf_f1_i8: {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i8": topo["routers"]["i8"]["links"]["f1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (225.1.1.1-5) as R2")

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

    step(
        "Send traffic from FHR to all the groups ( 225.1.1.1 to 225.1.1.5) and send"
        " multicast traffic"
    )

    input_src = {"i6": topo["routers"]["i6"]["links"]["l1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i6"]["links"]["l1"]["ipv4"].split("/")[0]

    input_dict_all = [
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["r2"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": "*",
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove the RP config for both the range from all the nodes")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE,
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_starg = [
        {
            "dut": "f1",
            "src_address": "*",
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        }
    ]

    input_dict_sg = [
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["r2"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
    ]

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send prune from receiver-1 (using ctrl+c) on iperf interface")
    app_helper.stop_all_hosts()

    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_traffic = {"f1": {"traffic_sent": [intf_f1_i8]}}
    traffic_before = verify_multicast_traffic(tgen, input_traffic, return_traffic=True)
    assert isinstance(traffic_before, dict), (
        "Testcase {} : Failed \n traffic_before is not dictionary \n "
        "Error: {}".format(tc_name, result)
    )

    step("IGMP groups are remove from FRR1 node 'show ip igmp groups'")

    dut = "f1"
    result = verify_igmp_groups(
        tgen, dut, intf_f1_i8, IGMP_JOIN_RANGE_1, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: IGMP groups should not present \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step(
        "After receiving the IGMP prune from FRR1 , verify traffic "
        "immediately stopped for this receiver 'show ip multicast'"
    )

    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_traffic = {"f1": {"traffic_sent": [intf_f1_i8]}}
    traffic_after = verify_multicast_traffic(tgen, input_traffic, return_traffic=True)
    assert isinstance(traffic_after, dict), (
        "Testcase {} : Failed \n traffic_after is not dictionary \n "
        "Error: {}".format(tc_name, result)
    )

    result = verify_state_incremented(traffic_before, traffic_after)
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    logger.info("Expected Behaviour: {}".format(result))

    step("Configure static RP for (225.1.1.1-5) as R2 loopback interface")

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

    step("Send IGMP joins again from LHR,check IGMP joins and starg received")

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send traffic from FHR and verify mroute upstream")

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i6"]["links"]["l1"]["ipv4"].split("/")[0]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_prune_sent_to_LHR_and_FHR_when_PIMnbr_down_p2(request):
    """
    TC_38 Verify prune is sent to LHR and FHR when PIM nbr went down
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step(
        "Remove cisco connected link to simulate topo "
        "LHR(FRR1(f1))----RP(cisco(f1)---FHR(FRR3(l1))"
    )

    intf_l1_c1 = topo["routers"]["l1"]["links"]["c1"]["interface"]
    intf_f1_c2 = topo["routers"]["f1"]["links"]["c2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_c1, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_c2, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (225.1.1.1-5)"
    )

    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    intf_f1_i8: {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i8": topo["routers"]["i8"]["links"]["f1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (225.1.1.1-5) as R2")

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

    step(
        "Send traffic from FHR to all the groups ( 225.1.1.1 to 225.1.1.5) and send"
        " multicast traffic"
    )

    input_src = {
        "i6": topo["routers"]["i6"]["links"]["l1"]["interface"],
        "i2": topo["routers"]["i2"]["links"]["f1"]["interface"],
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i6"]["links"]["l1"]["ipv4"].split("/")[0]
    source_i1 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]

    input_dict_all = [
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["r2"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": "*",
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i1,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step("Verify mcast traffic received")
    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_traffic = {"f1": {"traffic_sent": [intf_f1_i8]}}

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the link from LHR to RP from RP node")

    intf_r2_f1 = topo["routers"]["r2"]["links"]["f1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_f1, False)

    step("Verify RP info after Shut the link from LHR to RP from RP node")
    dut = "f1"
    rp_address = "1.0.5.17"
    SOURCE = "Static"
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_starg = [
        {
            "dut": "f1",
            "src_address": "*",
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        }
    ]

    input_dict_sg_i2 = [
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["r2"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
    ]

    input_dict_sg_i1 = [
        {
            "dut": "f1",
            "src_address": source_i1,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        }
    ]

    input_dict_sg_i2_l1 = [
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["r2"]["interface"],
        }
    ]

    step("Verify mroute after Shut the link from LHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    for data in input_dict_sg_i1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify upstream after Shut the link from LHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: Upstream IIF interface {} should not be present\n"
            "Found: {}".format(tc_name, data["dut"], data["iif"], result)
        )

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("No shut the link from LHR to RP from RP node")

    intf_r2_f1 = topo["routers"]["r2"]["links"]["f1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_f1, True)

    step("Verify RP info after No shut the link from LHR to RP from RP node")
    dut = "f1"
    rp_address = "1.0.5.17"
    SOURCE = "Static"
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: RP IIF should be updated as Unknown \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("Verify mroute  after No shut the link from LHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify upstrem after No shut the link from LHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify mcast traffic received after noshut LHR to RP from RP node")

    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_traffic = {"f1": {"traffic_sent": [intf_f1_i8]}}
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the link from FHR to RP from RP node")

    intf_r2_l1 = topo["routers"]["r2"]["links"]["l1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_l1, False)

    step("Verify RP info after Shut the link from FHR to RP from RP node")
    dut = "l1"
    rp_address = "1.0.5.17"
    SOURCE = "Static"
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify mroute after Shut the link from FHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify upstream after Shut the link from FHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i2_l1:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: Upstream IIF interface {} should not be present"
            " after shutting link from RP to FHR \n"
            "Found: {}".format(tc_name, data["dut"], data["iif"], result)
        )

    step(" No shut the link from FHR to RP from RP node")

    intf_r2_l1 = topo["routers"]["r2"]["links"]["l1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_l1, True)

    step("Verify RP info after Noshut the link from FHR to RP from RP node")

    dut = "l1"
    rp_address = "1.0.5.17"
    SOURCE = "Static"
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: RP IIF should be updated as Unknown \n"
        "Found: {}".format(tc_name, dut, result)
    )

    step("Verify mroute after Noshut the link from FHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify mroute after Noshut the link from FHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify mcast traffic received after noshut FHR to RP from RP node")
    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_traffic = {"f1": {"traffic_sent": [intf_f1_i8]}}
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the link from FHR to RP from FHR node")

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_r2, False)

    step("Verify PIM Nbrs after Shut the link from FHR to RP from FHR node")

    step("Verify RP info after Shut the link from FHR to RP from FHR node")
    dut = "l1"
    rp_address = "1.0.5.17"
    SOURCE = "Static"
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify mroute after Shut the link from FHR to RP from FHR node")

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify upstream after Shut the link from FHR to RP from FHR node")
    for data in input_dict_starg:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i2_l1:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: Upstream IIF interface {} should not be present"
            " after shutting link from FHR to RP \n"
            "Found: {}".format(tc_name, data["dut"], data["iif"], result)
        )

    step(" No shut the link from FHR to RP from FHR node")

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_r2, True)

    step("Verify RP info after No Shut the link from FHR to RP from FHR node")
    dut = "l1"
    rp_address = "1.0.5.17"
    SOURCE = "Static"
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: RP IIF should be updated as Unknown \n"
        "Found: {}".format(tc_name, dut, result)
    )

    step("Verify mroute after No Shut the link from FHR to RP from FHR node")

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify upstream after No Shut the link from FHR to RP from FHR node")

    for data in input_dict_starg:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify mcast traffic received after noshut FHR to RP from FHR node")
    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_traffic = {"f1": {"traffic_sent": [intf_f1_i8]}}
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_mroute_flags_p1(request):
    """
    TC_47 Verify mroute flag in LHR and FHR node
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step(
        "Remove cisco connected link to simulate topo "
        "LHR(FRR1(f1))----RP(cisco(f1)---FHR(FRR3(l1))"
    )

    intf_l1_c1 = topo["routers"]["l1"]["links"]["c1"]["interface"]
    intf_f1_c2 = topo["routers"]["f1"]["links"]["c2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_c1, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_c2, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (225.1.1.1-5)"
    )

    intf_f1_i8 = topo["routers"]["f1"]["links"]["i8"]["interface"]
    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    intf_f1_i8: {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i8": topo["routers"]["i8"]["links"]["f1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (225.1.1.1-5) as R2")

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

    step(
        "Send traffic from FHR to all the groups ( 225.1.1.1 to 225.1.1.5) and send"
        " multicast traffic"
    )

    input_src = {
        "i6": topo["routers"]["i6"]["links"]["l1"]["interface"],
        "i2": topo["routers"]["i2"]["links"]["f1"]["interface"],
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i6"]["links"]["l1"]["ipv4"].split("/")[0]
    source_i1 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]

    input_dict_all = [
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": topo["routers"]["l1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["r2"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": "*",
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i1,
            "iif": topo["routers"]["f1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": topo["routers"]["f1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["f1"]["links"]["i8"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    dut = "f1"
    step("verify flag for (*,G) on f1")
    src_address = "*"
    flag = "SC"
    result = verify_multicast_flag_state(
        tgen, dut, src_address, IGMP_JOIN_RANGE_1, flag
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify flag for (S,G) on f1 for Remote spurce ")
    src_address = source_i2
    flag = "ST"
    result = verify_multicast_flag_state(
        tgen, dut, src_address, IGMP_JOIN_RANGE_1, flag
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_multicast_traffic_when_LHR_connected_to_RP_p1(request):
    """
    TC_11: Verify multicast traffic flowing fine, when LHR connected to RP
    Topology used:
    FHR(FRR3(l1))---LHR(FRR1(r2)----RP(FRR2(f1))
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step(
        "Remove FRR3 to cisco connected link to simulate topo "
        "FHR(FRR3(l1))---LHR(FRR1(r2)----RP(FRR2(f1))"
    )

    intf_l1_c1 = topo["routers"]["l1"]["links"]["c1"]["interface"]
    intf_f1_c2 = topo["routers"]["f1"]["links"]["c2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_c1, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_c2, False)

    step("Disable IGMP config from l1")
    input_dict_2 = {
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "version": "2",
                            "delete": True,
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable the PIM on all the interfaces of FRR1, R2 and FRR3" " routers")
    step(
        "Enable IGMP on FRR1(r2) interface and send IGMP join (226.1.1.1-5)"
        " and (232.1.1.1-5)"
    )

    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]
    input_dict = {
        "r2": {
            "igmp": {
                "interfaces": {
                    intf_r2_i3: {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_join = {"i3": topo["routers"]["i3"]["links"]["r2"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, _IGMP_JOIN_RANGE, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (226.1.1.1-5) and (232.1.1.1-5) in (f1)")

    input_dict = {
        "f1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["f1"]["links"]["lo"]["ipv4"].split(
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

    step("Send multicast traffic from FRR3 to 225.1.1.1-225.1.1.10" " receiver")

    input_src = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, _IGMP_JOIN_RANGE, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "'show ip mroute' showing correct RPF and OIF interface for (*,G)"
        " and (S,G) entries on all the nodes"
    )

    source_i1 = topo["routers"]["i1"]["links"]["l1"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": source_i1,
            "iif": topo["routers"]["l1"]["links"]["i1"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["r2"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": topo["routers"]["r2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": source_i1,
            "iif": topo["routers"]["r2"]["links"]["l1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        },
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Multicast traffic is flowing for all the groups verify"
        "using 'show ip multicast'"
    )

    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    intf_r2_l1 = topo["routers"]["r2"]["links"]["l1"]["interface"]
    intf_r2_f1 = topo["routers"]["r2"]["links"]["f1"]["interface"]
    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]
    intf_f1_r2 = topo["routers"]["f1"]["links"]["r2"]["interface"]
    input_traffic = {
        "l1": {"traffic_received": [intf_l1_i1]},
        "r2": {"traffic_received": [intf_r2_l1], "traffic_sent": [intf_r2_i3]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and No shut the receiver port")

    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_i3, False)

    step(
        "Verification: After Shut of receiver port, Verify (*,G) and "
        "(S,G) got removed from LHR node (FRR1) using 'show ip mroute'"
    )

    input_dict_r2 = [
        {
            "dut": "r2",
            "src_address": "*",
            "iif": topo["routers"]["r2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": source_i1,
            "iif": topo["routers"]["r2"]["links"]["l1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        },
    ]

    for data in input_dict_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    shutdown_bringup_interface(tgen, "r2", intf_r2_i3, True)

    step(
        "Verification: After No shut of receiver port , Verify (*,G)"
        " and (S,G) got populated on LHR node (FRR1) using "
        "'show ip mroute' 'show ip pim upstream'"
    )

    for data in input_dict_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_r2:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Multicast traffic is resumed for all the groups verify "
        "using 'show ip multicast'"
    )

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and No shut the source port")

    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, False)

    step(
        "Verification: After Shut of source port, Verify (*,G) and "
        "(S,G) got removed from LHR node (FRR1) using 'show ip mroute'"
    )

    input_dict_l1 = [
        {
            "dut": "l1",
            "src_address": source_i1,
            "iif": topo["routers"]["l1"]["links"]["i1"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["r2"]["interface"],
        }
    ]

    for data in input_dict_l1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, True)

    step(
        "Verification: After No shut of source port , Verify (*,G)"
        " and (S,G) got populated on LHR node (FRR1) using "
        "'show ip mroute' 'show ip pim upstream'"
    )

    for data in input_dict_l1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_l1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Multicast traffic is resumed for all the groups verify "
        "using 'show ip multicast'"
    )

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and No shut of LHR to cisco port from LHR side")

    intf_r2_f1 = topo["routers"]["r2"]["links"]["f1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_f1, False)

    step(
        "Verification: After Shut of source port, Verify (S,G) got "
        "removed from LHR and FHR using 'show ip mroute'"
    )

    input_dict_r2_f1 = [
        {
            "dut": "r2",
            "src_address": "*",
            "iif": topo["routers"]["r2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    for data in input_dict_r2_f1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    shutdown_bringup_interface(tgen, "r2", intf_r2_f1, True)

    step(
        "Verification: After No shut of source port , Verify (*,G)"
        " and (S,G) got populated on LHR node (FRR1) using "
        "'show ip mroute' 'show ip pim upstream'"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Multicast traffic is resumed for all the groups verify "
        "using 'show ip multicast'"
    )

    input_traffic_r2 = {
        "r2": {"traffic_received": [intf_r2_l1], "traffic_sent": [intf_r2_i3]}
    }
    result = verify_multicast_traffic(tgen, input_traffic_r2)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and no shut of FHR to LHR port from FHR side")

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_r2, False)

    step(
        "Verification: After Shut of LHR to FHR port, Verify (S,G)"
        "got removed from LHR 'show ip mroute'"
    )

    dut = "r2"
    src_address = "*"
    iif = topo["routers"]["r2"]["links"]["f1"]["interface"]
    oil = topo["routers"]["r2"]["links"]["i3"]["interface"]

    result = verify_mroutes(tgen, dut, src_address, _IGMP_JOIN_RANGE, iif, oil)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    src_address = source_i1
    iif = topo["routers"]["r2"]["links"]["l1"]["interface"]
    oil = topo["routers"]["r2"]["links"]["i3"]["interface"]

    result = verify_mroutes(
        tgen, dut, src_address, _IGMP_JOIN_RANGE, iif, oil, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
        "Found: {}".format(tc_name, dut, result)
    )

    shutdown_bringup_interface(tgen, "l1", intf_l1_r2, True)

    step(
        "Verification: After No shut of source port , Verify (*,G)"
        " and (S,G) got populated on LHR node (FRR1) using "
        "'show ip mroute' 'show ip pim upstream'"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Multicast traffic is resumed for all the groups verify "
        "using 'show ip multicast'"
    )

    result = verify_multicast_traffic(tgen, input_traffic_r2)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_multicast_traffic_when_FHR_connected_to_RP_p1(request):
    """
    TC_12: Verify multicast traffic is flowing fine when FHR is connected to RP
    Topology used:
    LHR(FRR1)---FHR(FRR3)----RP(FRR2)
    """

    tgen = get_topogen()
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
    check_router_status(tgen)

    step(
        "Remove FRR3 to FRR2 connected link to simulate topo "
        "FHR(FRR3)---LHR(FRR1)----RP(FFR2)"
    )

    intf_l1_c1 = topo["routers"]["l1"]["links"]["c1"]["interface"]
    intf_f1_c2 = topo["routers"]["f1"]["links"]["c2"]["interface"]
    shutdown_bringup_interface(tgen, "l1", intf_l1_c1, False)
    shutdown_bringup_interface(tgen, "f1", intf_f1_c2, False)

    step("Enable the PIM on all the interfaces of FRR1, R2 and FRR3" " routers")
    step("Enable IGMP on FRR1(l1) interface and send IGMP join " " and (225.1.1.1-5)")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_join = {"i1": topo["routers"]["i1"]["links"]["l1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, _IGMP_JOIN_RANGE, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (225.1.1.1-5) in (f1)")

    input_dict = {
        "f1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["f1"]["links"]["lo"]["ipv4"].split(
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

    step("Send multicast traffic from FRR3(r2) to 225.1.1.1-225.1.1.10" " receiver")

    input_src = {"i3": topo["routers"]["i3"]["links"]["r2"]["interface"]}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, _IGMP_JOIN_RANGE, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "'show ip mroute' showing correct RPF and OIF interface for (*,G)"
        " and (S,G) entries on all the nodes"
    )

    source_i3 = topo["routers"]["i3"]["links"]["r2"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": "*",
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "l1",
            "src_address": source_i3,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": topo["routers"]["r2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": source_i3,
            "iif": topo["routers"]["r2"]["links"]["i3"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["interface"]
    intf_f1_r2 = topo["routers"]["f1"]["links"]["r2"]["interface"]
    intf_l1_i1 = topo["routers"]["l1"]["links"]["i1"]["interface"]
    input_traffic = {
        "l1": {"traffic_received": [intf_l1_r2], "traffic_sent": [intf_l1_i1]}
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the receiver(l1) port in 1 min interval")

    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, False)

    step(
        "Verification: After Shut of receiver port, Verify (*,G) and "
        "(S,G) got removed from LHR node (FRR1) using 'show ip mroute'"
    )

    input_dict_l1 = [
        {
            "dut": "l1",
            "src_address": source_i3,
            "iif": topo["routers"]["l1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["l1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_l1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    step("No shut the receiver(l1) port in 1 min interval")

    shutdown_bringup_interface(tgen, "l1", intf_l1_i1, True)

    step(
        "Verification: After No shut of receiver port , Verify (*,G)"
        " and (S,G) got populated on LHR node (FRR1) using "
        "'show ip mroute' 'show ip pim upstream'"
    )

    for data in input_dict_l1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_l1:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the source(r2) port in 1 min interval")

    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_i3, False)

    step(
        "Verification: After Shut of source port, Verify (S,G) got "
        "removed from FHR using 'show ip mroute'"
    )

    input_dict_r2 = [
        {
            "dut": "r2",
            "src_address": source_i3,
            "iif": topo["routers"]["r2"]["links"]["i3"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        }
    ]

    for data in input_dict_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    step("No shut the source(r2) port in 1 min interval")

    shutdown_bringup_interface(tgen, "r2", intf_r2_i3, True)

    step(
        "Verification: After No shut of source port , Verify (*,G)"
        " and (S,G) got populated on LHR and FHR using "
        "'show ip mroute' 'show ip pim upstream'"
    )

    for data in input_dict_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_r2:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut FHR to RP port from FHR side")

    intf_r2_f1 = topo["routers"]["r2"]["links"]["f1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_f1, False)

    step(
        "Verification: After Shut of FHR to cisco port, Verify (*,G) "
        "got removed from FHR and cisco node using 'show ip mroute'"
    )

    input_dict_all_star = [
        {
            "dut": "r2",
            "src_address": "*",
            "iif": topo["routers"]["r2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["l1"]["interface"],
        },
        {
            "dut": "f1",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["f1"]["links"]["r2"]["interface"],
        },
    ]

    for data in input_dict_all_star:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    write_test_footer(tc_name)


def test_PIM_passive_p1(request):
    """
    TC Verify PIM passive functionality"
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    app_helper.stop_all_hosts()
    # Creating configuration from JSON
    clear_mroute(tgen)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (225.1.1.1-5)"
    )

    intf_c1_i4 = topo["routers"]["c1"]["links"]["i4"]["interface"]

    step(
        "configure PIM passive on receiver interface to verify no impact on IGMP join"
        "and multicast traffic on pim passive interface"
    )

    raw_config = {
        "c1": {"raw_config": ["interface {}".format(intf_c1_i4), "ip pim passive"]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("configure IGMPv2 and send IGMP joinon on PIM passive interface")
    input_dict = {
        "c1": {"igmp": {"interfaces": {intf_c1_i4: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i4": topo["routers"]["i4"]["links"]["c1"]["interface"]}
    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (225.1.1.1-5) as R2")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
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

    step("Send Mcast traffic from C2 to all the groups ( 225.1.1.1 to 225.1.1.5)")

    input_src = {"i5": topo["routers"]["i5"]["links"]["c2"]["interface"]}
    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i5 = topo["routers"]["i5"]["links"]["c2"]["ipv4"].split("/")[0]

    input_dict_starg = [
        {
            "dut": "c1",
            "src_address": "*",
            "iif": topo["routers"]["c1"]["links"]["l1"]["interface"],
            "oil": topo["routers"]["c1"]["links"]["i4"]["interface"],
        }
    ]

    input_dict_sg = [
        {
            "dut": "c1",
            "src_address": source_i5,
            "iif": topo["routers"]["c1"]["links"]["c2"]["interface"],
            "oil": topo["routers"]["c1"]["links"]["i4"]["interface"],
        }
    ]

    step("(*,G) and (S,G) created on f1 and node verify using 'show ip mroute'")

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    intf_c1_c2 = topo["routers"]["c1"]["links"]["c2"]["interface"]
    intf_c2_c1 = topo["routers"]["c2"]["links"]["c1"]["interface"]

    step(
        "configure PIM passive on upstream interface to verify"
        "hello tx/rx counts are not incremented"
    )

    # Changing hello timer to 3sec for checking more number of packets

    raw_config = {
        "c1": {
            "raw_config": [
                "interface {}".format(intf_c1_c2),
                "ip pim passive",
                "ip pim hello 3",
            ]
        },
        "c2": {"raw_config": ["interface {}".format(intf_c2_c1), "ip pim hello 3"]},
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify PIM hello tx/rx stats on C1")
    state_dict = {
        "c1": {
            intf_c1_c2: ["helloTx", "helloRx"],
        }
    }

    logger.info("waiting for 5 sec config to get apply and hello count update")
    sleep(5)

    c1_state_before = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        c1_state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    logger.info(
        "sleeping for 30 sec hello interval timer to verify count are not increamented"
    )
    sleep(35)

    c1_state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        c1_state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("verify stats not increamented on c1")
    result = verify_pim_stats_increament(c1_state_before, c1_state_after)
    assert (
        result is not True
    ), "Testcase{} : Failed Error: {}" "stats incremented".format(tc_name, result)

    step("No impact observed on mroutes")
    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("remove PIM passive and verify hello tx/rx is increamented")
    raw_config = {
        "c1": {
            "raw_config": [
                "interface {}".format(intf_c1_c2),
                "no ip pim passive",
                "ip pim hello 3",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    logger.info("waiting for 30 sec for pim hello to receive")
    sleep(30)

    c1_state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        c1_state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("verify stats increamented on c1 after removing pim passive")
    result = verify_pim_stats_increament(c1_state_before, c1_state_after)
    assert result is True, "Testcase{} : Failed Error: {}" "stats incremented".format(
        tc_name, result
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
