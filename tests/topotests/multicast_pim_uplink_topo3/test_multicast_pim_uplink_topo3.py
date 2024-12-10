#!/usr/bin/env python3
#
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2023 by VMware, Inc. ("VMware")
#

"""
Following tests are covered to test multicast pim sm:

1. TC:1 Verify static IGMP group populated when static "ip igmp join <grp>" in configured
2. TC:2 Verify mroute and upstream populated with correct OIL/IIF with static igmp join
3. TC:3 Verify local IGMP join not allowed for "224.0.0.0/24" and non multicast group
4. TC:4 Verify static IGMP group removed from DUT while removing "ip igmp join" CLI
5. TC:5 Verify static IGMP groups after removing and adding IGMP config
"""

import os
import sys
import time
import pytest

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
    addKernelRoute,
    reset_config_on_routers,
    shutdown_bringup_interface,
    required_linux_kernel_version,
)
from lib.pim import (
    create_pim_config,
    create_igmp_config,
    verify_igmp_groups,
    verify_mroutes,
    clear_pim_interface_traffic,
    verify_upstream_iif,
    clear_mroute,
    verify_pim_rp_info,
    verify_local_igmp_groups,
    McastTesterHelper,
)
from lib.bgp import (
    verify_bgp_convergence,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

# Global variables
TOPOLOGY = """

        i9         i3-+-i4      i6-+-i7
        |              |           |
        i1--- R1-------R2----------R4------R5---i8
        |    |                    |
        i2   R3-------------------+
             +
             |
             i5

    Description:
    i1, i2, i3. i4, i5, i6, i7, i8 - FRR running iperf to send IGMP
                                     join and traffic
    R1 - DUT (LHR/FHR)
    R2 - RP
    R3 - Transit
    R4 - (LHR/FHR)
    R5 - Transit
"""
# Global variables
RP_RANGE1 = "226.0.0.1/32"
RP_RANGE2 = "226.0.0.2/32"
RP_RANGE3 = "226.0.0.3/32"
RP_RANGE4 = "226.0.0.4/32"
RP_RANGE5 = "226.0.0.5/32"
RP_RANGE6 = "232.0.0.1/32"
RP_RANGE7 = "232.0.0.2/32"
RP_RANGE8 = "232.0.0.3/32"
RP_RANGE9 = "232.0.0.4/32"
RP_RANGE10 = "232.0.0.5/32"

GROUP_RANGE = "224.0.0.0/4"
IGMP_GROUP = "225.1.1.1/32"
IGMP_JOIN = "225.1.1.1"
GROUP_RANGE_1 = [
    "225.1.1.1/32",
    "225.1.1.2/32",
    "225.1.1.3/32",
    "225.1.1.4/32",
    "225.1.1.5/32",
]
IGMP_JOIN_RANGE_1 = ["225.1.1.1", "225.1.1.2", "225.1.1.3", "225.1.1.4", "225.1.1.5"]
IGMP_JOIN_RANGE_2 = ["224.0.0.1", "224.0.0.2", "224.0.0.3", "192.0.0.4", "192.0.0.5"]
IGMP_JOIN_RANGE_3 = [
    "226.0.0.1",
    "226.0.0.2",
    "226.0.0.3",
    "226.0.0.4",
    "226.0.0.5",
    "232.0.0.1",
    "232.0.0.2",
    "232.0.0.3",
    "232.0.0.4",
    "232.0.0.5",
]
GROUP_RANGE_3 = [
    "226.0.0.1/32",
    "226.0.0.2/32",
    "226.0.0.3/32",
    "226.0.0.4/32",
    "226.0.0.5/32",
    "232.0.0.1/32",
    "232.0.0.2/32",
    "232.0.0.3/32",
    "232.0.0.4/32",
    "232.0.0.5/32",
]

r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r2_r4_links = []
r3_r1_links = []
r3_r4_links = []
r4_r2_links = []
r4_r3_links = []

pytestmark = [pytest.mark.pimd]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/multicast_pim_uplink_topo3.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, tgen.json_topo)

    # Pre-requisite data
    get_interfaces_names(topo)

    # XXX Replace this using "with McastTesterHelper()... " in each test if possible.
    global app_helper
    app_helper = McastTesterHelper(tgen)

    # Verify BGP convergence
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error:" " {}".format(
        BGP_CONVERGENCE
    )

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
#   Local APIs
#
#####################################################


def get_interfaces_names(topo):
    """
    API to fetch interfaces names and create list, which further would be used
    for verification

    Parameters
    ----------
    * `topo` : inout JSON data
    """

    for link in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(link)]["interface"]
        r1_r2_links.append(intf)

        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(link)]["interface"]
        r1_r3_links.append(intf)

        intf = topo["routers"]["r2"]["links"]["r1-link{}".format(link)]["interface"]
        r2_r1_links.append(intf)

        intf = topo["routers"]["r3"]["links"]["r1-link{}".format(link)]["interface"]
        r3_r1_links.append(intf)

        intf = topo["routers"]["r2"]["links"]["r4-link{}".format(link)]["interface"]
        r2_r4_links.append(intf)

        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(link)]["interface"]
        r4_r2_links.append(intf)

        intf = topo["routers"]["r4"]["links"]["r3-link{}".format(link)]["interface"]
        r4_r3_links.append(intf)


def shutdown_interfaces(tgen):
    """
     API to Shut down interfaces which is not
     used in all the testcases as part of this TDS

    Parameters
    ----------
    * `tgen`: topogen object

    """
    logger.info("shutting down extra interfaces")
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r1_r5 = topo["routers"]["r1"]["links"]["r5"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]
    intf_r5_r1 = topo["routers"]["r5"]["links"]["r1"]["interface"]
    intf_r4_r5 = topo["routers"]["r4"]["links"]["r5"]["interface"]
    intf_r5_r4 = topo["routers"]["r5"]["links"]["r4"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r1", intf_r1_r5, False)
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, False)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r1, False)
    shutdown_bringup_interface(tgen, "r4", intf_r4_r5, False)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r4, False)


def config_to_send_igmp_join_and_traffic(
    tgen, topo, tc_name, iperf, iperf_intf, GROUP_RANGE, join=False, traffic=False
):
    """
    API to do pre-configuration to send IGMP join and multicast
    traffic

    parameters:
    -----------
    * `tgen`: topogen object
    * `topo`: input json data
    * `tc_name`: caller test case name
    * `iperf`: router running iperf
    * `iperf_intf`: interface name router running iperf
    * `GROUP_RANGE`: group range
    * `join`: IGMP join, default False
    * `traffic`: multicast traffic, default False
    """

    if join:
        # Add route to kernal
        result = addKernelRoute(tgen, iperf, iperf_intf, GROUP_RANGE)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    if traffic:
        # Add route to kernal
        result = addKernelRoute(tgen, iperf, iperf_intf, GROUP_RANGE)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        router_list = tgen.routers()
        for router in router_list.keys():
            if router == iperf:
                continue

            rnode = router_list[router]
            rnode.run("echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter")

    return True


#####################################################
#
#   Testcases
#
#####################################################


def test_ip_igmp_local_joins_p0(request):
    """
    TC_1 Verify static IGMP group populated when static
    "ip igmp join <grp>" in configured
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("shut down not required interfaces")
    shutdown_interfaces(tgen)

    step("Enable the PIM on all the interfaces of R1, R2, R3, R4")
    step("configure BGP on R1, R2, R3, R4 and enable redistribute static/connected")
    step("Enable the IGMP on R11 interfac of R1 and configure local igmp groups")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {"igmp": {"version": "2", "join": IGMP_JOIN_RANGE_1}},
                    intf_r1_i2: {"igmp": {"version": "2", "join": IGMP_JOIN_RANGE_1}},
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
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

    step("verify static igmp join using show ip igmp join")
    dut = "r1"
    interfaces = [intf_r1_i1, intf_r1_i2]
    for interface in interfaces:
        result = verify_local_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify igmp groups using show ip igmp groups")
    interfaces = [intf_r1_i1, intf_r1_i2]
    for interface in interfaces:
        result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_mroute_with_igmp_local_joins_p0(request):
    """
    TC_2 Verify mroute and upstream populated with correct OIL/IIF with
     static igmp join
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("shut down not required interfaces")
    shutdown_interfaces(tgen)

    step("Enable the PIM on all the interfaces of R1, R2, R3, R4")
    step("configure BGP on R1, R2, R3, R4 and enable redistribute static/connected")
    step("Enable the IGMP on R11 interfac of R1 and configure local igmp groups")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {"igmp": {"version": "2", "join": IGMP_JOIN_RANGE_1}},
                    intf_r1_i2: {"igmp": {"version": "2", "join": IGMP_JOIN_RANGE_1}},
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
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

    step("verify static igmp join using show ip igmp join")
    dut = "r1"
    interfaces = [intf_r1_i1, intf_r1_i2]
    for interface in interfaces:
        result = verify_local_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify igmp groups using show ip igmp groups")
    interfaces = [intf_r1_i1, intf_r1_i2]
    for interface in interfaces:
        result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify RP-info populated in DUT")
    dut = "r1"
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv4"].split("/")[0]
    SOURCE = "Static"
    oif = r1_r2_links
    result = verify_pim_rp_info(tgen, topo, dut, GROUP_RANGE_1, oif, rp_address, SOURCE)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Send traffic from R4 to all the groups ( 225.1.1.1 to 225.1.1.5)")

    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]

    r1_r2_r3 = r1_r2_links + r1_r3_links
    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_r3,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        },
    ]

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_r3,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_r3,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream for local igmp groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
            result = verify_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("Verify mroutes not created with local interface ip ")

    input_dict_local_sg = [
        {
            "dut": "r1",
            "src_address": intf_r1_i1,
            "iif": r1_r2_r3,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": intf_r1_i2,
            "iif": r1_r2_r3,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        },
    ]

    for data in input_dict_local_sg:
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
            "Testcase {} : Failed Error: {}"
            "sg created with local interface ip".format(tc_name, result)
        )

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed Error: {}"
            "upstream created with local interface ip".format(tc_name, result)
        )

    write_test_footer(tc_name)


def test_igmp_local_join_with_reserved_address_p0(request):
    """
    TC_3 Verify local IGMP join not allowed for "224.0.0.0/24"
    and non multicast group
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("shut down not required interfaces")
    shutdown_interfaces(tgen)

    step("Enable the PIM on all the interfaces of R1, R2, R3, R4")
    step("configure BGP on R1, R2, R3, R4 and enable redistribute static/connected")
    step("Enable the IGMP on R11 interface of R1 and configure local igmp groups")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {"igmp": {"version": "2", "join": IGMP_JOIN_RANGE_2}}
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify static igmp join using show ip igmp join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_igmp_groups(
        tgen, dut, interface, IGMP_JOIN_RANGE_1, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} :Failed \n Error: {}" "IGMP join still present".format(
        tc_name, result
    )

    step("verify igmp groups using show ip igmp groups")
    interface = intf_r1_i1
    result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1, expected=False)
    assert (
        result is not True
    ), "Testcase {} :Failed \n Error: {}" "IGMP groups still present".format(
        tc_name, result
    )

    write_test_footer(tc_name)


def test_remove_add_igmp_local_joins_p1(request):
    """
    TC_4 Verify static IGMP group removed from DUT while
     removing "ip igmp join" CLI
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("shut down not required interfaces")
    shutdown_interfaces(tgen)

    step("Enable the PIM on all the interfaces of R1, R2, R3, R4")
    step("configure BGP on R1, R2, R3, R4 and enable redistribute static/connected")
    step("Enable the IGMP on R11 interfac of R1 and configure local igmp groups")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {"igmp": {"version": "2", "join": IGMP_JOIN_RANGE_1}}
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
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

    step("verify static igmp join using show ip igmp join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify igmp groups using show ip igmp groups")

    interface = intf_r1_i1
    result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify RP-info populated in DUT")
    dut = "r1"
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv4"].split("/")[0]
    SOURCE = "Static"
    oif = r1_r2_links
    result = verify_pim_rp_info(tgen, topo, dut, GROUP_RANGE_1, oif, rp_address, SOURCE)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Send traffic from R4 to all the groups ( 225.1.1.1 to 225.1.1.5)")

    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]

    logger.info("waiting 30 sec for SPT switchover")

    r1_r2_r3 = r1_r2_links + r1_r3_links
    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_r3,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_r3,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    step("Verify mroutes and iff upstream for local igmp groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
            result = verify_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("Remove IGMP join from DUT")
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "join": IGMP_JOIN_RANGE_1,
                            "delete_attr": True,
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify static igmp join removed using show ip igmp join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_igmp_groups(
        tgen, dut, interface, IGMP_JOIN_RANGE_1, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} :Failed \n Error: {}" "IGMP join still present".format(
        tc_name, result
    )

    step("verify igmp groups removed using show ip igmp groups")
    interface = intf_r1_i1
    result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1, expected=False)
    assert (
        result is not True
    ), "Testcase {} :Failed \n Error: {}" "IGMP groups still present".format(
        tc_name, result
    )

    step("Verify mroutes and iff upstream for local igmp groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
            result = verify_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert (
                result is not True
            ), "Testcase {} : Failed Error: {}" "mroutes still present".format(
                tc_name, result
            )

            result = verify_upstream_iif(
                tgen,
                data["dut"],
                data["iif"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                expected=False,
            )
            assert (
                result is not True
            ), "Testcase {} : Failed Error: {}" "mroutes still present".format(
                tc_name, result
            )

    step("Add IGMP join on DUT again")
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "join": IGMP_JOIN_RANGE_1,
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify static igmp join using show ip igmp join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify igmp groups using show ip igmp groups")

    interface = intf_r1_i1
    result = verify_igmp_groups(tgen, dut, interface, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify mroutes and iff upstream for local igmp groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
            result = verify_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
