#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test multicast pim uplink:

1. Verify mroutes OIL and IIF updated correctly when receivers present inside
    and outside of DUT
2. Verify mroutes OIL and IIF updated correctly when source present inside
    and outside of DUT
3. Verify Mroutes and BSM forwarding when edge is transit node
4. Verify mroutes updated correctly after source interface shut/no shut
5. Verify mroutes updated correctly after receiver interface shut/no shut
6. Verify mroute updated correctly after sending IGMP prune and join
7. Verify mroute updated correctly after clear mroute
8. Verify (*,G) mroute entries after changing the RP configuration
9. Verify mroute entries after FRR service stop and start
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
    reset_config_on_routers,
    shutdown_bringup_interface,
    start_router,
    stop_router,
    create_static_routes,
    required_linux_kernel_version,
)
from lib.bgp import (
    create_router_bgp,
    verify_bgp_convergence,
)
from lib.pim import (
    create_pim_config,
    create_igmp_config,
    verify_igmp_groups,
    verify_mroutes,
    clear_pim_interface_traffic,
    verify_upstream_iif,
    clear_mroute,
    verify_multicast_traffic,
    verify_pim_rp_info,
    verify_pim_interface_traffic,
    verify_pim_state,
    McastTesterHelper,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

# Global variables
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

r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r3_r1_links = []
r2_r4_links = []
r4_r2_links = []
r4_r3_links = []
HELLO_TIMER = 1
HOLD_TIMER = 3

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
    json_file = "{}/multicast_pim_uplink_topo1.json".format(testdir)
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


def configure_static_routes_for_rp_reachability(tgen, topo):
    """
    API to configure static routes for rp reachability

    Parameters
    ----------
    * `topo` : inout JSON data
    """

    for i in range(1, 5):
        static_routes = {
            "r1": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["r2"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv4"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv4"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r2"]["links"][
                            "r1-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r3"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv4"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv4"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r3"]["links"][
                            "r1-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["i6"]["links"]["r4"]["ipv4"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv4"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv4"],
                            topo["routers"]["r3"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r4"]["links"][
                            "r2-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r1"]["links"]["lo"]["ipv4"],
                            topo["routers"]["r3"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv4"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r1"]["links"][
                            "r2-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                ]
            },
            "r3": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["r4"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv4"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv4"],
                            topo["routers"]["r2"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r4"]["links"][
                            "r3-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r1"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv4"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv4"],
                            topo["routers"]["r2"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r1"]["links"][
                            "r3-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["r3"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv4"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv4"],
                            topo["routers"]["r1"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r3"]["links"][
                            "r4-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r2"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv4"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv4"],
                            topo["routers"]["r1"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r2"]["links"][
                            "r4-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                ]
            },
        }

        result = create_static_routes(tgen, static_routes)
        assert result is True, "API {} : Failed Error: {}".format(
            sys._getframe().f_code.co_name, result
        )


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
            if state_before[router][state] > state_after[router][state]:
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


def test_mroutes_updated_with_correct_oil_iif_when_receiver_is_in_and_outside_DUT_p0(
    request,
):
    """
    Verify mroutes OIL and IIF updated correctly when receivers present inside
    and outside of DUT
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 225.1.1.1-5")

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

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 225.1.1.1-5")

    input_src = {"i6": topo["routers"]["i6"]["links"]["r4"]["interface"]}

    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "IGMP groups are received on DUT and R4 verify using 'show ip igmp groups'"
        " and 'show ip igmp groups json'"
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    result = verify_igmp_groups(tgen, "r4", intf_r4_i7, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    input_dict_star_sg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_star_sg:
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
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Random shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step(
        "After shut of upstream interface from DUT verify mroutes has moved "
        "to another interface (R2 or R3) and updated with correct OIL/IIF using"
        " 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step("Random no shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    step(
        "After no shut of upstream interface from DUT verify no change on"
        "mroute using 'show ip mroute json'; 'show ip upstream json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step("Shut of upstream interface in alternate fashion from R4 side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    step(
        "After shut of upstream interface from R4 verify mroutes has moved "
        "to another interface (R2 or R3) and updated with correct OIL/IIF using"
        " 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step("No shut of upstream interface in alternate fashion from R4 side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, True)

    step(
        "After no shut of upstream interface from DUT verify no change on"
        "mroute using 'show ip mroute json'; 'show ip upstream json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step(
        "Send different IGMP joins from DUT and R4 for group range (From DUT "
        "225.1.1.1-5 and from R4 226.1.1.1-5)"
    )

    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_2, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send traffic for all the groups from R4")

    input_src = {"i6": topo["routers"]["i6"]["links"]["r4"]["interface"]}
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1 + IGMP_JOIN_RANGE_2, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "IGMP groups are received on DUT and R4 verify using 'show ip igmp groups'"
        " and 'show ip igmp groups json'"
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    result = verify_igmp_groups(
        tgen, "r4", intf_r4_i7, IGMP_JOIN_RANGE_1 + IGMP_JOIN_RANGE_2
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] != "*":
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

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Random shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step(
        "After shut of upstream interface from DUT verify mroutes has moved "
        "to another interface (R2 or R3) and updated with correct OIL/IIF using"
        " 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step("Random no shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    step(
        "After no shut of upstream interface from DUT verify no change on"
        "mroute using 'show ip mroute json'; 'show ip upstream json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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


def test_mroutes_updated_with_correct_oil_iif_when_source_is_in_and_outside_DUT_p0(
    request,
):
    """
    Verify mroutes OIL and IIF updated correctly when source present inside
    and outside of DUT
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 225.1.1.1-5")

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

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 225.1.1.1-5")

    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "IGMP groups are received on DUT and R4 verify using 'show ip igmp groups'"
        " and 'show ip igmp groups json'"
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    result = verify_igmp_groups(tgen, "r4", intf_r4_i7, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    input_dict_star_sg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_star_sg:
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
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Random shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step(
        "After shut of upstream interface from DUT verify mroutes has moved "
        "to another interface (R2 or R3) and updated with correct OIL/IIF using"
        " 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step("Random no shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    step(
        "After no shut of upstream interface from DUT verify no change on"
        "mroute using 'show ip mroute json'; 'show ip upstream json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step("Random shut of upstream interface from R4 side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    step(
        "After shut of upstream interface from R4 verify mroutes has moved "
        "to another interface (R2 or R3) and updated with correct OIL/IIF using"
        " 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step("Random no shut of upstream interface from R4 side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, True)

    step(
        "After no shut of upstream interface from DUT verify no change on"
        "mroute using 'show ip mroute json'; 'show ip upstream json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step(
        "Send different IGMP joins from DUT and R4 for group range (From DUT "
        "225.1.1.1-5 and from R4 226.1.1.1-5)"
    )

    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_2, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send traffic for all the groups from R4")

    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1 + IGMP_JOIN_RANGE_2, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "IGMP groups are received on DUT and R4 verify using 'show ip igmp groups'"
        " and 'show ip igmp groups json'"
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    result = verify_igmp_groups(
        tgen, "r4", intf_r4_i7, IGMP_JOIN_RANGE_1 + IGMP_JOIN_RANGE_2
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] != "*":
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

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Random shut and no shut of upstream interface from DUT side")

    step("Random shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step(
        "After shut of upstream interface from DUT verify mroutes has moved "
        "to another interface (R2 or R3) and updated with correct OIL/IIF using"
        " 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step("Random no shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    step(
        "After no shut of upstream interface from DUT verify no change on"
        "mroute using 'show ip mroute json'; 'show ip upstream json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    write_test_footer(tc_name)


def test_verify_mroutes_forwarding_p0(request):
    """
    Verify Mroutes and BSM forwarding when edge is transit node
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

    step("To make DUT as transit node , shut all the links from R3 to R4 nodes")
    for i in range(1, 5):
        intf = topo["routers"]["r3"]["links"]["r4-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r3", intf, False)

        intf = topo["routers"]["r4"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    step("Enable IGMP on DUT and R3 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r3_i5 = topo["routers"]["r3"]["links"]["i5"]["interface"]
    for dut, intf in zip(["r1", "r3"], [intf_r1_i1, intf_r3_i5]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 226.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i5": topo["routers"]["i5"]["links"]["r3"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_2, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 226.1.1.1-5")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_2,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 226.1.1.1-5")

    input_src = {
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"],
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"],
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_2, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "BSR and candidate RP info populated in R3 node verify using "
        "'show ip pim rp-info json'"
    )

    rp_addr_r2 = topo["routers"]["r2"]["links"]["lo"]["ipv4"].split("/")[0]

    result = verify_pim_rp_info(
        tgen, topo, "r2", GROUP_RANGE_2, "lo", rp_addr_r2, "Static"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    step(
        "DUT created (*,G) and (S,G) entries as transit node for 226.1.1.1-5 "
        "mroutes , OIL is local received and toward R3"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict_star_sg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": r1_r3_links + [topo["routers"]["r1"]["links"]["i1"]["interface"]],
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r3_links + [topo["routers"]["r1"]["links"]["i1"]["interface"]],
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": r1_r3_links + [topo["routers"]["r1"]["links"]["i1"]["interface"]],
        },
        {
            "dut": "r3",
            "src_address": "*",
            "iif": r3_r1_links,
            "oil": topo["routers"]["r3"]["links"]["i5"]["interface"],
        },
        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": r3_r1_links,
            "oil": topo["routers"]["r3"]["links"]["i5"]["interface"],
        },
        {
            "dut": "r3",
            "src_address": source_i6,
            "iif": r3_r1_links,
            "oil": topo["routers"]["r3"]["links"]["i5"]["interface"],
        },
    ]

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r3_i5 = topo["routers"]["r3"]["links"]["i5"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r3": {"traffic_sent": [intf_r3_i5]},
        "r1": {"traffic_sent": [intf_r1_i2]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Send different join from R3 (232.1.1.1-5) and traffic "
        "from R4 for same range"
    )

    input_join = {"i5": topo["routers"]["i5"]["links"]["r3"]["interface"]}
    result = app_helper.run_join("i5", IGMP_JOIN_RANGE_3, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_src = {"i6": topo["routers"]["i6"]["links"]["r4"]["interface"]}
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_3, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("For different join (232.1.1.1-5) DUT created mroute OIL toward R3 only")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    input_dict_sg = [
        {"dut": "r1", "src_address": "*", "iif": r1_r2_links, "oil": r1_r3_links},
        {"dut": "r1", "src_address": source_i6, "iif": r1_r2_links, "oil": r1_r3_links},
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_3,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_3
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut from DUT to R2 and no shut from DUT")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step(
        "After Shut (R1-R2) link from DUT, verify IIF on DUT changed to "
        "different uplink interface on DUT 'show ip mroute json' for R4 so "
        "connected urce"
    )

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r3_links + [topo["routers"]["r1"]["links"]["i1"]["interface"]],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Traffic is received fine for R4 source 'show ip multicast json' on DUT")

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("No shut from DUT to R2 and no shut from DUT")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and no shut DUT to R2 within 30 sec from DUT")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    step(
        "Shut and No shut in 30 sec time , verify on R2 added 2 entries in mroute "
        ", shut link OIL got timeout after sometime"
    )

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_2
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_mroutes_updated_correctly_after_source_interface_shut_noshut_p1(request):
    """
    Verify mroutes updated correctly after source interface shut/no shut
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 225.1.1.1-5")

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

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 225.1.1.1-5")
    step("Send traffic from DUT for group range 225.1.1.1-5")

    input_src = {
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"],
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"],
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
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
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r3_links + [topo["routers"]["r1"]["links"]["i1"]["interface"]],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

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

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("On R1 for local IGMP receivers, OIL towards RP is removed")

    input_dict = [
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        }
    ]

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
        ), "Testcase {} : Failed " "Mroute IIF and OIF are same \n Error: {}".format(
            tc_name, result
        )

    step("Shut and No shut source interface multiple time")

    for _ in range(0, 2):
        step("Shut and no shut the source interface from DUT")
        intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf_r1_i2, False)
        shutdown_bringup_interface(tgen, "r1", intf_r1_i2, True)

        step(
            "After shut/no shut of source interface verify all the (S,G) "
            "got re-learn and IIF/OIF pointing any of the links from R2 or "
            "R3 verify using 'show ip mroute json'"
        )

        step(
            "(S,G) OIL on R1 has only respective receiver port and uplink port "
            " , RP side oil is removed"
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
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

        step("No change seen on (*,G) mroutes")

        for data in input_dict_starg:
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

        step(
            "Traffic is received for all the groups , verify using "
            "'show ip multicast count json'"
        )

        result = verify_multicast_traffic(tgen, input_traffic)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        step("Shut and no shut the source interface from R4")

        intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf_r4_i6, False)
        shutdown_bringup_interface(tgen, "r4", intf_r4_i6, True)

        step(
            "After shut/no shut of source interface verify all the (S,G) "
            "got re-learn and IIF/OIF pointing any of the links from R2 or "
            "R3 verify using 'show ip mroute json'"
        )

        step(
            "(S,G) OIL on R1 has only respective receiver port and uplink port "
            " , RP side oil is removed"
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
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

        step("No change seen on (*,G) mroutes")

        for data in input_dict_starg:
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

    step(
        "Traffic is received for all the groups , verify using "
        "'show ip multicast count json'"
    )

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Shut source interface from R4 and no shut immediate after the "
        "same source upstream expires from DUT"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    shutdown_bringup_interface(tgen, "r4", intf_r4_i6, False)
    shutdown_bringup_interface(tgen, "r4", intf_r4_i6, True)

    step(
        "After no shut verify mroutes populated and multicast traffic resume ,"
        " verify using 'show ip mroute json' 'show ip multicast count json'"
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

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Shut source interface from DUT and no shut immediate after the "
        "same source upstream expires from R4"
    )

    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_i2, False)
    shutdown_bringup_interface(tgen, "r1", intf_r1_i2, True)

    step(
        "After no shut verify mroutes populated and multicast traffic resume ,"
        " verify using 'show ip mroute json' 'show ip multicast count json'"
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

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_mroutes_updated_correctly_after_receiver_interface_shut_noshut_p1(request):
    """
    Verify mroutes updated correctly after receiver interface shut/no shut
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 225.1.1.1-5")

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

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 225.1.1.1-5")

    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send traffic from DUT for group range 225.1.1.1-5")

    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif_r1_r2": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif_r1_r2": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif_r1_r2"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r3_links + [topo["routers"]["r1"]["links"]["i1"]["interface"]],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

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

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and no shut the source interface from DUT")
    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

        step(
            "After shut/no shut of source interface verify all the (S,G) "
            "got re-learn and IIF/OIF pointing any of the links from R2 or "
            "R3 verify using 'show ip mroute json'"
        )

        step(
            "(S,G) OIL on R1 has only respective receiver port and uplink port "
            " , RP side oil is removed"
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
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

        step(
            "Traffic is received for all the groups , verify using "
            "'show ip multicast count json'"
        )

        result = verify_multicast_traffic(tgen, input_traffic)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the receiver interface from R4")
    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, True)

        step(
            "After shut/no shut of source interface verify all the (S,G) "
            "got re-learn and IIF/OIF pointing any of the links from R2 or "
            "R3 verify using 'show ip mroute json'"
        )

        step(
            "(S,G) OIL on R1 has only respective receiver port and uplink port "
            " , RP side oil is removed"
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
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

        step(
            "Traffic is received for all the groups , verify using "
            "'show ip multicast count json'"
        )

        result = verify_multicast_traffic(tgen, input_traffic)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Shut and no shut the receiver interface from DUT after PIM upstream" " timeout"
    )

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

        for data in input_dict_sg:
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

        step(
            "Traffic is received for all the groups , verify using "
            "'show ip multicast count json'"
        )

        result = verify_multicast_traffic(tgen, input_traffic)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Shut and no shut the receiver interface from R4 after PIM upstream " "timeout"
    )

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, True)

        for data in input_dict_sg:
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

        step(
            "Traffic is received for all the groups , verify using "
            "'show ip multicast count json'"
        )

        result = verify_multicast_traffic(tgen, input_traffic)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_mroutes_updated_after_sending_IGMP_prune_and_join_p1(request):
    """
    Verify mroute updated correctly after sending IGMP prune and join
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 225.1.1.1-5")

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

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 225.1.1.1-5")
    step("Send traffic from DUT for group range 225.1.1.1-5")

    input_src = {
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"],
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"],
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif_r1_r2": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif_r1_r2": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif_r1_r2"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

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

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send IGMP prune and join for receivers connected on DUT")
    step("Send IGMP prune and join for receivers connected on R4")

    app_helper.stop_all_hosts()

    step(
        "After sending prune verify (*,G) and (S,G) entries got cleared "
        "from all the nodes"
    )

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif_r1_r2"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed " " mroute are still present \n Error: {}".format(
            tc_name, result
        )

    for data in input_dict_sg:
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
        ), "Testcase {} : Failed " " mroute are still present \n Error: {}".format(
            tc_name, result
        )

    step(
        "After sending joins verify (*,G) and (S,G) entries got populated "
        "again correct OIL and IIF info (any of the link of R2 or R3) verify "
        "using 'show ip mroute json'"
    )

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Multicast traffic receiver for all the groups verify using "
        "'show ip multicast count'"
    )

    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_mroutes_updated_after_after_clear_mroute_p1(request):
    """
    Verify mroute updated correctly after clear mroute
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 225.1.1.1-5")

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

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 225.1.1.1-5")
    step("Send traffic from DUT for group range 225.1.1.1-5")

    input_src = {
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"],
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"],
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif_r1_r2": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif_r1_r2": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif_r1_r2"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

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

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Clear ip mroute from DUT")
    clear_mroute(tgen, "r1")

    step("Clear ip mroute from r4")
    clear_mroute(tgen, "r4")

    step(
        "Multicast traffic receiver for all the groups verify using "
        "'show ip multicast count'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_mroutes_updated_after_changing_rp_config_p1(request):
    """
    Verify (*,G) mroute entries after changing the RP configuration
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

    step("Unconfigure BGP from all nodes as using static routes")

    input_dict = {}
    DUT = ["r1", "r2", "r3", "r4"]
    ASN = [100, 200, 300, 400]
    for dut, asn in zip(DUT, ASN):
        temp = {dut: {"bgp": {}}}
        input_dict.update(temp)

        temp[dut]["bgp"].update({"local_as": asn, "delete": True})

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 225.1.1.1-5")

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

    step("Configure static routes between nodes for making RP and source" "reachable")

    configure_static_routes_for_rp_reachability(tgen, topo)

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 225.1.1.1-5")
    step("Send traffic from DUT for group range 225.1.1.1-5")

    input_src = {
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"],
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"],
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_1, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict_star_sg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_star_sg:
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
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify RP has (S,G) with none OIL or Upstream should be present using 'show ip mroute json'"
        " 'show ip pim upstream json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict_star_sg = [
        {"dut": "r2", "src_address": source_i2, "iif": r2_r1_links, "oil": r2_r4_links},
        {"dut": "r2", "src_address": source_i6, "iif": r2_r4_links, "oil": r2_r1_links},
    ]

    for data in input_dict_star_sg:
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

    step("Verify pim interface traffic before changing RP")

    intf_traffic = topo["routers"]["r4"]["links"]["r3-link1"]["interface"]
    state_dict = {"r4": {intf_traffic: ["registerStopRx"]}}
    state_before = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("Change the RP to R3 loopback for same group range (225.1.1.1-5)")

    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                        "delete": True,
                    }
                ]
            }
        },
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1 + GROUP_RANGE_2,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After changing the RP to R3 , verify (S,G) with none OIL and "
        "upstream got cleared from R2 and created on R3 verify using "
        "'show ip mroute json'; 'show ip pim upstream json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] != "*":
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

    step("(*,G) IIF on DUT is changed towards R3, verify using 'show ip mroute json'")

    input_dict_star_g = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_star_g:
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
        "R4 is sending null register packets to R3 'show ip pim multicast traffic json'"
    )
    step("Verify pim interface traffic after changing RP")

    state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("Send new IGMP join for new group range (226.1.1.1-5)")

    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_2, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send traffic from R4 to same group range")

    input_src = {
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"],
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"],
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, IGMP_JOIN_RANGE_2, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*.G) and (S,G) on LHR for group range (226.1.1.1-5)")
    step(
        "(*,G) joins sent towards new RP (R3) , mroute created verify using "
        "'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_2
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Traffic is received for groups (226.1.1.1-5) , (S,G) mroute updated "
        "in DUT and R4 node verify using 'show ip multicast json'"
    )

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Delete and Add the RP for group range 225.1.1.1-5 on DUT")

    input_dict = {
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After delete of RP verify mroute got uninstall from DUT IIF updated as "
        "unknown in PIM state using 'show ip mroute' 'show ip pim state json'"
    )
    step(
        "No impact seen to on data path as RP config removed after SPT switchover "
        "verify uptime and traffic using 'show ip mroute' 'show ip mroute count json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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
                "Testcase {} : Failed "
                "(*,G) entried are still present \n Error: {}".format(tc_name, result)
            )

        else:
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

    iif = topo["routers"]["r1"]["links"]["i2"]["interface"]
    oil = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_pim_state(tgen, "r1", iif, oil, IGMP_JOIN_RANGE_1, expected=False)
    assert result is not True, (
        "Testcase {} :Failed "
        "PIM state is not unknown after deleting RP \n Error: {}".format(
            tc_name, result
        )
    )

    input_dict = {
        "r3": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv4"].split(
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
        "After Adding the RP verify IIF updated again towards RP , and DUT"
        " sending register packets towards RP, verify using 'show ip mroute'"
        " and 'show ip pim int traffic'"
    )
    step(
        "No impact seen to on data path as RP config removed after SPT "
        "switchover verify uptime and traffic using 'show ip mroute' "
        "'show ip mroute count json'"
    )

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_mroutes_after_restart_frr_services_p2(request):
    """
    Verify mroute entries after FRR service stop and start
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"igmp": {"interfaces": {intf: {"igmp": {"version": "2"}}}}}}

        result = create_igmp_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT and R4 for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 225.1.1.1-5")

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

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range 225.1.1.1-5")

    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send traffic from DUT for group range 225.1.1.1-5")

    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict_star_sg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": r1_r2_links + [topo["routers"]["r1"]["links"]["i2"]["interface"]],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_star_sg:
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
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop the FRR services using kill -9 pid(s) from DUT")
    stop_router(tgen, "r1")

    step("Start the FRR services from DUT")
    start_router(tgen, "r1")

    step("(*,G) IIF and OIL updated on both the nodes")

    for data in input_dict_star_sg:
        if data["src_address"] == "*":
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

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ip mroute' and 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] != "*":
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

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ip multicast'; 'show ip multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_traffic = {
        "r1": {"traffic_sent": [intf_r1_i1]},
        "r4": {"traffic_received": [intf_r4_i6]},
    }
    result = verify_multicast_traffic(tgen, input_traffic)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop the traffic and do frr services stop/start")
    app_helper.stop_all_hosts()

    stop_router(tgen, "r1")
    start_router(tgen, "r1")

    step(
        "FRR services started with new PID , (S,G) not present "
        "on DUT and R4 , verify using 'show ip mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] != "*":
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
            ), "Testcase {}: Failed " "mroutes are still present \n Error: {}".format(
                tc_name, result
            )

    step("Stop FRR on R4 node")

    stop_router(tgen, "r4")

    step(
        "After stop of FRR on R4 node verify mroute on DUT should be "
        "pimreg/prune state"
    )
    step("No OIL created toward R2 on R11 node")

    for data in input_dict_star_sg:
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
        ), "Testcase {} : Failed " " Mroutes are still present \n Error: {}".format(
            tc_name, result
        )

    step("Start FRR on R4 node")

    start_router(tgen, "r4")

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
