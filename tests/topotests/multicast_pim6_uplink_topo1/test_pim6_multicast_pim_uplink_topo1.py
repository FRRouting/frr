#!/usr/bin/env python

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
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
Following tests are covered to test multicast pim6 uplink:

1. Verify mroutes OIL and IIF updated correctly when receivers present inside
and outside of DUT
2. Verify mroutes updated correctly after source interface shut/no shut
3. Verify mroutes updated correctly after receiver interface shut/no shut
4. Verify mroute updated correctly after sending MLD prune and join
5. Verify mroute updated correctly after clear mroute
6. Verify (*,G) mroute entries after changing the RP configuration
7. Verify (*,G) and (S,G) after adding removing the PIM and MLD config
from DUT interfaces
8. Verify mroute when DUT replicating towards both the uplinks
"""

import os
import sys
import json
import time
import pytest
import random
from time import sleep

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
    create_static_routes,
    required_linux_kernel_version,
    topo_daemons,
)
from lib.bgp import create_router_bgp
from lib.pim import (
    create_pim_config,
    create_mld_config,
    verify_mld_groups,
    verify_mroutes,
    clear_pim6_interface_traffic,
    verify_upstream_iif,
    clear_pim6_mroute,
    verify_multicast_traffic,
    verify_pim_interface_traffic,
    verify_pim_state,
    verify_sg_traffic,
    verify_pim6_neighbors,
    McastTesterHelper,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

# Global variables
GROUP_RANGE_1 = [
    "ffaa::1/128",
    "ffaa::2/128",
    "ffaa::3/128",
    "ffaa::4/128",
    "ffaa::5/128",
]
IGMP_JOIN_RANGE_1 = ["ffaa::1", "ffaa::2", "ffaa::3", "ffaa::4", "ffaa::5"]
GROUP_RANGE_2 = [
    "ffbb::1/128",
    "ffbb::2/128",
    "ffbb::3/128",
    "ffbb::4/128",
    "ffbb::5/128",
]
IGMP_JOIN_RANGE_2 = ["ffbb::1", "ffbb::2", "ffbb::3", "ffbb::4", "ffbb::5"]
GROUP_RANGE_3 = [
    "ffcc::1/128",
    "ffcc::2/128",
    "ffcc::3/128",
    "ffcc::4/128",
    "ffcc::5/128",
]
IGMP_JOIN_RANGE_3 = ["ffcc::1", "ffcc::2", "ffcc::3", "ffcc::4", "ffcc::5"]

r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r3_r1_links = []
r3_r4_links = []
r2_r4_links = []
r4_r2_links = []
r4_r3_links = []
HELLO_TIMER = 1
HOLD_TIMER = 3

pytestmark = [pytest.mark.pim6d]


@pytest.fixture(scope="function")
def app_helper():
    with McastTesterHelper(get_topogen()) as ah:
        yield ah


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
    json_file = "{}/multicast_pim6_uplink_topo1.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen, tgen.json_topo)

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen, daemons)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, tgen.json_topo)

    # Pre-requisite data
    get_interfaces_names(topo)

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

        intf = topo["routers"]["r3"]["links"]["r4-link{}".format(link)]["interface"]
        r3_r4_links.append(intf)

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
                            topo["routers"]["r2"]["links"]["lo"]["ipv6"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv6"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv6"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv6"],
                        ],
                        "next_hop": topo["routers"]["r2"]["links"][
                            "r1-link{}".format(i)
                        ]["ipv6"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r3"]["links"]["lo"]["ipv6"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv6"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv6"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv6"],
                        ],
                        "next_hop": topo["routers"]["r3"]["links"][
                            "r1-link{}".format(i)
                        ]["ipv6"].split("/")[0],
                    },
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["i6"]["links"]["r4"]["ipv6"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv6"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv6"],
                            topo["routers"]["r3"]["links"]["lo"]["ipv6"],
                        ],
                        "next_hop": topo["routers"]["r4"]["links"][
                            "r2-link{}".format(i)
                        ]["ipv6"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r1"]["links"]["lo"]["ipv6"],
                            topo["routers"]["r3"]["links"]["lo"]["ipv6"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv6"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv6"],
                        ],
                        "next_hop": topo["routers"]["r1"]["links"][
                            "r2-link{}".format(i)
                        ]["ipv6"].split("/")[0],
                    },
                ]
            },
            "r3": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["r4"]["links"]["lo"]["ipv6"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv6"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv6"],
                            topo["routers"]["r2"]["links"]["lo"]["ipv6"],
                        ],
                        "next_hop": topo["routers"]["r4"]["links"][
                            "r3-link{}".format(i)
                        ]["ipv6"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r1"]["links"]["lo"]["ipv6"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv6"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv6"],
                            topo["routers"]["r2"]["links"]["lo"]["ipv6"],
                        ],
                        "next_hop": topo["routers"]["r1"]["links"][
                            "r3-link{}".format(i)
                        ]["ipv6"].split("/")[0],
                    },
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["r3"]["links"]["lo"]["ipv6"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv6"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv6"],
                            topo["routers"]["r1"]["links"]["lo"]["ipv6"],
                        ],
                        "next_hop": topo["routers"]["r3"]["links"][
                            "r4-link{}".format(i)
                        ]["ipv6"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r2"]["links"]["lo"]["ipv6"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv6"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv6"],
                            topo["routers"]["r1"]["links"]["lo"]["ipv6"],
                        ],
                        "next_hop": topo["routers"]["r2"]["links"][
                            "r4-link{}".format(i)
                        ]["ipv6"].split("/")[0],
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
        for state, value in state_data.items():
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


def test_pim6_mroutes_updated_with_correct_oil_iif_when_receiver_is_in_and_outside_DUT_p0(
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
    clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable MLD on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]

    step("Configure RP as R2 for group range ffaa::1-5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1 + GROUP_RANGE_2,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i1: send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM6 on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range ffaa::1-5")

    step("i6: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("MLD groups are received on DUT and R4 verify using 'show mld'")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_star_sg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
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
            "oil": r4_r2_links + r4_r3_links,
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
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    for dut in ["r1", "r4"]:
        result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, source_i6, "ipv6")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Random shut of upstream interface from DUT side")
    for i in range(1, 5, 2):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step(
        "After shut of upstream interface from DUT verify mroutes has moved "
        "to another interface (R2 or R3) and updated with correct OIL/IIF using"
        " 'show ipv6 mroute json'"
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
        "mroute using 'show ipv6 mroute json'; 'show ipv6 upstream json'"
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
        " 'show ipv6 mroute json'"
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
        "mroute using 'show ipv6 mroute json'; 'show ipv6 upstream json'"
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
        "Send different MLD joins from DUT and R4 for group range (From DUT "
        "ffaa::1-5 and from R4 ffbb::1-5)"
    )

    step("i7: send mld join (ffaa::1-5) to R4")
    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_2, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send traffic for all the groups from R4")

    step("i6: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1 + IGMP_JOIN_RANGE_2, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("MLD groups are received on DUT and R4 verify using 'show mld'")

    step(
        "MLD groups are received on DUT and R4 verify using 'show ipv6 MLD groups'"
        " and 'show ipv6 MLD groups json'"
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
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
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
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
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
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
        " 'show ipv6 mroute json'"
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
        "mroute using 'show ipv6 mroute json'; 'show ipv6 upstream json'"
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


def test_pim6_mroutes_updated_correctly_after_source_ineterface_shut_noshut_p1(request):
    """
    Verify mroutes updated correctly after source interface shut/no shut
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    # Need uncomment once pim6d core bug is fixed
    clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable MLD on DUT and R4 interface")

    step("Send MLD joins from DUT and R4 for group range ffaa::1-5")
    step("i1: send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i4: send mld join (ffaa::1-5) to R4")
    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range ffaa::1-5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Send traffic from R4 for group range ffaa::1-5")
    step("i6: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i2: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "MLD groups are received on DUT and R4 verify using 'show ipv6 MLD groups'"
        " and 'show ipv6 MLD groups json'"
    )

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
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv6"].split("/")[0]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("On R1 for local MLD receivers, OIL towards RP is removed")

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

    for i in range(0, 2):
        step("Shut and no shut the source interface from DUT")
        intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf_r1_i2, False)
        shutdown_bringup_interface(tgen, "r1", intf_r1_i2, True)

        step(
            "After shut/no shut of source interface verify all the (S,G) "
            "got re-learn and IIF/OIF pointing any of the links from R2 or "
            "R3 verify using 'show ipv6 mroute json'"
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
            "'show ipv6 multicast count json'"
        )

        for dut in ["r1", "r4"]:
            for src in [source_i2, source_i6]:
                result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
                assert result is True, "Testcase {} : Failed Error: {}".format(
                    tc_name, result
                )

        step("Shut and no shut the source interface from R4")

        intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf_r4_i6, False)
        shutdown_bringup_interface(tgen, "r4", intf_r4_i6, True)

        step(
            "After shut/no shut of source interface verify all the (S,G) "
            "got re-learn and IIF/OIF pointing any of the links from R2 or "
            "R3 verify using 'show ipv6 mroute json'"
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
        "'show ipv6 multicast count json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step(
        "Shut source interface from R4 and no shut immediate after the "
        "same source upstream expires from DUT"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    shutdown_bringup_interface(tgen, "r4", intf_r4_i6, False)

    step(
        "After shut verify upstream got expired using 'show ipv6 pim "
        "'upstream' before doing no shut"
    )

    done_flag = False
    for retry in range(1, 11):
        result = verify_upstream_iif(
            tgen, "r1", "Unknown", source_i6, IGMP_JOIN_RANGE_1
        )
        if result is not True:
            done_flag = True
        else:
            logger.info("Sleeping for 30 more sec..")
            sleep(30)

        if done_flag:
            logger.info("Expected Behavior: {}".format(result))
            break

    assert done_flag is True, (
        "Testcase {} : Failed Error: \n "
        "mroutes are still present, after waiting for 10 mins".format(tc_name)
    )

    step("No shut immediate after the same source upstream expires from DUT")
    shutdown_bringup_interface(tgen, "r4", intf_r4_i6, True)

    step(
        "After no shut verify mroutes populated and multicast traffic resume ,"
        " verify using 'show ipv6 mroute json' 'show ipv6 multicast count json'"
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

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step(
        "Shut source interface from DUT and no shut immediate after the "
        "same source upstream expires from R4"
    )

    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_i2, False)

    step(
        "After shut verify upstream got expired using 'show ipv6 pim "
        "'upstream' before doing no shut"
    )

    done_flag = False
    for retry in range(1, 11):
        result = verify_upstream_iif(
            tgen, "r4", "Unknown", source_i2, IGMP_JOIN_RANGE_1
        )
        if result is not True:
            done_flag = True
        else:
            logger.info("Sleeping for 30 more sec..")
            sleep(30)

        if done_flag:
            logger.info("Expected Behavior: {}".format(result))
            break

    assert done_flag is True, (
        "Testcase {} : Failed Error: \n "
        "mroutes are still present, after waiting for 10 mins".format(tc_name)
    )

    step("No shut immediate after the same source upstream expires from R4")
    shutdown_bringup_interface(tgen, "r1", intf_r1_i2, True)

    step(
        "After no shut verify mroutes populated and multicast traffic resume ,"
        " verify using 'show ipv6 mroute json' 'show ipv6 multicast count json'"
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

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_pim6_mroutes_updated_correctly_after_receiver_interface_shut_noshut_p1(
    request,
):
    """
    Verify mroutes updated correctly after receiver interface shut/no shut
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    # uncomment once pim6d crash bug is fixed
    # clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable MLD on DUT and R4 interface")
    step("Send MLD joins from DUT and R4 for group range ffaa::1-5")
    step("i1: send mld join (ffaa::1-5) to R1")
    intf = topo["routers"]["i1"]["links"]["r1"]["interface"]
    intf_ip = topo["routers"]["i1"]["links"]["r1"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i1", "UDP6-RECV", IGMP_JOIN_RANGE_1, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i4: send mld join (ffaa::1-5) to R4")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range ffaa::1-5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Send traffic from R4 for group range ffaa::1-5")
    step("i6: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i2: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "MLD groups are received on DUT and R4 verify using 'show ipv6 MLD groups'"
        " and 'show ipv6 MLD groups json'"
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
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
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv6"].split("/")[0]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

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
        "R3 verify using 'show ipv6 mroute json'"
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
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Traffic is received for all the groups , verify using "
        "'show ipv6 multicast count json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

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
        "R3 verify using 'show ipv6 mroute json'"
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
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Traffic is received for all the groups , verify using "
        "'show ipv6 multicast count json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step(
        "Shut and no shut the receiver interface from DUT after PIM upstream"
        " timeout (6 min interval)"
    )

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step("Wait for 6 min for upstream to timeout")
    sleep(360)

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
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Traffic is received for all the groups , verify using "
        "'show ipv6 multicast count json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step(
        "Shut and no shut the receiver interface from R4 after PIM upstream "
        "timeout (6 min interval)"
    )

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    step("Wait for 6 min for upstream to timeout")
    sleep(360)

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
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Traffic is received for all the groups , verify using "
        "'show ipv6 multicast count json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_pim6_mroutes_updated_after_sending_IGMP_prune_and_join_p1(request):
    """
    Verify mroute updated correctly after sending MLD prune and join
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    # clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable MLD on DUT and R4 interface")
    step("Send MLD joins from DUT and R4 for group range ffaa::1-5")
    step("i1: send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i4: send mld join (ffaa::1-5) to R4")
    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range ffaa::1-5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Send traffic from R4 for group range ffaa::1-5")
    step("i6: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i2: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

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
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv6"].split("/")[0]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("Send MLD prune and join for receivers connected on DUT")
    step("Send MLD prune and join for receivers connected on R4")

    app_helper.stop_host("i1")
    app_helper.stop_host("i7")

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
        "using 'show ipv6 mroute json'"
    )

    step("i1: send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i4: send mld join (ffaa::1-5) to R4")
    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

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
        "'show ipv6 multicast count'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_pim6_mroutes_updated_after_after_clear_mroute_p1(request):
    """
    Verify mroute updated correctly after clear mroute
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    # clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable MLD on DUT and R4 interface")
    step("Send MLD joins from DUT and R4 for group range ffaa::1-5")
    step("i1: send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i4: send mld join (ffaa::1-5) to R4")
    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range ffaa::1-5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Send traffic from R4 for group range ffaa::1-5")
    step("i6: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i2: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

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
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv6"].split("/")[0]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("Clear ip mroute from DUT")
    step(
        "Mroute entries got populated again correct OIL and IIF info"
        "verify using 'show ipv6 mroute json'"
    )
    step(
        "DUT connected source has OIL toward local receiver on R1 and "
        "R3 receiver, RPT path is removed"
    )
    clear_pim6_mroute(tgen, "r1")

    step("Clear ip mroute from r4")
    clear_pim6_mroute(tgen, "r4")

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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Multicast traffic receiver for all the groups verify using "
        "'show ipv6 multicast count'"
    )

    for dut in ["r1", "r4"]:
        result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, source_i6, "ipv6")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_mroutes_updated_after_changing_rp_config_p1(request):
    """
    Verify (*,G) mroute entries after changing the RP configuration
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    # clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

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

    step("Enable MLD on DUT and R4 interface")
    step("Send MLD joins from DUT and R4 for group range ffaa::1-5")
    step("i1: send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i7: send mld join (ffaa::1-5) to R4")
    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range ffaa::1-5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Configure static routes between nodes for making RP and source" " reachable")

    # configure_static_routes_for_rp_reachability(tgen, topo)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range ffaa::1-5")
    step("i6: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i2: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv6"].split("/")[0]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step(
        "Verify RP has (S,G) with none OIL or Upstream should be present using 'show ipv6 mroute json'"
        " 'show ipv6 pim upstream json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv6"].split("/")[0]
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
    state_before = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("Change the RP to R3 loopback for same group range (ffaa::1-5)")

    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                        "delete": True,
                    }
                ]
            }
        },
        "r3": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv6"].split(
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
        "'show ipv6 mroute json'; 'show ipv6 pim upstream json'"
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

    step("(*,G) IIF on DUT is changed towards R3, verify using 'show ipv6 mroute json'")

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
        "R4 is sending null register packets to R3 'show ipv6 pim multicast traffic json'"
    )
    step("Verify pim interface traffic after changing RP")

    state_after = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_after is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("Send new MLD join for new group range (ffbb::1-5)")

    step("i1: send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i4: send mld join (ffaa::1-5) to R4")
    result = app_helper.run_join("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send traffic from R4 to same group range")

    step("i6: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i2: Send multicast traffic for group ffaa::1-5")
    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("(*.G) and (S,G) on LHR for group range (ffbb::1-5)")
    step(
        "(*,G) joins sent towards new RP (R3) , mroute created verify using "
        "'show ipv6 mroute json'"
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
        "Traffic is received for groups (ffbb::1-5) , (S,G) mroute updated "
        "in DUT and R4 node verify using 'show ipv6 multicast json'"
    )

    result = verify_sg_traffic(tgen, "r4", IGMP_JOIN_RANGE_2, source_i6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Delete and Add the RP for group range ffaa::1-5 on DUT")

    input_dict = {
        "r3": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv6"].split(
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
        "unknown in PIM state using 'show ipv6 mroute' 'show ipv6 pim state json'"
    )
    step(
        "No impact seen to on data path as RP config removed after SPT switchover "
        "verify uptime and traffic using 'show ipv6 mroute' 'show ipv6 mroute count json'"
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
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv6"].split(
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
        " sending register packets towards RP, verify using 'show ipv6 mroute'"
        " and 'show ipv6 pim int traffic'"
    )
    step(
        "No impact seen to on data path as RP config removed after SPT "
        "switchover verify uptime and traffic using 'show ipv6 mroute' "
        "'show ipv6 mroute count json'"
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

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_pim6_mroutes_updated_after_adding_removing_pim_igmp_config_p1(request):
    """
    Verify (*,G) and (S,G) after adding removing the PIM and MLD config
    from DUT interfaces
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    # clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

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

    step("Enable MLD on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i7]):
        input_dict = {dut: {"mld": {"interfaces": {intf: {"mld": {"version": "1"}}}}}}

        result = create_mld_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable MLD on DUT and R4 interface")
    step("Send MLD joins from DUT and R4 for group range ffaa::1-5")
    step("i1: send mld join (ffaa::1-5) to R1")
    intf = topo["routers"]["i1"]["links"]["r1"]["interface"]
    intf_ip = topo["routers"]["i1"]["links"]["r1"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i1", "UDP6-RECV", IGMP_JOIN_RANGE_1, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i4: send mld join (ffaa::1-5) to R4")
    intf = topo["routers"]["i7"]["links"]["r4"]["interface"]
    intf_ip = topo["routers"]["i7"]["links"]["r4"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i7", "UDP6-RECV", IGMP_JOIN_RANGE_1, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range ffaa::1-5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    # configure_static_routes_for_rp_reachability(tgen, topo)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range ffaa::1-5")
    step("i6: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i6"]["links"]["r4"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i6", "UDP6-SEND", IGMP_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i2: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i2"]["links"]["r1"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i2", "UDP6-SEND", IGMP_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv6"].split("/")[0]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
    )

    for dut in ["r1", "r4"]:
        for src in [source_i2, source_i6]:
            result = verify_sg_traffic(tgen, dut, IGMP_JOIN_RANGE_1, src, "ipv6")
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("Remove ip MLD from receiver interface of DUT")

    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {intf_r1_i1: {"mld": {"version": "1", "delete": True}}}
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "After removing MLD from CLI verify MLD groups are removed "
        "using 'show ipv6 MLD groups json'"
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(
        tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed " "MLD groups are still present \n Error: {}".format(
        tc_name, result
    )

    step(
        "(*,G) and (S,G) got removed from DUT using 'show ipv6 mroute json'"
        "'show ipv6 pim upstream' and traffic stopped 'show ipv6 multicast json'"
    )

    for data in input_dict_star_sg:
        if data["dut"] == "r1" and data["src_address"] in [source_i6, "*"]:
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
            ), "Testcase {} : Failed " "mroutes are still present \n Error: {}".format(
                tc_name, result
            )

    step("Config ip MLD on receiver interface of DUT")

    input_dict = {
        "r1": {"mld": {"interfaces": {intf_r1_i1: {"mld": {"version": "1"}}}}}
    }

    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i1: send mld join (ffaa::1-5) to R1")
    intf = topo["routers"]["i1"]["links"]["r1"]["interface"]
    intf_ip = topo["routers"]["i1"]["links"]["r1"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i1", "UDP6-RECV", IGMP_JOIN_RANGE_1, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "After config of MLD CLI all the groups are received verify using"
        " 'show ipv6 MLD json'"
    )

    result = verify_mld_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(*,G) and (S,G) got re-learn from DUT using 'show ipv6 mroute json'"
        " 'show ipv6 pim upstream' and traffic resume 'show ipv6 multicast json'"
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
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("No core observed after removing /adding the CLI")

    if tgen.routers_have_failure():
        assert True, "Testcase {}: Failed Error: {}".format(tc_name, tgen.errors)

    step(
        "Remove PIM6 'no ipv6 pim sm' from all the DUT interface one by one"
        " ( DUT-R4, DUT-R2, DUT-R3)"
    )

    input_dict_1 = {"r1": {"pim6": {"disable": r1_r2_links + r1_r3_links}}}
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "After removing PIM one by one verify interface not shown in "
        "'show ipv6 pim interface json'"
    )

    randnum = random.randint(0, len(r1_r2_links) - 1)
    rand_iface = r1_r2_links[randnum]
    result = verify_pim6_neighbors(
        tgen, topo, dut="r1", iface=rand_iface, expected=False
    )
    assert (
        result is not True
    ), "Testcase {}: Failed " "PIM interfaces still present \n Error: {}".format(
        tc_name, result
    )

    step("Corresponding nbr is down 'show ipv6 pim nbrs json'")

    result = verify_pim6_neighbors(tgen, topo, "r1", expected=False)
    assert (
        result is not True
    ), "Testcase {}: Failed " "PIM neighbor present \n Error: {}".format(
        tc_name, result
    )

    step("Enable PIM6 for all interfaces in DUT")

    input_dict_1 = {"r1": {"pim6": {"enable": r1_r2_links + r1_r3_links}}}
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Nbr has come up after adding the PIM config 'show ipv6 pim nbrs json'")

    result = verify_pim6_neighbors(tgen, topo, "r2")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Adding PIM config for all the link (S,G) taking shortest path "
        "(DUT-R4) verify using 'show ipv6 mroute json' 'show ipv6 multicast json'"
    )

    input_dict_star_sg = [
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
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Remove PIM6 config from all the uplinks")

    input_dict_1 = {"r1": {"pim6": {"disable": r1_r2_links + r1_r3_links}}}
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Removing config from all the interface (S,G) got removed from " "mroute")

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

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
        ), "Testcase {}: Failed " "Mroutes are still present Error: {}".format(
            tc_name, result
        )

    step("Add PIM config from all the uplinks")

    reset_config_on_routers(tgen)

    step("No core observed after removing /adding the CLI")
    if tgen.routers_have_failure():
        assert True, "Testcase {}: Failed Error: {}".format(tc_name, tgen.errors)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
