#!/usr/bin/env python

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
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
Following tests are covered to test multicast pim ssm:

1. Verify IGMPv3 join is received on R1
2. Verify static /local IGMPv3 join
3. Verify SSM mroute and upstream updated
   with correct OIL and IIF
"""

import ipaddress
import os
import sys
import time
import pytest
import datetime
from subprocess import call
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
    create_prefix_lists,
    write_test_header,
    write_test_footer,
    step,
    check_router_status,
    addKernelRoute,
    create_static_routes,
    stop_router,
    start_router,
    HostApplicationHelper,
    shutdown_bringup_interface,
    kill_router_daemons,
    start_router_daemons,
    reset_config_on_routers,
    do_countdown,
    apply_raw_config,
    run_frr_cmd,
    required_linux_kernel_version,
    IPerfHelper,
    InvalidCLIError,
    retry,
    run_frr_cmd,
    socat_send_ssm_join,
    kill_socat,
)

from lib.pim import (
    create_igmp_config,
    verify_igmp_config,
    find_rp_details,
    create_pim_config,
    add_rp_interfaces_and_pim_config,
    reconfig_interfaces,
    scapy_send_bsr_raw_packet,
    find_rp_from_bsrp_info,
    verify_pim_grp_rp_source,
    verify_pim_bsr,
    verify_join_state_and_timer,
    verify_pim_state,
    verify_upstream_iif,
    verify_multicast_flag_state,
    enable_disable_pim_unicast_bsm,
    enable_disable_pim_bsm,
    get_pim_interface_traffic,
    McastTesterHelper,
    clear_mroute,
    clear_pim_interface_traffic,
    verify_ssm_traffic,
    verify_igmp_source,
    verify_pim_interface_traffic,
    verify_pim_neighbors,
    verify_mroutes,
    verify_igmp_groups,
)
from lib.bgp import create_router_bgp
from lib.topolog import logger
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

# Reading the data from JSON File for topology creation
topo = None

# Global variables
IGMP_GROUP = "232.1.1.1/32"
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
    "232.1.1.1/32",
    "232.1.1.2/32",
    "232.1.1.3/32",
    "232.1.1.4/32",
    "232.1.1.5/32",
]
IGMP_JOIN_RANGE_3 = ["232.1.1.1", "232.1.1.2", "232.1.1.3", "232.1.1.4", "232.1.1.5"]

r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r3_r1_links = []
r2_r4_links = []
r4_r2_links = []
r4_r3_links = []
HELLO_TIMER = 1
HOLD_TIMER = 3


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/multicast_pim_ssm_topo1.json".format(testdir)
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

    # Pre-requisite data
    get_interfaces_names(topo)

    result = verify_pim_neighbors(tgen, topo)
    assert result is True, " Verify PIM neighbor: Failed Error: {}".format(result)

    # XXX Replace this using "with McastTesterHelper()... " in each test if possible.
    global app_helper
    app_helper = McastTesterHelper(tgen)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    app_helper.cleanup()
    kill_socat(tgen, action="remove_ssm_join")

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
        assert result is True, "Testcase : Failed Error: {}".format(result)


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
            if state_before[router][state] != state_after[router][state]:
                errormsg = (
                    "[R1: %s]: state %s value has not"
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
                "[R1: %s]: State %s value is "
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


def test_verify_IGMPv3_join_on_R1_p0(request):
    """
    Verify IGMPv3 join is received on R1
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Unconfigure BGP from all nodes as using static routes")
    DUT = ["r1", "r2", "r3", "r4"]
    ASN = [100, 200, 300, 400]
    for dut, asn in zip(DUT, ASN):
        input_dict = {dut: {"bgp": [{"local_as": asn, "delete": True}]}}

        result = create_router_bgp(tgen, topo, input_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure IGMP on R1 to iperf connected port")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i1_ip = topo["routers"]["r1"]["links"]["i1"]["ipv4"].split("/")[0]

    input_dict = {
        "r1": {"igmp": {"interfaces": {intf_r1_i1: {"igmp": {"version": "3"}}}}}
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        'Configure "ip pim ssm enable" on all the nodes enable as part of initial setup'
    )

    step("Configure static routers toward source and RP on all the nodes")
    configure_static_routes_for_rp_reachability(tgen, topo)

    step("Send IGMPv3 join from R1 for group range 225.1.1.1-5")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]

    intf_ip = topo["routers"]["i1"]["links"]["r1"]["ipv4"].split("/")[0]
    result = socat_send_ssm_join(
        tgen, "i1", "UDP-RECV", IGMP_JOIN_RANGE_3, intf_ip, source_i6
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("IGMP join received on R1 with correct source address")
    step("verify IGMP group")
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, version=3)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify source timer is updating fine")
    step("verify IGMP join source address")
    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_IGMPv3_static_join_p0(request):

    """
    Verify static /local IGMPv3 join
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]

    step("configure static IGMP join for SSM range")
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version": "3",
                            "join": IGMP_JOIN_RANGE_3,
                            "source": source_i6,
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("configure static IGMP join for ASM range")
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {"igmp": {"version": "3", "join": IGMP_JOIN_RANGE_2}}
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "IGMP join and IGMP group is present for SSM range group using 'show ip pim join json'"
    )

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "IGMP join and IGMP group is present for SM range group using 'show ip pim join json'"
    )
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 226.1.1.x and 232.1.1.x")

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

    step("Send traffic on ASM range groups")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_2, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send traffic on SSM range groups")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_3, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("SSM mroute and upstream is created on R1 and R4, verify using")
    step("show ip pim upstream json" "show ip mroute json")

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    input_dict_star_sg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    step("(*,G) mroute and upstream is created on R1")

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

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_3,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
        "After sending traffic on SSM range group , verify SSM range group"
        "is receiving traffic using 'show ip mroute count json'"
    )

    result = verify_ssm_traffic(tgen, "r1", IGMP_JOIN_RANGE_2, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Delete static IGMP join for SSM range")
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version": "3",
                            "join": IGMP_JOIN_RANGE_3,
                            "source": source_i6,
                            "delete": True,
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Delete static IGMP join for SM range")
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version": "3",
                            "join": IGMP_JOIN_RANGE_2,
                            "delete": True,
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Mroute deleted after deleting IGMP groups")

    for data in input_dict_sg:

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {}: Failed " "mroutes are still present \n Error: {}".format(
            tc_name, result
        )

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_3,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {}: Failed " "mroutes are still present \n Error: {}".format(
            tc_name, result
        )

    step("send ASM and SSM join from different interfaces")

    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version": "3",
                            "join": IGMP_JOIN_RANGE_3,
                            "source": source_i6,
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("configure static IGMP join for SM range")
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {"igmp": {"version": "3", "join": IGMP_JOIN_RANGE_2}}
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "SSM IGMP join received on receiver-1 interface , verify using 'show ip igmp join'"
    )

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "ASM IGMP join received on receiver-2 interface , verify using 'show ip igmp join'"
    )
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send traffic for SSM and ASM range group from R4")

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

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_3,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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

    write_test_footer(tc_name)


def test_ssm_mroute_upstream_p0(request):
    """
    Verify SSM mroute and upstream updated
    with correct OIL and IIF
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]

    step("Enable IGMP on R1 and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    DUT = ["r1", "r2", "r3", "r4"]

    input_dict = {
        "r1": {"igmp": {"interfaces": {intf_r1_i1: {"igmp": {"version": "3"}}}}}
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Send IGMPv3 join for SSM range (grp-set1) from R1 source as R4 iperf"
        "connected interface ip"
    )
    intf_ip = topo["routers"]["i1"]["links"]["r1"]["ipv4"].split("/")[0]
    result = socat_send_ssm_join(
        tgen, "i1", "UDP-RECV", IGMP_JOIN_RANGE_3, intf_ip, source_i6
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "IGMPv3 groups are received on R1 verify using show ip igmp groups json"
        "show ip igmp source json"
    )

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send traffic from R4 node")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_3, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "SSM mroute on R1 where IIF towards R4 side and OIL towards receiver interface ,"
        "verify using show ip mroute json on R1 and R4"
    )

    step(
        "Upstream created on R1 and R4 with JOIN flag , RegP and RegJ flag should not be present on"
        "both the nodes , verify using show ip pim upstream json"
    )

    step(
        "Join timer is running on all (s,g) and LHR sending join to every 60 sec to FHR , verify using"
        "show ip pim interface stats"
    )

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    input_dict_sg_r4 = [
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links + r4_r3_links,
        }
    ]

    for data in input_dict_sg:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_3,
            joinState="Joined",
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_3,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_join_state_and_timer(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_3
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for data in input_dict_sg_r4:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_3,
            joinState="Joined",
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_3,
            regState="RegNoInfo",
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Register packet transmit and receive count are not incrementing on R1 and R4 node,"
        "verify using show ip pim interface traffic json"
    )

    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]

    state_dict = {"r4": {intf_r4_i6: ["registerTx"], intf_r4_i6: ["registerRx"]}}

    state_before = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    logger.info("sleeping for 30sec to verify stats increamented")

    state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step(
        "Multicast traffic received on SSM group range verify using"
        "show ip mroute count json and show ip multicast count json"
    )

    result = verify_ssm_traffic(tgen, "r1", IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove join and traffic")

    app_helper.stop_all_hosts()

    step("First send traffic from R4 node wait for 60sec")
    result = app_helper.run_traffic("i6", IGMP_JOIN_RANGE_3, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send join from R1 after that")
    intf_ip = topo["routers"]["i1"]["links"]["r1"]["ipv4"].split("/")[0]
    result = socat_send_ssm_join(
        tgen, "i1", "UDP-RECV", IGMP_JOIN_RANGE_3, intf_ip, source_i6
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Verify multicast traffic")

    result = verify_ssm_traffic(tgen, "r1", IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
