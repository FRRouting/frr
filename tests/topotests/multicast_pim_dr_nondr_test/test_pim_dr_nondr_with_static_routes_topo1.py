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
1. Verify mroute while rebooting DR /Non DR nodes( r1, r2 , r3 on all the nodes)
"""

import os
import sys
import json
import time
import datetime
from time import sleep
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
    apply_raw_config,
    add_interfaces_to_vlan,
    stop_router,
    start_router,
    check_router_status,
    topo_daemons,
    required_linux_kernel_version,
)
from lib.pim import (
    create_pim_config,
    create_igmp_config,
    verify_mroutes,
    clear_mroute,
    clear_pim_interface_traffic,
    verify_pim_config,
    verify_upstream_iif,
    verify_multicast_flag_state,
    McastTesterHelper,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

HELLO_TIMER = 1
HOLD_TIMER = 3

pytestmark = [pytest.mark.pimd]

TOPOLOGY = """

Descripton: Configuring static routes on r1/r2/r3/r4/r5 for RP reachablility.
IPs are assigned automatically to routers, start IP and subnet is defined in respective JSON file
JSON snippet:
    "link_ip_start": {"ipv4": "10.0.0.0", "v4mask": 24},

                               r5 ------- i2
                    10.0.3.2/24| 10.0.0.2/24
                               |
                    10.0.3.1/24|
                  ------------ r4 ----------
                |   10.0.1.2/24  10.0.2.2/24 |
    10.0.1.1/24 |                            | 10.0.2.1/24
                r1 ----------- s1 ---------- r2
                  10.0.4.2/24  | 10.0.4.3/24
                               |
                               |10.0.4.4/24
                   i1 -------- r3
                    10.0.4.1/24
    Description:
    i1, i2  - FRR running iperf to send IGMP
                                     join and traffic
    r1, r2, r3, r4, r5 - FRR ruter
    s1 - OVS switch
"""

# Global variables
VLAN_1 = 2501
GROUP_RANGE = "225.0.0.0/8"
IGMP_JOIN = "225.1.1.1"
VLAN_INTF_ADRESS_1 = "10.0.8.3/24"
SAME_VLAN_IP_1 = {"ip": "10.1.1.1", "subnet": "255.255.255.0", "cidr": "24"}
SAME_VLAN_IP_2 = {"ip": "10.1.1.2", "subnet": "255.255.255.0", "cidr": "24"}
SAME_VLAN_IP_3 = {"ip": "10.1.1.3", "subnet": "255.255.255.0", "cidr": "24"}
SAME_VLAN_IP_4 = {"ip": "10.1.1.4", "subnet": "255.255.255.0", "cidr": "24"}
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

intf_r1_s1 = None
intf_r1_s1_addr = None
intf_r2_s1 = None
intf_r2_s1_addr = None
intf_r3_s1 = None
intf_r3_s1_addr = None
intf_i1_s1 = None
intf_i1_s1_addr = None


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
    logger.info("Master Topology: \n {}".format(TOPOLOGY))

    logger.info("Running setup_module to create topology")

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/pim_dr_nondr_with_static_routes_topo1.json".format(testdir)
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
#   Local APIs
#
#####################################################


def pre_config_for_receiver_dr_tests(
    tgen, topo, tc_name, highest_priority, lowest_priority
):
    """
    API to do common pre-configuration for receiver test cases

    parameters:
    -----------
    * `tgen`: topogen object
    * `topo`: input json data
    * `tc_name`: caller test case name
    * `highest_priority`: router which will be having highest DR priority
    * `lowest_priority`: router which will be having lowest DR priority
    """

    global intf_r1_s1, intf_r1_s1_addr, intf_r2_s1, intf_r2_s1_addr, intf_r3_s1, intf_r3_s1_addr, intf_i1_s1, intf_i1_s1_addr

    step("Configure IGMP and PIM on switch connected receiver nodes")
    step("Configure PIM on all upstream interfaces")

    step("Configure link between R1, R2 ,R3 and receiver on" " same vlan")
    step(
        "Make sure {0} is DR initially configuring highest IP on {0} and R2 "
        "second highest, {1} is lower".format(highest_priority, lowest_priority)
    )

    intf_r1_s1 = topo["routers"]["r1"]["links"]["s1"]["interface"]
    intf_r1_s1_addr = topo["routers"]["r1"]["links"]["s1"]["ipv4"]

    intf_r2_s1 = topo["routers"]["r2"]["links"]["s1"]["interface"]
    intf_r2_s1_addr = topo["routers"]["r2"]["links"]["s1"]["ipv4"]

    intf_r3_s1 = topo["routers"]["r3"]["links"]["s1"]["interface"]
    intf_r3_s1_addr = topo["routers"]["r3"]["links"]["s1"]["ipv4"]

    intf_i1_s1 = topo["routers"]["i1"]["links"]["s1"]["interface"]
    intf_i1_s1_addr = topo["routers"]["i1"]["links"]["s1"]["ipv4"]

    if lowest_priority == "r1":
        lowest_pr_intf = intf_r1_s1
    else:
        lowest_pr_intf = intf_r3_s1

    if highest_priority == "r1":
        highest_pr_intf = intf_r1_s1
    else:
        highest_pr_intf = intf_r3_s1

    vlan_input = {
        lowest_priority: {
            "vlan": {
                VLAN_1: [
                    {
                        lowest_pr_intf: {
                            "ip": SAME_VLAN_IP_1["ip"],
                            "subnet": SAME_VLAN_IP_1["subnet"],
                        }
                    }
                ]
            }
        },
        "r2": {
            "vlan": {
                VLAN_1: [
                    {
                        intf_r2_s1: {
                            "ip": SAME_VLAN_IP_2["ip"],
                            "subnet": SAME_VLAN_IP_2["subnet"],
                        }
                    }
                ]
            }
        },
        highest_priority: {
            "vlan": {
                VLAN_1: [
                    {
                        highest_pr_intf: {
                            "ip": SAME_VLAN_IP_3["ip"],
                            "subnet": SAME_VLAN_IP_3["subnet"],
                        }
                    }
                ]
            }
        },
        "i1": {
            "vlan": {
                VLAN_1: [
                    {
                        intf_i1_s1: {
                            "ip": SAME_VLAN_IP_4["ip"],
                            "subnet": SAME_VLAN_IP_4["subnet"],
                        }
                    }
                ]
            }
        },
    }

    add_interfaces_to_vlan(tgen, vlan_input)

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_s1),
                "no ip address {}".format(intf_r1_s1_addr),
                "no ip pim",
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}".format(intf_r2_s1),
                "no ip address {}".format(intf_r2_s1_addr),
                "no ip pim",
            ]
        },
        "r3": {
            "raw_config": [
                "interface {}".format(intf_r3_s1),
                "no ip address {}".format(intf_r3_s1_addr),
                "no ip pim",
            ]
        },
        "i1": {
            "raw_config": [
                "interface {}".format(intf_i1_s1),
                "no ip address {}".format(intf_i1_s1_addr),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    raw_config = {
        lowest_priority: {
            "raw_config": [
                "interface {}.{}".format(lowest_pr_intf, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_1["ip"], SAME_VLAN_IP_1["cidr"]),
                "ip pim",
                "ip igmp",
                "ip igmp version 2",
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}.{}".format(intf_r2_s1, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
                "ip pim",
                "ip igmp",
                "ip igmp version 2",
            ]
        },
        highest_priority: {
            "raw_config": [
                "interface {}.{}".format(highest_pr_intf, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]),
                "ip pim",
                "ip igmp",
                "ip igmp version 2",
            ]
        },
        "i1": {
            "raw_config": [
                "interface {}.{}".format(intf_i1_s1, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_4["ip"], SAME_VLAN_IP_4["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for dut, intf in zip(["r1", "r2", "r3"], [intf_r1_s1, intf_r2_s1, intf_r3_s1]):
        raw_config = {
            dut: {
                "raw_config": [
                    "interface {}.{}".format(intf, VLAN_1),
                    "ip pim hello {} {}".format(HELLO_TIMER, HOLD_TIMER),
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure R4 as RP on all the nodes for group range 224.0.0.0/24")

    input_dict = {
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r4"]["links"]["lo"]["ipv4"].split(
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

    step("Send IGMP join for groups 226.1.1.1 to 226.1.1.5")

    vlan_intf_i1_s1 = "{}.{}".format(intf_i1_s1, VLAN_1)
    result = app_helper.run_join("i1", IGMP_JOIN_RANGE_1, join_intf=vlan_intf_i1_s1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Using static routes instead OSPF: Enable OSPF between all the nodes")

    step("Start traffic from R4 connected source")

    result = app_helper.run_traffic("i2", IGMP_JOIN_RANGE_1, "r5")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    return True


def pre_config_for_source_dr_tests(
    tgen, topo, tc_name, highest_priority, lowest_priority
):
    """
    API to do common pre-configuration for source test cases

    parameters:
    -----------
    * `tgen`: topogen object
    * `topo`: input json data
    * `tc_name`: caller test case name
    * `highest_priority`: router which will be having highest DR priority
    * `lowest_priority`: router which will be having lowest DR priority
    """

    global intf_r1_s1, intf_r1_s1_addr, intf_r2_s1, intf_r2_s1_addr, intf_r3_s1, intf_r3_s1_addr, intf_i1_s1, intf_i1_s1_addr

    step("Configure IGMP and PIM on switch connected receiver nodes")
    step("Configure PIM on all upstream interfaces")

    step("Configure link between R1, R2 ,R3 and receiver on" " same vlan")
    step(
        "Make sure {0} is DR initially configuring highest IP on {0} and R2 "
        "second highest, {1} is lower".format(highest_priority, lowest_priority)
    )

    intf_r1_s1 = topo["routers"]["r1"]["links"]["s1"]["interface"]
    intf_r1_s1_addr = topo["routers"]["r1"]["links"]["s1"]["ipv4"]

    intf_r2_s1 = topo["routers"]["r2"]["links"]["s1"]["interface"]
    intf_r2_s1_addr = topo["routers"]["r2"]["links"]["s1"]["ipv4"]

    intf_r3_s1 = topo["routers"]["r3"]["links"]["s1"]["interface"]
    intf_r3_s1_addr = topo["routers"]["r3"]["links"]["s1"]["ipv4"]

    intf_i1_s1 = topo["routers"]["i1"]["links"]["s1"]["interface"]
    intf_i1_s1_addr = topo["routers"]["i1"]["links"]["s1"]["ipv4"]

    if lowest_priority == "r1":
        lowest_pr_intf = intf_r1_s1
    else:
        lowest_pr_intf = intf_r3_s1

    if highest_priority == "r1":
        highest_pr_intf = intf_r1_s1
    else:
        highest_pr_intf = intf_r3_s1

    vlan_input = {
        lowest_priority: {
            "vlan": {
                VLAN_1: [
                    {
                        lowest_pr_intf: {
                            "ip": SAME_VLAN_IP_1["ip"],
                            "subnet": SAME_VLAN_IP_1["subnet"],
                        }
                    }
                ]
            }
        },
        "r2": {
            "vlan": {
                VLAN_1: [
                    {
                        intf_r2_s1: {
                            "ip": SAME_VLAN_IP_2["ip"],
                            "subnet": SAME_VLAN_IP_2["subnet"],
                        }
                    }
                ]
            }
        },
        highest_priority: {
            "vlan": {
                VLAN_1: [
                    {
                        highest_pr_intf: {
                            "ip": SAME_VLAN_IP_3["ip"],
                            "subnet": SAME_VLAN_IP_3["subnet"],
                        }
                    }
                ]
            }
        },
        "i1": {
            "vlan": {
                VLAN_1: [
                    {
                        intf_i1_s1: {
                            "ip": SAME_VLAN_IP_4["ip"],
                            "subnet": SAME_VLAN_IP_4["subnet"],
                        }
                    }
                ]
            }
        },
    }

    add_interfaces_to_vlan(tgen, vlan_input)

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_s1),
                "no ip address {}".format(intf_r1_s1_addr),
                "no ip pim",
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}".format(intf_r2_s1),
                "no ip address {}".format(intf_r2_s1_addr),
                "no ip pim",
            ]
        },
        "r3": {
            "raw_config": [
                "interface {}".format(intf_r3_s1),
                "no ip address {}".format(intf_r3_s1_addr),
                "no ip pim",
            ]
        },
        "i1": {
            "raw_config": [
                "interface {}".format(intf_i1_s1),
                "no ip address {}".format(intf_i1_s1_addr),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Configure IGMP and PIM on switch connected receiver nodes , "
        "configure PIM nbr with hello timer 1"
    )

    raw_config = {
        lowest_priority: {
            "raw_config": [
                "interface {}.{}".format(lowest_pr_intf, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_1["ip"], SAME_VLAN_IP_1["cidr"]),
                "ip pim",
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}.{}".format(intf_r2_s1, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
                "ip pim",
            ]
        },
        highest_priority: {
            "raw_config": [
                "interface {}.{}".format(highest_pr_intf, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]),
                "ip pim",
            ]
        },
        "i1": {
            "raw_config": [
                "interface {}.{}".format(intf_i1_s1, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_4["ip"], SAME_VLAN_IP_4["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for dut, intf in zip(["r1", "r2", "r3"], [intf_r1_s1, intf_r2_s1, intf_r3_s1]):
        raw_config = {
            dut: {
                "raw_config": [
                    "interface {}.{}".format(intf, VLAN_1),
                    "ip pim hello {} {}".format(HELLO_TIMER, HOLD_TIMER),
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure R4 as RP on all the nodes for group range 224.0.0.0/24")

    input_dict = {
        "r4": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r4"]["links"]["lo"]["ipv4"].split(
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

    step("Configure IGMP on R5 port and send IGMP join for groups " "(226.1.1.1-5)")

    intf_r5_i2 = topo["routers"]["r5"]["links"]["i2"]["interface"]
    input_dict = {
        "r5": {"igmp": {"interfaces": {intf_r5_i2: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_src = {"i2": topo["routers"]["i2"]["links"]["r5"]["interface"]}

    result = app_helper.run_join("i2", IGMP_JOIN_RANGE_1, "r5")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Using static routes instead OSPF: Enable OSPF between all the nodes")

    step("Start traffic from Source node")

    vlan_intf_i1_s1 = "{}.{}".format(intf_i1_s1, VLAN_1)
    result = app_helper.run_traffic("i1", IGMP_JOIN_RANGE_1, bind_intf=vlan_intf_i1_s1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    return True


#####################################################
#
#   Testcases
#
#####################################################


def test_pim_source_dr_functionality_while_rebooting_dr_non_dr_nodes_p1(request):
    """
    Verify mroute while rebooting DR /Non DR nodes( r1, r2 , r3 on all the nodes)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = pre_config_for_source_dr_tests(tgen, topo, tc_name, "r1", "r3")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R1 is the DR , verify using 'show ip pim interface json'")

    vlan_intf_r1_s1 = "{}.{}".format(intf_r1_s1, VLAN_1)
    input_dict_dr = {
        "r1": {
            "pim": {
                "interfaces": {vlan_intf_r1_s1: {"drAddress": SAME_VLAN_IP_3["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R2 is transit router for I1 to reach R4, mroute should have (s, g) mroute with "
        "OIL towards R4, using 'show ip mroute json'"
    )
    step(
        "R2 (s, g) upstream should be in join state verify using "
        "'show ip pim upstream json'"
    )
    step(
        "R1 has (S, G) mroute with NONE OIL and upstream as not joined, verify using "
        "'show ip mroute json' 'show ip pim upstream json'"
    )

    source_i1 = SAME_VLAN_IP_4["ip"]
    input_dict_r1_r2 = [
        {
            "dut": "r1",
            "src_address": source_i1,
            "oil": "none",
            "iif": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r2",
            "src_address": source_i1,
            "oil": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "iif": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
    ]

    for data in input_dict_r1_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        if data["dut"] == "r2":
            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )
        else:
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
                "Upstream is still joined state \n Error: {}".format(tc_name, result)
            )

    step("Reboot R3 node")
    stop_router(tgen, "r3")

    step(
        "After reboot of R3 verify R1 continues to be DR, using 'show ip pim interface json'"
    )

    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R3 should not have any mroute and upstream")
    step("R2 has mroute with OIL towards R4 /R1 , verify using 'show ip mroute'")
    step(
        "R2 has upstream with Join RejP state verify using 'show ip pim upstream json'"
    )
    step("R1 has mroute with none OIL and upstream with Not Join")

    for data in input_dict_r1_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        if data["dut"] == "r2":
            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )
        else:
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
                "Upstream is still joined state \n Error: {}".format(tc_name, result)
            )

    step("Reboot R2 node")
    stop_router(tgen, "r2")

    step(
        "After reboot of R2, R1 continues to be DR verify using 'show ip pim interface json'"
    )

    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R3 and R2 should not have any mroute and upstream , verify using "
        "'show ip mroute json' 'show ip pim upstream json'"
    )
    step("R1 has mroute created with empty OIL, using 'show ip mroute json'")
    step(
        "R1 has upstream with Not Join, Rej Prune , verify using 'show ip pim upstream json'"
    )

    for data in input_dict_r1_r2:
        if data["dut"] == "r1":
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
                tgen,
                data["dut"],
                data["iif"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n "
                "Upstream is still joined state \n Error: {}".format(tc_name, result)
            )

    step("Reboot R1 node using FRR stop")
    stop_router(tgen, "r1")

    step(
        "After stop of all the routers, verify upstream and mroutes should "
        "not present in any of them"
    )

    for data in input_dict_r1_r2:
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
        ), "Testcase {} : Failed \n " "mroutes are still present \n Error: {}".format(
            tc_name, result
        )

    step("start FRR for all the nodes")
    start_router(tgen, "r1")
    start_router(tgen, "r2")
    start_router(tgen, "r3")

    step("After start of all the routers, R1 became DR")

    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_r1_r2:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        if data["dut"] == "r2":
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
