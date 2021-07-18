#!/usr/bin/env python

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
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
Following tests are covered to test multicast pim sm:

Test steps
- Create topology (setup module)
- Bring up topology

Following tests are covered:
TC_1:
    Verify mroute while rebooting DR /Non DR nodes( r1, r2 , r3 on all
    the nodes)
TC_2:
    Verify mroutes while changing IP address of DR/Non DR ( r1, r2 , r3 on all
    the nodes)
TC_3:
    Verify mroute while changing DR priority on DR / Non DR( r1, r2 , r3 on
    all the nodes)
TC_10:
    Verify mroute while rebooting DR /Non DR nodes( r1, r2 , r3 on all the nodes)
TC_11:
    Verify mroute, while changing ip address on DR / Non DR( r1, r2 , r3 on
    all the nodes)
TC_12:
    Verify mroute while changing DR priority on DR / Non DR( r1, r2, r3 on all
    the nodes)
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
from mininet.topo import Topo

from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    step,
    iperfSendIGMPJoin,
    addKernelRoute,
    reset_config_on_routers,
    iperfSendTraffic,
    kill_iperf,
    shutdown_bringup_interface,
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
    verify_ip_mroutes,
    clear_ip_mroute,
    clear_ip_pim_interface_traffic,
    verify_pim_neighbors,
    verify_pim_config,
    verify_upstream_iif,
    verify_multicast_traffic,
    verify_ip_pim_join,
    verify_multicast_flag_state,
)
from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json

# Reading the data from JSON File for topology creation
jsonFile = "{}/multicast_pim_dr_nondr_topo1.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

HELLO_TIMER = 1
HOLD_TIMER = 3

TOPOLOGY = """

         r5 --- i2
         |
         |
     --- r4 ----
    |           |
    |           |
    r1 -- s1 -- r2
          |
          |
    i1 -- r3

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


class CreateTopo(Topo):
    """
    Test BasicTopo - topology 1

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        """Build function"""
        tgen = get_topogen(self)

        # Building topology from json file
        build_topo_from_json(tgen, topo)


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.14")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)
    logger.info("Master Topology: \n {}".format(TOPOLOGY))

    logger.info("Running setup_module to create topology")

    tgen = Topogen(CreateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen, topo)

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen, daemons)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    try:
        # Stop toplogy and Remove tmp files
        tgen.stop_topology()

    except OSError:
        # OSError exception is raised when mininet tries to stop switch
        # though switch is stopped once but mininet tries to stop same
        # switch again, where it ended up with exception
        pass

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#   Local APIs
#
#####################################################


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
        if result is not True:
            return result

        router_list = tgen.routers()
        for router in router_list.keys():
            if router == iperf:
                continue

            rnode = router_list[router]
            rnode.run("echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter")

    return True


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
    input_join = {"i1": vlan_intf_i1_s1}

    for recvr, recvr_intf in input_join.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, recvr, vlan_intf_i1_s1, GROUP_RANGE_1, join=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendIGMPJoin(tgen, recvr, IGMP_JOIN_RANGE_1, join_interval=1)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Using static routes instead OSPF: Enable OSPF between all the nodes")

    step("Start traffic from R4 connected source")

    input_src = {"i2": topo["routers"]["i2"]["links"]["r5"]["interface"]}

    for src, src_intf in input_src.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, src, src_intf, GROUP_RANGE_1, traffic=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendTraffic(tgen, src, IGMP_JOIN_RANGE_1, 32, 2500)
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

    for recvr, recvr_intf in input_src.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, recvr, recvr_intf, GROUP_RANGE_1, join=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendIGMPJoin(tgen, recvr, IGMP_JOIN_RANGE_1, join_interval=1)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Using static routes instead OSPF: Enable OSPF between all the nodes")

    step("Start traffic from Source node")

    vlan_intf_i1_s1 = "{}.{}".format(intf_i1_s1, VLAN_1)
    input_join = {"i1": vlan_intf_i1_s1}

    for src, src_intf in input_join.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, src, src_intf, GROUP_RANGE_1, traffic=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendTraffic(tgen, src, IGMP_JOIN_RANGE_1, 32, 2500)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    return True


#####################################################
#
#   Testcases
#
#####################################################


def pim_receiver_dr_functionality_while_rebooting_dr_non_dr_nodes_p1(request):
    """
    TC_1:
    Verify mroute while rebooting DR /Non DR nodes( r1, r2 , r3 on all the nodes)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = pre_config_for_receiver_dr_tests(tgen, topo, tc_name, "r3", "r1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R3 is the DR , verify using 'show ip pim interface json'")

    vlan_intf_r3_s1 = "{}.{}".format(intf_r3_s1, VLAN_1)
    input_dict_dr = {
        "r3": {
            "pim": {
                "interfaces": {vlan_intf_r3_s1: {"drAddress": SAME_VLAN_IP_3["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R3 has (*, G) mroute created with IIF toward (R1 or R2 based on RP "
        "reachability ) and OIL with PIMreg only, no other interface should "
        "present in OIL"
    )

    step(
        "R1 has (*,G) and (S,G) mroutes created with S flag joined via PIM "
        "verify using 'show ip mroute json' 'show ip pim upstream json'"
    )

    step(
        "R1 (S,G) has OIL created toward switch connected interface, traffic "
        "is received on switch interface using 'show ip mroute json' "
        "'show ip pim upstream json'"
    )

    step("R1 (S,G) and (*,G) IIF toward RP/source interface")

    step(
        "R2 should not have any mroutes and upstream created using "
        "'show ip mroute json' 'show ip pim upstream json'"
    )

    source_i2 = topo["routers"]["i2"]["links"]["r5"]["ipv4"].split("/")[0]
    input_dict_r1_r3 = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r3",
            "src_address": "*",
            "oil": "pimreg",
            "iif": "{}.{}".format(
                topo["routers"]["r3"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
    ]

    for data in input_dict_r1_r3:
        if data["dut"] == "r2":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    for dut, flag in zip(["r3", "r1"], ["SC", "S"]):
        step("{} has (*,G) flag as {}".format(dut, flag))
        result = verify_multicast_flag_state(tgen, dut, "*", IGMP_JOIN_RANGE_1, flag)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop R3 node")
    stop_router(tgen, "r3")

    step(
        "After reboot of R3 node , verify R2 became DR , R2 has created "
        "mroute with OIL towards switch port and IIF towards RP , using "
        "'show ip mroute' 'show ip pim interface'"
    )

    vlan_intf_r2_s1 = "{}.{}".format(intf_r2_s1, VLAN_1)
    input_dict_dr = {
        "r2": {
            "pim": {
                "interfaces": {vlan_intf_r2_s1: {"drAddress": SAME_VLAN_IP_2["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i2"]["links"]["r5"]["ipv4"].split("/")[0]

    input_dict_r1_r2 = [
        {
            "dut": "r2",
            "src_address": "*",
            "iif": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
    ]

    for data in input_dict_r1_r2:
        if data["dut"] == "r1":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    for dut, flag in zip(["r2"], ["SC"]):
        step("{} has (*,G) flag as {}".format(dut, flag))
        result = verify_multicast_flag_state(tgen, dut, "*", IGMP_JOIN_RANGE_1, flag)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("start r3 router")
    start_router(tgen, "r3")

    step(
        "After R3 come up, verify (*,G) created on R3 with pimreg only OIL, "
        "and R1 has (*,G) mroute created PIM flag (S,G) created with OIL as "
        "switch interface , verify using 'show ip mroute json' "
        "'show ip pim upstream json'"
    )

    for data in input_dict_r1_r3:
        if data["dut"] == "r2":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    step("Stop R2 and R3 node")
    stop_router(tgen, "r2")
    stop_router(tgen, "r3")

    step(
        "After reboot of R2 and R3 , R1 became DR , verify using "
        "'show ip pim interface'"
    )

    vlan_intf_r1_s1 = "{}.{}".format(intf_r1_s1, VLAN_1)
    input_dict_dr = {
        "r1": {
            "pim": {
                "interfaces": {vlan_intf_r1_s1: {"drAddress": SAME_VLAN_IP_1["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R1 should have (*,G) flag as SC")

    for dut, flag in zip(["r1"], ["SC"]):
        step("{} has (*,G) flag as {}".format(dut, flag))
        result = verify_multicast_flag_state(tgen, dut, "*", IGMP_JOIN_RANGE_1, flag)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) mroute created where IIF is R1 to RP connected interface "
        "and OIL toward switch interface , using 'show ip mroute'"
    )

    for data in input_dict_r1_r3:
        if data["dut"] == "r1":
            result = verify_ip_mroutes(
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

    step("Start R2 and R3 node")
    start_router(tgen, "r2")
    start_router(tgen, "r3")

    step(
        "After R3 come up , verify (*,G) created on R3 with pimreg only OIL, "
        "and R1 has (*,G) mroute created PIM flag (S,G) created with OIL as "
        "switch interface , verify using 'show ip mroute json' "
        "'show ip pim upstream json'"
    )

    for data in input_dict_r1_r3:
        if data["dut"] == "r2":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    step("Stop R1 and R2 node")
    stop_router(tgen, "r1")
    stop_router(tgen, "r2")

    step(
        "After reboot of R1 and R2, verify mroute got cleared from R3, "
        "as no path to upstream nbr, using 'show ip mroute' 'show ip multicast'"
    )

    for data in input_dict_r1_r3:
        if data["dut"] == "r3":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )

    step("Start R1 and R2 node")
    start_router(tgen, "r1")
    start_router(tgen, "r2")

    step("After R3 come up entries are created as per verification steps 8")

    for data in input_dict_r1_r3:
        if data["dut"] == "r2":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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


def mroutes_while_changing_ip_address_of_receiver_dr_non_dr_nodes_p1(request):
    """
    TC_2:
    Verify mroutes while changing IP address of DR/Non DR ( r1, r2 , r3 on all the nodes)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Creating configuration from JSON
    kill_iperf(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = pre_config_for_receiver_dr_tests(tgen, topo, tc_name, "r3", "r1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R3 is the DR , verify using 'show ip pim interface json'")

    vlan_intf_r3_s1 = "{}.{}".format(intf_r3_s1, VLAN_1)
    input_dict_dr = {
        "r3": {
            "pim": {
                "interfaces": {vlan_intf_r3_s1: {"drAddress": SAME_VLAN_IP_3["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R3 has (*, G) mroute created with IIF toward (R1 or R2 based on RP "
        "reachability ) and OIL with PIMreg only, no other interface should "
        "present in OIL"
    )

    step(
        "R1 has (*,G) and (S,G) mroutes created with S flag joined via PIM "
        "verify using 'show ip mroute json' 'show ip pim upstream json'"
    )

    step(
        "R1 (S,G) has OIL created toward switch connected interface, traffic "
        "is received on switch interface using 'show ip mroute json' "
        "'show ip pim upstream json'"
    )

    step("R1 (S,G) and (*,G) IIF toward RP/source interface")

    step(
        "R2 should not have any mroutes and upstream created using "
        "'show ip mroute json' 'show ip pim upstream json'"
    )

    source_i2 = topo["routers"]["i2"]["links"]["r5"]["ipv4"].split("/")[0]

    input_dict_r1_r3 = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r3",
            "src_address": "*",
            "oil": "pimreg",
            "iif": "{}.{}".format(
                topo["routers"]["r3"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
    ]

    for data in input_dict_r1_r3:
        if data["dut"] == "r2":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    for dut, flag in zip(["r3", "r1"], ["SC", "S"]):
        step("{} has (*,G) flag as {}".format(dut, flag))
        result = verify_multicast_flag_state(tgen, dut, "*", IGMP_JOIN_RANGE_1, flag)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Change higher IP to R1 switch connected port")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}.{}".format(intf_r1_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_1["ip"], SAME_VLAN_IP_1["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]),
            ]
        },
        "r3": {
            "raw_config": [
                "interface {}.{}".format(intf_r3_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_1["ip"], SAME_VLAN_IP_1["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R1 became DR, verify using 'show ip pim interface' (*,G) and "
        "(S,G) mroutes present on R1 only , verify using 'show ip mroute json'"
        "'show ip pim upstream'"
    )
    step(
        "R1 (*,G) should have IGMP only created entries verify using "
        "show ip pim upstream json' PIM should sould get reoved"
    )
    step(
        "R2 and R3 should not have any mroutes entries verify using "
        "'show ip mroute json'"
    )

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

    for data in input_dict_r1_r3:
        if data["dut"] == "r2" or data["dut"] == "r3":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    step("Change higher IP to R2 switch connected port")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}.{}".format(intf_r1_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}.{}".format(intf_r2_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After changing higher IP to R2 became DR using"
        "'show ip pim interface json' , verify R2 has (*,G) and (S,G) "
        "mroutes created using 'show ip mroute'"
    )
    step("R1 and R3 node should not have any mroutes created " "show ip mroute json'")

    vlan_intf_r2_s1 = "{}.{}".format(intf_r2_s1, VLAN_1)
    input_dict_dr = {
        "r2": {
            "pim": {
                "interfaces": {vlan_intf_r2_s1: {"drAddress": SAME_VLAN_IP_3["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_r1_r3:
        if data["dut"] == "r2":
            result = verify_ip_mroutes(
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

    step("(*,G) should have SC flag")

    for dut, flag in zip(["r2"], ["SC"]):
        step("{} has (*,G) flag as {}".format(dut, flag))
        result = verify_multicast_flag_state(tgen, dut, "*", IGMP_JOIN_RANGE_1, flag)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Make R1 DR again lowering IP address from R2 switch connected port")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}.{}".format(intf_r1_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]),
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}.{}".format(intf_r2_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After changing lower IP to R2, R1 became DR using "
        "show ip pim interface json' , verify R1 has (*,G) and (S,G) mroutes "
        "created using 'show ip mroute'"
    )
    step("R2 and R3 node should not have any mroutes created " "show ip mroute json'")

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

    for data in input_dict_r1_r3:
        if data["dut"] == "r2" or data["dut"] == "r3":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    step("(*,G) should have SC flag")

    for dut, flag in zip(["r1"], ["SC"]):
        step("{} has (*,G) flag as {}".format(dut, flag))
        result = verify_multicast_flag_state(tgen, dut, "*", IGMP_JOIN_RANGE_1, flag)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def mroutes_while_changing_dr_priority_receiver_dr_non_dr_nodes_p1(request):
    """
    TC_3:
    Verify mroute while changing DR priority on DR / Non DR( r1, r2 , r3 on all the nodes)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = pre_config_for_receiver_dr_tests(tgen, topo, tc_name, "r3", "r1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Make R2 node to higher priority")

    vlan_intf_r2_s1 = "{}.{}".format(intf_r2_s1, VLAN_1)
    raw_config = {
        "r2": {
            "raw_config": [
                "interface {}".format(vlan_intf_r2_s1),
                "ip pim drpriority 200",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R2 became DR , verify using 'show ip pim interface' "
        "(*,G) and (S,G) mroutes present on R2 only , verify using "
        "'show ip mroute json' 'show ip pim upstream'"
    )
    step(
        "R2 (*,G) should have IGMP onlt created entries verify using "
        "'show ip pim upstream json'"
    )
    step(
        "R1 and R3 should not have any mroutes entries verify using "
        "'show ip mroute json'"
    )

    input_dict_dr = {
        "r2": {
            "pim": {
                "interfaces": {vlan_intf_r2_s1: {"drAddress": SAME_VLAN_IP_2["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i2"]["links"]["r5"]["ipv4"].split("/")[0]
    input_dict_r1_r3 = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r3",
            "src_address": "*",
            "oil": "pimreg",
            "iif": "{}.{}".format(
                topo["routers"]["r3"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
    ]

    for data in input_dict_r1_r3:
        if data["dut"] == "r1" or data["dut"] == "r3":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    step("Make R1 node to higher priority")
    step("Configure R1 lower ip and higher priority")

    vlan_intf_r1_s1 = "{}.{}".format(intf_r1_s1, VLAN_1)
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(vlan_intf_r1_s1),
                "ip pim drpriority 210",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R1 became DR , verify using 'show ip pim interface' "
        "(*,G) and (S,G) mroutes present on R1 only , verify using "
        "'show ip mroute json' 'show ip pim upstream'"
    )
    step(
        "R1 (*,G) should have IGMP onlt created entries verify using "
        "'show ip pim upstream json'"
    )
    step(
        "R2 and R3 should not have any mroutes entries verify using "
        "'show ip mroute json'"
    )

    input_dict_dr = {
        "r1": {
            "pim": {
                "interfaces": {vlan_intf_r1_s1: {"drAddress": SAME_VLAN_IP_1["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_r1_r3:
        if data["dut"] == "r2" or data["dut"] == "r3":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    step("(*,G) should have SC flag")

    for dut, flag in zip(["r1"], ["SC"]):
        step("{} has (*,G) flag as {}".format(dut, flag))
        result = verify_multicast_flag_state(tgen, dut, "*", IGMP_JOIN_RANGE_1, flag)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Make R3 node to higher prioriy")

    vlan_intf_r3_s1 = "{}.{}".format(intf_r3_s1, VLAN_1)
    raw_config = {
        "r3": {
            "raw_config": [
                "interface {}".format(vlan_intf_r3_s1),
                "ip pim drpriority 220",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R3 became DR , verify using 'show ip pim interface' "
        "R3 has (*,G) mroute created with IIF toward (R1 or R2 based on "
        "RP reachability ) and OIL with PIMreg only , no other interface "
        "should present in OIL"
    )
    step(
        "R1 (S,G) has OIL created toward switch connected interface , traffic "
        "is received on switch interface using 'show ip mroute json' '"
        "'show ip pim upstream json'"
    )
    step(
        "R2 should not have any mroutes and upstream created using "
        "show ip mroute json' 'show ip pim upstream json'"
    )

    input_dict_dr = {
        "r3": {
            "pim": {
                "interfaces": {vlan_intf_r3_s1: {"drAddress": SAME_VLAN_IP_3["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_r1_r3:
        if data["dut"] == "r2":
            result = verify_ip_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \n"
                "mroutes are still present \n Error: {}".format(tc_name, result)
            )
        else:
            result = verify_ip_mroutes(
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

    step("R3 has (*,G) flag as SC")
    step(
        "R1 has (*,G) and (S,G) mroutes created with S flag joined via PIM "
        "verify using 'show ip mroute json' 'show ip pim upstream json'"
    )

    for dut, flag in zip(["r1", "r3"], ["S", "SC"]):
        step("{} has (*,G) flag as {}".format(dut, flag))
        result = verify_multicast_flag_state(tgen, dut, "*", IGMP_JOIN_RANGE_1, flag)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_pim_source_dr_functionality_while_rebooting_dr_non_dr_nodes_p1(request):
    """
    TC_10:
    Verify mroute while rebooting DR /Non DR nodes( r1, r2 , r3 on all the nodes)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

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
        "R2 is transit router for R3 to reach R4, mroute should have (s, g) mroute with "
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
        result = verify_ip_mroutes(
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

    step("After reboot of R3 verify R1 became DR, using 'show ip pim interface json'")

    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R3 should not have any mroute and upstream")
    step("R2 has mroute with OIL towards R4 /R1 , verify using 'show ip mroute'")
    step(
        "R2 has upstream with Join RejP state verify using 'show ip pim upstream json'"
    )
    step("R1 has mroute with none OIL and upstream with Not Join")

    for data in input_dict_r1_r2:
        result = verify_ip_mroutes(
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

    step("After reboot of R2, R1 became DR verify using 'show ip pim interface json'")

    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R3 and R2 should not have any mroute and upstream , verify using "
        "'show ip mroute json' 'show ip pim upstream json'"
    )
    step("R1 has mroute created with OIL towards R4 , using 'show ip mroute json'")
    step(
        "R1 has upstream with Join Rej Prune , verify using 'show ip pim upstream json'"
    )

    for data in input_dict_r1_r2:
        if data["dut"] == "r1":
            result = verify_ip_mroutes(
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
        result = verify_ip_mroutes(
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
            "mroutes are still present \n Error: {}".format(tc_name, result)
        )

    step("start FRR for all the nodes")
    start_router(tgen, "r1")
    start_router(tgen, "r2")
    start_router(tgen, "r3")

    step("After start of all the routers, R1 became DR")

    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_r1_r2:
        result = verify_ip_mroutes(
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

    write_test_footer(tc_name)


def mroutes_while_changing_ip_address_of_source_dr_non_dr_nodes_p1(request):
    """
    TC_11:
    Verify mroute, while changing ip address on DR / Non DR( r1, r2 , r3 on all the nodes)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = pre_config_for_source_dr_tests(tgen, topo, tc_name, "r3", "r1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Change higher IP on R1 switch connected port")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}.{}".format(intf_r1_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_1["ip"], SAME_VLAN_IP_1["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]),
            ]
        },
        "r3": {
            "raw_config": [
                "interface {}.{}".format(intf_r3_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_1["ip"], SAME_VLAN_IP_1["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After configuring higher IP on R1 , verify R1 became DR using "
        "'show ip pim interface json'"
    )

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

    step("R2 is having (S,G) mroutes towards R4 verify using 'show ip mroute json'")
    step("R2 is having upstream with Join RegP state using 'show ip pim upstream'")
    step(
        "R5 has mroute created with OIL towards receiver and IIF towards R4 side, "
        "verify using 'show ip mroute json'"
    )

    source_i1 = SAME_VLAN_IP_4["ip"]
    input_dict_r2_r5 = [
        {
            "dut": "r2",
            "src_address": source_i1,
            "oil": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "iif": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r5",
            "src_address": "*",
            "oil": topo["routers"]["r5"]["links"]["i2"]["interface"],
            "iif": topo["routers"]["r5"]["links"]["r4"]["interface"],
        },
        {
            "dut": "r5",
            "src_address": source_i1,
            "oil": topo["routers"]["r5"]["links"]["i2"]["interface"],
            "iif": topo["routers"]["r5"]["links"]["r4"]["interface"],
        },
    ]

    for data in input_dict_r2_r5:
        result = verify_ip_mroutes(
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

    step("R1 and R3 has mroute with none OIL , verify using 'show ip mroute json'")
    step(
        "R1 and R3 has upstream with Not Join state , verify using 'show ip pim upstream json'"
    )

    input_dict_r1_r3 = [
        {
            "dut": "r1",
            "src_address": source_i1,
            "iif": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
            "oil": "none",
        },
        {
            "dut": "r3",
            "src_address": source_i1,
            "iif": "{}.{}".format(
                topo["routers"]["r3"]["links"]["s1"]["interface"], VLAN_1
            ),
            "oil": "none",
        },
    ]

    for data in input_dict_r1_r3:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
            "upstream state is join \n Error: {}".format(tc_name, result)
        )

    step("Change higher ip on R2 switch connected port")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}.{}".format(intf_r1_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}.{}".format(intf_r2_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After configuring higher IP on R2, verify R2 became DR using "
        "'show ip pim interface json'"
    )

    vlan_intf_r2_s1 = "{}.{}".format(intf_r2_s1, VLAN_1)
    input_dict_dr = {
        "r2": {
            "pim": {
                "interfaces": {vlan_intf_r2_s1: {"drAddress": SAME_VLAN_IP_3["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R2 is having (S,G) mroutes towards R4 verify using 'show ip mroute json'")
    step("R2 is having upstream with Join RegP state using 'show ip pim upstream'")
    step(
        "R5 has mroute created with OIL towards receiver and IIF towards R4 side, "
        "verify using 'show ip mroute json'"
    )

    for data in input_dict_r2_r5:
        result = verify_ip_mroutes(
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

    step("R1 and R3 has mroute with none OIL , verify using 'show ip mroute json'")
    step(
        "R1 and R3 has upstream with Not Join state , verify using "
        "'show ip pim upstream json'"
    )

    for data in input_dict_r1_r3:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
            "upstream state is join \n Error: {}".format(tc_name, result)
        )

    step("Make R1 DR again lowering IP address from R2 switch connected port")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}.{}".format(intf_r1_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]),
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}.{}".format(intf_r2_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_3["ip"], SAME_VLAN_IP_3["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After configuring lower IP on R2 , verify R1 became DR using "
        "'show ip pim interface json'"
    )
    input_dict_dr = {
        "r1": {
            "pim": {
                "interfaces": {vlan_intf_r1_s1: {"drAddress": SAME_VLAN_IP_3["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R2 is having (S,G) mroutes towards R4 verify using 'show ip mroute json'")
    step("R2 is having upstream with Join RegP state using 'show ip pim upstream'")
    step(
        "R5 has mroute created with OIL towards receiver and IIF towards R4 side, "
        "verify using 'show ip mroute json'"
    )

    for data in input_dict_r2_r5:
        result = verify_ip_mroutes(
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

    step("R1 and R3 has mroute with none OIL , verify using 'show ip mroute json'")
    step(
        "R1 and R3 has upstream with Not Join state , verify using 'show ip pim upstream json'"
    )

    for data in input_dict_r1_r3:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
            "upstream state is join \n Error: {}".format(tc_name, result)
        )

    write_test_footer(tc_name)


def mroutes_while_changing_dr_priority_source_dr_non_dr_nodes_p1(request):
    """
    TC_12:
    Verify mroute while changing DR priority on DR / Non DR( r1, r2, r3 on all the nodes)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = pre_config_for_source_dr_tests(tgen, topo, tc_name, "r3", "r1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Make R2 node to higher priority")

    vlan_intf_r2_s1 = "{}.{}".format(intf_r2_s1, VLAN_1)
    raw_config = {
        "r2": {
            "raw_config": [
                "interface {}".format(vlan_intf_r2_s1),
                "ip pim drpriority 200",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After configuring priority on R2 , verify R2 became DR using "
        "show ip pim interface json'"
    )

    vlan_intf_r2_s1 = "{}.{}".format(intf_r2_s1, VLAN_1)
    input_dict_dr = {
        "r2": {
            "pim": {
                "interfaces": {vlan_intf_r2_s1: {"drAddress": SAME_VLAN_IP_2["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R2 is having (S,G) mroutes towards R4 verify using 'show ip mroute json'")
    step("R2 is having upstream with Join RegP state using 'show ip pim upstream'")
    step(
        "R5 has mroute created with OIL towards receiver and IIF towards R4 side, "
        "verify using 'show ip mroute json'"
    )

    source_i1 = SAME_VLAN_IP_4["ip"]
    input_dict_r2_r5 = [
        {
            "dut": "r2",
            "src_address": source_i1,
            "oil": topo["routers"]["r2"]["links"]["r4"]["interface"],
            "iif": "{}.{}".format(
                topo["routers"]["r2"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r5",
            "src_address": "*",
            "oil": topo["routers"]["r5"]["links"]["i2"]["interface"],
            "iif": topo["routers"]["r5"]["links"]["r4"]["interface"],
        },
        {
            "dut": "r5",
            "src_address": source_i1,
            "oil": topo["routers"]["r5"]["links"]["i2"]["interface"],
            "iif": topo["routers"]["r5"]["links"]["r4"]["interface"],
        },
    ]

    for data in input_dict_r2_r5:
        result = verify_ip_mroutes(
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

    step("R1 has mroute with none OIL , verify using 'show ip mroute json'")
    step(
        "R1 has upstream with Not Join state , verify using "
        "show ip pim upstream json'"
    )

    input_dict_r1 = [
        {
            "dut": "r1",
            "src_address": source_i1,
            "iif": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
            "oil": "none",
        }
    ]

    for data in input_dict_r1:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
            "upstream state is join \n Error: {}".format(tc_name, result)
        )

    step("Make R1 node to higher priority")
    step("Configure R1 lower ip and higher priority")

    vlan_intf_r1_s1 = "{}.{}".format(intf_r1_s1, VLAN_1)
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(vlan_intf_r1_s1),
                "ip pim drpriority 210",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After configuring priority on R1, verify R1 became DR using "
        "show ip pim interface json'"
    )

    vlan_intf_r1_s1 = "{}.{}".format(intf_r1_s1, VLAN_1)
    input_dict_dr = {
        "r1": {
            "pim": {
                "interfaces": {vlan_intf_r1_s1: {"drAddress": SAME_VLAN_IP_1["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R2 is having (S,G) mroutes towards R4 verify using 'show ip mroute json'")
    step("R2 is having upstream with Join RegP state using 'show ip pim upstream'")
    step(
        "R5 has mroute created with OIL towards receiver and IIF towards R4 side, "
        "verify using 'show ip mroute json'"
    )

    for data in input_dict_r2_r5:
        result = verify_ip_mroutes(
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

    step("R1 has mroute with none OIL , verify using 'show ip mroute json'")
    step(
        "R1 has upstream with Not Join state , verify using "
        "show ip pim upstream json'"
    )

    for data in input_dict_r1:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
            "upstream state is join \n Error: {}".format(tc_name, result)
        )

    step("Make R3 node to higher prioriy")

    vlan_intf_r3_s1 = "{}.{}".format(intf_r3_s1, VLAN_1)
    raw_config = {
        "r3": {
            "raw_config": [
                "interface {}".format(vlan_intf_r3_s1),
                "ip pim drpriority 220",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After configuring priority on R3, verify R3 became DR using "
        "show ip pim interface json'"
    )

    vlan_intf_r3_s1 = "{}.{}".format(intf_r3_s1, VLAN_1)
    input_dict_dr = {
        "r3": {
            "pim": {
                "interfaces": {vlan_intf_r3_s1: {"drAddress": SAME_VLAN_IP_3["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R2 is having (S,G) mroutes towards R4 verify using 'show ip mroute json'")
    step("R2 is having upstream with Join RegP state using 'show ip pim upstream'")
    step(
        "R5 has mroute created with OIL towards receiver and IIF towards R4 side, "
        "verify using 'show ip mroute json'"
    )

    for data in input_dict_r2_r5:
        result = verify_ip_mroutes(
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

    step("R1 has mroute with none OIL , verify using 'show ip mroute json'")
    step(
        "R1 has upstream with Not Join state , verify using "
        "show ip pim upstream json'"
    )

    for data in input_dict_r1:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
            "upstream state is join \n Error: {}".format(tc_name, result)
        )

    step("Lower priority on R3 to make R1 as DR")

    vlan_intf_r3_s1 = "{}.{}".format(intf_r3_s1, VLAN_1)
    raw_config = {
        "r3": {
            "raw_config": [
                "interface {}".format(vlan_intf_r3_s1),
                "ip pim drpriority 100",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After configuring priority on R3, verify R1 became DR using "
        "show ip pim interface json'"
    )

    vlan_intf_r1_s1 = "{}.{}".format(intf_r1_s1, VLAN_1)
    input_dict_dr = {
        "r1": {
            "pim": {
                "interfaces": {vlan_intf_r1_s1: {"drAddress": SAME_VLAN_IP_1["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R2 is having (S,G) mroutes towards R4 verify using 'show ip mroute json'")
    step("R2 is having upstream with Join RegP state using 'show ip pim upstream'")
    step(
        "R5 has mroute created with OIL towards receiver and IIF towards R4 side, "
        "verify using 'show ip mroute json'"
    )

    for data in input_dict_r2_r5:
        result = verify_ip_mroutes(
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

    step("R1 has mroute with none OIL , verify using 'show ip mroute json'")
    step(
        "R1 has upstream with Not Join state , verify using "
        "show ip pim upstream json'"
    )

    for data in input_dict_r1:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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
            "upstream state is join \n Error: {}".format(tc_name, result)
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
