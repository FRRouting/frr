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
TC_8:
    Verify mroute when transit router present between DR and RP
TC_16:
    Verify mroutes when transit router present between RP and Source DR
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
    kill_router_daemons,
    start_router_daemons,
    create_static_routes,
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
    verify_igmp_groups,
)
from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json

# Reading the data from JSON File for topology creation
jsonFile = "{}/multicast_pim_dr_nondr_topo3.json".format(CWD)
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

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

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

    global intf_r1_s1, intf_r1_s1_addr, intf_r2_s1, intf_r2_s1_addr, intf_i1_s1, intf_i1_s1_addr

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

    intf_i1_s1 = topo["routers"]["i1"]["links"]["s1"]["interface"]
    intf_i1_s1_addr = topo["routers"]["i1"]["links"]["s1"]["ipv4"]

    if lowest_priority == "r1":
        lowest_pr_intf = intf_r1_s1
    else:
        lowest_pr_intf = intf_r2_s1

    if highest_priority == "r1":
        highest_pr_intf = intf_r1_s1
    else:
        highest_pr_intf = intf_r2_s1

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
        highest_priority: {
            "vlan": {
                VLAN_1: [
                    {
                        highest_pr_intf: {
                            "ip": SAME_VLAN_IP_2["ip"],
                            "subnet": SAME_VLAN_IP_2["subnet"],
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
        highest_priority: {
            "raw_config": [
                "interface {}.{}".format(highest_pr_intf, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
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

    for dut, intf in zip(["r1", "r2"], [intf_r1_s1, intf_r2_s1]):
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

    step("Enable OSPF between r1 and r2")

    for dut, intf in zip(["r1", "r2"], [intf_r1_s1, intf_r2_s1]):
        raw_config = {
            dut: {
                "raw_config": [
                    "interface {}.{}".format(intf, VLAN_1),
                    "ip ospf area 0.0.0.0",
                    "ip ospf dead-interval 4",
                    "ip ospf hello-interval 1",
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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

    global intf_r1_s1, intf_r1_s1_addr, intf_r2_s1, intf_r2_s1_addr, intf_i1_s1, intf_i1_s1_addr

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

    intf_i1_s1 = topo["routers"]["i1"]["links"]["s1"]["interface"]
    intf_i1_s1_addr = topo["routers"]["i1"]["links"]["s1"]["ipv4"]

    if lowest_priority == "r1":
        lowest_pr_intf = intf_r1_s1
    else:
        lowest_pr_intf = intf_r2_s1

    if highest_priority == "r1":
        highest_pr_intf = intf_r1_s1
    else:
        highest_pr_intf = intf_r2_s1

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
        highest_priority: {
            "vlan": {
                VLAN_1: [
                    {
                        highest_pr_intf: {
                            "ip": SAME_VLAN_IP_2["ip"],
                            "subnet": SAME_VLAN_IP_2["subnet"],
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
        highest_priority: {
            "raw_config": [
                "interface {}.{}".format(highest_pr_intf, VLAN_1),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
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

    for dut, intf in zip(["r1", "r2"], [intf_r1_s1, intf_r2_s1]):
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

    step("Enable OSPF between r1 and r2")

    for dut, intf in zip(["r1", "r2"], [intf_r1_s1, intf_r2_s1]):
        raw_config = {
            dut: {
                "raw_config": [
                    "interface {}.{}".format(intf, VLAN_1),
                    "ip ospf area 0.0.0.0",
                    "ip ospf dead-interval 4",
                    "ip ospf hello-interval 1",
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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


def test_mroute_when_transit_router_present_between_reciever_dr_non_dr_nodes_p1(
    request,
):
    """
    TC_8:
    Verify mroute when transit router present between DR and RP
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

    result = pre_config_for_receiver_dr_tests(tgen, topo, tc_name, "r1", "r2")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taken care in base config: Add router R6 between R4 and DR non DR node")

    step(
        "On DR node R1, verify (*,G) and (S,G) created with IIF as R6 transit "
        "node using 'show ip pim mroute json'"
    )
    step(
        "On DR node R1 , verify upstream created with IIF as R6 transit node using"
        "'show ip pim upstream json'"
    )
    step("R6 has (S,G) and (*,G) created OIL toward R4")

    source_i2 = topo["routers"]["i2"]["links"]["r5"]["ipv4"].split("/")[0]
    input_dict_r1_r6 = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r6"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r6"]["interface"],
            "oil": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
        },
        {
            "dut": "r6",
            "src_address": "*",
            "iif": topo["routers"]["r6"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r6"]["links"]["r1"]["interface"],
        },
        {
            "dut": "r6",
            "src_address": source_i2,
            "iif": topo["routers"]["r6"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r6"]["links"]["r1"]["interface"],
        },
    ]

    for data in input_dict_r1_r6:
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

    write_test_footer(tc_name)


def test_mroute_when_transit_router_present_between_rp_and_source_dr_p1(request):
    """
    TC_16:
    Verify mroutes when transit router present between RP and Source DR
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

    result = pre_config_for_source_dr_tests(tgen, topo, tc_name, "r1", "r2")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taken care in base config: Add router R6 between RP and R1 , R2")

    step("R1 is the DR, mroute and upstream created on R1")

    vlan_intf_r1_s1 = "{}.{}".format(intf_r1_s1, VLAN_1)
    input_dict_dr = {
        "r1": {
            "pim": {
                "interfaces": {vlan_intf_r1_s1: {"drAddress": SAME_VLAN_IP_2["ip"]}}
            }
        }
    }
    result = verify_pim_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("On R1 Mroute OIL towards R6, upstream in join Rej Prune state")

    source_i1 = SAME_VLAN_IP_4["ip"]
    input_dict_r1 = [
        {
            "dut": "r1",
            "src_address": source_i1,
            "oil": topo["routers"]["r1"]["links"]["r6"]["interface"],
            "iif": "{}.{}".format(
                topo["routers"]["r1"]["links"]["s1"]["interface"], VLAN_1
            ),
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
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R5 have mroute created and traffic is received, verify using "
        "'show ip mroute json' 'show ip multicast json'"
    )

    input_dict_r5 = [
        {
            "dut": "r5",
            "src_address": "*",
            "iif": topo["routers"]["r5"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r5"]["links"]["i2"]["interface"],
        },
        {
            "dut": "r5",
            "src_address": source_i1,
            "iif": topo["routers"]["r5"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r5"]["links"]["i2"]["interface"],
        },
    ]

    for data in input_dict_r5:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_traffic_r5 = {
        "r5": {
            "traffic_received": [topo["routers"]["r5"]["links"]["r4"]["interface"]],
            "traffic_sent": [topo["routers"]["r5"]["links"]["i2"]["interface"]],
        }
    }

    result = verify_multicast_traffic(tgen, input_dict_traffic_r5)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Make R2 as DR configuring higher priority value")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}.{}".format(intf_r1_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_1["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_1["ip"], SAME_VLAN_IP_1["cidr"]),
            ]
        },
        "r2": {
            "raw_config": [
                "interface {}.{}".format(intf_r2_s1, VLAN_1),
                "no ip address {}/{}".format(
                    SAME_VLAN_IP_1["ip"], SAME_VLAN_IP_1["cidr"]
                ),
                "ip address {}/{}".format(SAME_VLAN_IP_2["ip"], SAME_VLAN_IP_2["cidr"]),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("R2 is the DR, mroute and upstream created on R2")

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

    step("On R2 mroute OIL towards R6 , upstream in join Rej Prune state")
    step(
        "R5 have mroute created and traffic is received, verify using "
        "'show ip mroute json' 'show ip multicast json'"
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
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "R5 have mroute created and traffic is received, verify using "
        "'show ip mroute json' 'show ip multicast json'"
    )

    for data in input_dict_r5:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_multicast_traffic(tgen, input_dict_traffic_r5)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
