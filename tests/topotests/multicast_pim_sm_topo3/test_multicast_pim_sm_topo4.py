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

1. TC:48 Verify mroute after configuring black-hole route for RP and source
2. TC:49 Verify mroute when RP is reachable using default route
3. TC:50 Verify mroute when LHR,FHR,RP and transit routers reachable
    using default routes
4. TC:52 Verify PIM nbr after changing interface ip
5. TC:53 Verify IGMP interface updated with correct detail after changing interface config
6. TC:54 Verify received and transmit hello stats are getting cleared after PIM nbr reset


"""

import os
import re
import sys
import json
import time
import datetime
from time import sleep
import pytest

pytestmark = pytest.mark.pimd

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
    start_router,
    stop_router,
    apply_raw_config,
    create_static_routes,
    required_linux_kernel_version,
    topo_daemons,
)
from lib.pim import (
    create_pim_config,
    create_igmp_config,
    verify_igmp_groups,
    verify_ip_mroutes,
    clear_ip_pim_interface_traffic,
    verify_igmp_config,
    verify_pim_neighbors,
    verify_pim_config,
    verify_pim_interface,
    verify_upstream_iif,
    clear_ip_mroute,
    verify_multicast_traffic,
    verify_pim_rp_info,
    verify_pim_interface_traffic,
    verify_igmp_interface,
)
from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json

# Reading the data from JSON File for topology creation
jsonFile = "{}/multicast_pim_sm_topo4.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

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
NEW_ADDRESS_1 = "192.168.20.1"
NEW_ADDRESS_2 = "192.168.20.2"
NEW_ADDRESS_1_SUBNET = "192.168.20.1/24"
NEW_ADDRESS_2_SUBNET = "192.168.20.2/24"


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
    result = required_linux_kernel_version("4.19")
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

        for router in topo["routers"].keys():
            if "static_routes" in topo["routers"][router]:
                static_routes = topo["routers"][router]["static_routes"]
                for static_route in static_routes:
                    network = static_route["network"]
                    next_hop = static_route["next_hop"]
                    if type(network) is not list:
                        network = [network]

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
        for state, value in state_data.items():
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


def test_mroute_when_RP_reachable_default_route_p2(request):
    """
    TC_49 Verify mroute when and source RP is reachable using default route
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step(
        "Remove c1-c2 connected link to simulate topo "
        "c1(FHR)---l1(RP)----r2---f1-----c2(LHR)"
    )

    intf_c1_c2 = topo["routers"]["c1"]["links"]["c2"]["interface"]
    intf_c2_c1 = topo["routers"]["c2"]["links"]["c1"]["interface"]
    shutdown_bringup_interface(tgen, "c1", intf_c1_c2, False)
    shutdown_bringup_interface(tgen, "c2", intf_c2_c1, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (225.1.1.1-5)"
    )

    intf_c2_i5 = topo["routers"]["c2"]["links"]["i5"]["interface"]
    input_dict = {
        "c2": {"igmp": {"interfaces": {intf_c2_i5: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i5": topo["routers"]["i5"]["links"]["c2"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, recvr, recvr_intf, GROUP_RANGE_1, join=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendIGMPJoin(tgen, recvr, IGMP_JOIN_RANGE_1, join_interval=1)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (225.1.1.1-5) as R2")

    input_dict = {
        "l1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["l1"]["links"]["lo"]["ipv4"].split(
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

    step("Send traffic from C1 to all the groups ( 225.1.1.1 to 225.1.1.5)")

    input_src = {"i4": topo["routers"]["i4"]["links"]["c1"]["interface"]}

    for src, src_intf in input_src.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, src, src_intf, GROUP_RANGE_1, traffic=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendTraffic(tgen, src, IGMP_JOIN_RANGE_1, 32, 2500)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i4 = topo["routers"]["i4"]["links"]["c1"]["ipv4"].split("/")[0]

    input_dict_starg = [
        {
            "dut": "c2",
            "src_address": "*",
            "iif": topo["routers"]["c2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["c2"]["links"]["i5"]["interface"],
        }
    ]

    input_dict_sg = [
        {
            "dut": "c2",
            "src_address": source_i4,
            "iif": topo["routers"]["c2"]["links"]["f1"]["interface"],
            "oil": topo["routers"]["c2"]["links"]["i5"]["interface"],
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_sg:
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

    for data in input_dict_starg:
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

    step("Delete static routes on c2")
    input_dict = {
        "c2": {
            "static_routes": [
                {
                    "network": ["1.0.4.11/32", "10.0.2.1/24", "10.0.1.2/24"],
                    "next_hop": "10.0.3.2",
                    "delete": True,
                }
            ]
        }
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info unknown after removing static route from c2 ")
    dut = "c2"
    rp_address = topo["routers"]["l1"]["links"]["lo"]["ipv4"].split("/")[0]
    SOURCE = "Static"
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify mroute not present after Delete of static routes on c1")

    for data in input_dict_sg:
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
            "mroutes(S,G) are present after delete of static routes on c1 \n Error: {}".format(
                tc_name, result
            )
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
            "upstream is present after delete of static routes on c1 \n Error: {}".format(
                tc_name, result
            )
        )

    for data in input_dict_starg:
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
            "mroutes(*,G) are present after delete of static routes on c1 \n Error: {}".format(
                tc_name, result
            )
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
            "upstream is present after delete of static routes on c1 \n Error: {}".format(
                tc_name, result
            )
        )

    step("Configure default routes on c2")

    intf_f1_c2 = topo["routers"]["f1"]["links"]["c2"]["ipv4"].split("/")[0]

    input_dict = {
        "c2": {"static_routes": [{"network": "0.0.0.0/0", "next_hop": intf_f1_c2}]}
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("applying ip nht config  on c2")

    raw_config = {"c2": {"raw_config": ["ip nht resolve-via-default"]}}

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify RP info is NOT unknown after removing static route from c2 ")
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "RP info is unknown after removing static route from c2 \n Error: {}".format(
            tc_name, result
        )
    )

    step("Verify (s,g) populated after adding default route ")

    for data in input_dict_sg:
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

    step("Verify (*,g) populated after adding default route ")

    for data in input_dict_starg:
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


def test_mroute_with_RP_default_route_all_nodes_p2(request):
    """
    TC_50 Verify mroute when LHR,FHR,RP and transit routers reachable
    using default routes
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step(
        "Remove c1-c2 connected link to simulate topo "
        "c1(LHR)---l1(RP)----r2---f1-----c2(FHR)"
    )

    intf_c1_c2 = topo["routers"]["c1"]["links"]["c2"]["interface"]
    intf_c2_c1 = topo["routers"]["c2"]["links"]["c1"]["interface"]
    shutdown_bringup_interface(tgen, "c1", intf_c1_c2, False)
    shutdown_bringup_interface(tgen, "c2", intf_c2_c1, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (225.1.1.1-5)"
    )

    intf_c1_i4 = topo["routers"]["c1"]["links"]["i4"]["interface"]
    input_dict = {
        "c1": {"igmp": {"interfaces": {intf_c1_i4: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i4": topo["routers"]["i4"]["links"]["c1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, recvr, recvr_intf, GROUP_RANGE_1, join=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendIGMPJoin(tgen, recvr, IGMP_JOIN_RANGE_1, join_interval=1)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (225.1.1.1-5) as R2")

    input_dict = {
        "l1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["l1"]["links"]["lo"]["ipv4"].split(
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

    step("Send traffic from C2 to all the groups ( 225.1.1.1 to 225.1.1.5)")

    input_src = {"i5": topo["routers"]["i5"]["links"]["c2"]["interface"]}

    for src, src_intf in input_src.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, src, src_intf, GROUP_RANGE_1, traffic=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendTraffic(tgen, src, IGMP_JOIN_RANGE_1, 32, 2500)
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
            "iif": topo["routers"]["c1"]["links"]["l1"]["interface"],
            "oil": topo["routers"]["c1"]["links"]["i4"]["interface"],
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_sg:
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

    for data in input_dict_starg:
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

    step("Delete static routes RP on all the nodes")
    input_dict = {
        "c2": {
            "static_routes": [
                {"network": ["1.0.4.11/32"], "next_hop": "10.0.3.2", "delete": True}
            ]
        },
        "c1": {
            "static_routes": [
                {"network": ["1.0.4.11/32"], "next_hop": "10.0.2.2", "delete": True}
            ]
        },
        "r2": {
            "static_routes": [
                {"network": ["1.0.4.11/32"], "next_hop": "10.0.12.1", "delete": True}
            ]
        },
        "f1": {
            "static_routes": [
                {"network": ["1.0.4.11/32"], "next_hop": "10.0.7.2", "delete": True}
            ]
        },
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info unknown after removing static route from c2 ")
    dut = "c2"
    rp_address = topo["routers"]["l1"]["links"]["lo"]["ipv4"].split("/")[0]
    SOURCE = "Static"
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    for data in input_dict_starg:
        result = verify_ip_mroutes(
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
        ), "Testcase {} : Failed \n " "upstream is still present \n Error: {}".format(
            tc_name, result
        )

    step("Configure default routes on all the nodes")

    intf_f1_c2 = topo["routers"]["f1"]["links"]["c2"]["ipv4"].split("/")[0]
    intf_l1_c1 = topo["routers"]["l1"]["links"]["c1"]["ipv4"].split("/")[0]
    intf_l1_r2 = topo["routers"]["l1"]["links"]["r2"]["ipv4"].split("/")[0]
    intf_r2_f1 = topo["routers"]["r2"]["links"]["f1"]["ipv4"].split("/")[0]

    input_dict = {
        "c1": {"static_routes": [{"network": "0.0.0.0/0", "next_hop": intf_l1_c1}]},
        "c2": {"static_routes": [{"network": "0.0.0.0/0", "next_hop": intf_f1_c2}]},
        "r2": {"static_routes": [{"network": "0.0.0.0/0", "next_hop": intf_l1_r2}]},
        "f1": {"static_routes": [{"network": "0.0.0.0/0", "next_hop": intf_r2_f1}]},
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("applying ip nht config  on c2")

    raw_config = {
        "c1": {"raw_config": ["ip nht resolve-via-default"]},
        "c2": {"raw_config": ["ip nht resolve-via-default"]},
        "r2": {"raw_config": ["ip nht resolve-via-default"]},
        "f1": {"raw_config": ["ip nht resolve-via-default"]},
        "l1": {"raw_config": ["ip nht resolve-via-default"]},
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify RP info Not unknown after removing static route from c2 ")
    dut = "c2"
    step("Verify RP info is NOT unknown after removing static route from c2 ")
    result = verify_pim_rp_info(
        tgen, topo, dut, GROUP_RANGE_1, "Unknown", rp_address, SOURCE, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "RP info is unknown after removing static route from c2 \n Error: {}".format(
            tc_name, result
        )
    )

    step("Verify (s,g) populated after adding default route ")

    for data in input_dict_sg:
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

    step("Verify (*,g) populated after adding default route ")

    for data in input_dict_starg:
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


def test_PIM_hello_tx_rx_p1(request):
    """
    TC_54 Verify received and transmit hello stats
        are getting cleared after PIM nbr reset
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    kill_iperf(tgen)
    clear_ip_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step(
        "Remove c1-c2 connected link to simulate topo "
        "c1(LHR)---l1(RP)----r2---f1-----c2(FHR)"
    )

    intf_c1_c2 = topo["routers"]["c1"]["links"]["c2"]["interface"]
    intf_c2_c1 = topo["routers"]["c2"]["links"]["c1"]["interface"]
    shutdown_bringup_interface(tgen, "c1", intf_c1_c2, False)
    shutdown_bringup_interface(tgen, "c2", intf_c2_c1, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step(
        "Enable IGMP of FRR1 interface and send IGMP joins "
        " from FRR1 node for group range (225.1.1.1-5)"
    )

    intf_c1_i4 = topo["routers"]["c1"]["links"]["i4"]["interface"]
    input_dict = {
        "c1": {"igmp": {"interfaces": {intf_c1_i4: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i4": topo["routers"]["i4"]["links"]["c1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, recvr, recvr_intf, GROUP_RANGE_1, join=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendIGMPJoin(tgen, recvr, IGMP_JOIN_RANGE_1, join_interval=1)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (225.1.1.1-5) as R2")

    input_dict = {
        "l1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["l1"]["links"]["lo"]["ipv4"].split(
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

    step("Send Mcast traffic from C2 to all the groups ( 225.1.1.1 to 225.1.1.5)")

    input_src = {"i5": topo["routers"]["i5"]["links"]["c2"]["interface"]}

    for src, src_intf in input_src.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, src, src_intf, GROUP_RANGE_1, traffic=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = iperfSendTraffic(tgen, src, IGMP_JOIN_RANGE_1, 32, 2500)
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
            "iif": topo["routers"]["c1"]["links"]["l1"]["interface"],
            "oil": topo["routers"]["c1"]["links"]["i4"]["interface"],
        }
    ]

    step("(*,G) and (S,G) created on f1 and node verify using 'show ip mroute'")
    for data in input_dict_sg:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_starg:
        result = verify_ip_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    intf_l1_c1 = topo["routers"]["l1"]["links"]["c1"]["interface"]
    intf_c1_l1 = topo["routers"]["c1"]["links"]["l1"]["interface"]

    step("verify before stats on C1")
    state_dict = {
        "c1": {
            intf_c1_l1: ["helloTx", "helloRx"],
        }
    }

    c1_state_before = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        c1_state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n "
    "Error: {}".format(tc_name, result)

    step("Flap PIM nbr while doing interface c1-l1 interface shut from f1 side")
    shutdown_bringup_interface(tgen, "c1", intf_c1_l1, False)

    step(
        "After shut of local interface from c1 , verify rx/tx hello counters are cleared on c1 side"
        "verify using 'show ip pim interface traffic'"
    )
    shutdown_bringup_interface(tgen, "c1", intf_c1_l1, True)

    step("verify stats after on c1")
    c1_state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        c1_state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n "
    "Error: {}".format(tc_name, result)

    step("verify stats not increamented on c1")
    result = verify_state_incremented(c1_state_before, c1_state_after)
    assert (
        result is not True
    ), "Testcase{} : Failed Error: {}" "stats incremented".format(tc_name, result)

    step("verify before stats on l1")
    l1_state_dict = {
        "l1": {
            intf_l1_c1: ["helloTx", "helloRx"],
        }
    }

    l1_state_before = verify_pim_interface_traffic(tgen, l1_state_dict)
    assert isinstance(
        l1_state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n "
    "Error: {}".format(tc_name, result)

    step("Flap PIM nbr while doing interface r2-c1 shut from r2 side")
    shutdown_bringup_interface(tgen, "l1", intf_l1_c1, False)

    step(
        "After shut the interface from r2 side , verify r2 side rx and tx of hello"
        "counters are resetted show ip pim interface traffic"
    )
    shutdown_bringup_interface(tgen, "l1", intf_l1_c1, True)

    step("verify stats after on l1")
    l1_state_after = verify_pim_interface_traffic(tgen, l1_state_dict)
    assert isinstance(
        l1_state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n "
    "Error: {}".format(tc_name, result)

    step("verify stats not increamented on l1")
    result = verify_state_incremented(l1_state_before, l1_state_after)
    assert (
        result is not True
    ), "Testcase{} : Failed Error: {}" "stats incremented".format(tc_name, result)

    step("Reinit the dict")
    c1_state_before = {}
    l1_state_before = {}
    c1_state_after = {}
    l1_state_after = {}

    step("verify before stats on C1")
    state_dict = {
        "c1": {
            intf_c1_l1: ["helloTx", "helloRx"],
        }
    }

    c1_state_before = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        c1_state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n "
    "Error: {}".format(tc_name, result)

    step("Flap c1-r2 pim nbr while changing ip address from c1 side")
    c1_l1_ip_subnet = topo["routers"]["c1"]["links"]["l1"]["ipv4"]

    raw_config = {
        "c1": {
            "raw_config": [
                "interface {}".format(intf_c1_l1),
                "no ip address {}".format(c1_l1_ip_subnet),
                "ip address {}".format(NEW_ADDRESS_2_SUBNET),
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify stats after on c1")
    c1_state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        c1_state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n "
    "Error: {}".format(tc_name, result)

    step("verify stats not increamented on c1")
    result = verify_state_incremented(c1_state_before, c1_state_after)
    assert (
        result is not True
    ), "Testcase{} : Failed Error: {}" "stats incremented".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
