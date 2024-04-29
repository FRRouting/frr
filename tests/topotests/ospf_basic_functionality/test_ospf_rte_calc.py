#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#


"""OSPF Basic Functionality Automation."""
import os
import sys
import time
import pytest
import ipaddress

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    create_interfaces_cfg,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    step,
    shutdown_bringup_interface,
)
from lib.bgp import verify_bgp_convergence, create_router_bgp
from lib.topolog import logger
from lib.topojson import build_config_from_json

from lib.ospf import (
    verify_ospf_neighbor,
    clear_ospf,
    verify_ospf_rib,
    redistribute_ospf,
    config_ospf_interface,
    verify_ospf_interface,
)

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.staticd]


# Global variables
topo = None

# number of retries.
nretry = 5

NETWORK = {
    "ipv4": [
        "11.0.20.1/32",
        "11.0.20.2/32",
        "11.0.20.3/32",
        "11.0.20.4/32",
        "11.0.20.5/32",
    ]
}

NETWORK_APP_E = {"ipv4": ["12.0.0.0/24", "12.0.0.0/16", "12.0.0.0/8"]}
TOPOOLOGY = """
      Please view in a fixed-width font such as Courier.
      +---+  A1       +---+
      +R1 +------------+R2 |
      +-+-+-           +--++
        |  --        --  |
        |    -- A0 --    |
      A0|      ----      |
        |      ----      | A2
        |    --    --    |
        |  --        --  |
      +-+-+-            +-+-+
      +R0 +-------------+R3 |
      +---+     A3     +---+
"""

TESTCASES = """
1. Test OSPF intra area route calculations.
2. Test OSPF inter area route calculations.
3. Test OSPF redistribution of connected routes.
"""


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/ospf_rte_calc.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error  {}".format(
        ospf_covergence
    )

    logger.info("Running setup_module() done")


def teardown_module(mod):
    """
    Teardown the pytest environment.

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


# ##################################
# Test cases start here.
# ##################################


def test_ospf_redistribution_tc5_p0(request):
    """Test OSPF intra area route calculations."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)

    step("Verify that OSPF neighbors are FULL.")
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("verify intra area route is calculated for r0-r3 interface ip in R1")
    ip = topo["routers"]["r0"]["links"]["r3"]["ipv4"]
    ip_net = str(ipaddress.ip_interface("{}".format(ip)).network)
    nh = topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict = {
        "r1": {"static_routes": [{"network": ip_net, "no_of_ip": 1, "routeType": "N"}]}
    }

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the ip address on newly configured interface of R0")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv4": topo["routers"]["r0"]["links"]["r3"]["ipv4"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    for num in range(0, nretry):
        result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh, expected=False)
        if result is not True:
            break

    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: OSPF routes are present after deleting ip address of newly "
        "configured interface of R0 \n Error: {}".format(tc_name, result)
    )

    protocol = "ospf"
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        input_dict,
        protocol=protocol,
        next_hop=nh,
        retry_timeout=10,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: OSPF routes are present in fib after deleting ip address of newly "
        "configured interface of R0 \n Error: {}".format(tc_name, result)
    )

    step("Add back the deleted ip address on newly configured interface of R0")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv4": topo["routers"]["r0"]["links"]["r3"]["ipv4"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Shut no shut interface on R0")
    dut = "r0"
    intf = topo["routers"]["r0"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("un shut the OSPF interface on R0")
    dut = "r0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_redistribution_tc6_p0(request):
    """Test OSPF inter area route calculations."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)

    step("Verify that OSPF neighbors are FULL.")
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("verify intra area route is calculated for r0-r3 interface ip in R1")
    ip = topo["routers"]["r0"]["links"]["r3"]["ipv4"]
    ip_net = str(ipaddress.ip_interface("{}".format(ip)).network)
    nh = topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict = {
        "r1": {"static_routes": [{"network": ip_net, "no_of_ip": 1, "routeType": "N"}]}
    }

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the ip address on newly configured loopback of R0")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv4": topo["routers"]["r0"]["links"]["r3"]["ipv4"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    for num in range(0, nretry):
        result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh, expected=False)
        if result is not True:
            break
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: OSPF routes are present after deleting ip address of newly "
        "configured loopback of R0 \n Error: {}".format(tc_name, result)
    )

    protocol = "ospf"
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        input_dict,
        protocol=protocol,
        next_hop=nh,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "r1: OSPF routes are present in fib after deleting ip address of newly "
        "configured loopback of R0 \n Error: {}".format(tc_name, result)
    )

    step("Add back the deleted ip address on newly configured interface of R0")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv4": topo["routers"]["r0"]["links"]["r3"]["ipv4"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Shut no shut interface on R0")
    dut = "r0"
    intf = topo["routers"]["r0"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("un shut the OSPF interface on R0")
    dut = "r0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_redistribution_tc8_p1(request):
    """
    Test OSPF redistribution of connected routes.

    Verify OSPF redistribution of connected routes when bgp multi hop
    neighbor is configured using ospf routes

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    step(
        "Configure loopback interface on all routers, and redistribut"
        "e connected routes into ospf"
    )
    reset_config_on_routers(tgen)

    step(
        "verify that connected routes -loopback is found in all routers"
        "advertised/exchaged via ospf"
    )
    for rtr in topo["routers"]:
        redistribute_ospf(tgen, topo, rtr, "static")
        redistribute_ospf(tgen, topo, rtr, "connected")
    for node in topo["routers"]:
        input_dict = {
            "r0": {
                "static_routes": [
                    {
                        "network": topo["routers"][node]["links"]["lo"]["ipv4"],
                        "no_of_ip": 1,
                    }
                ]
            }
        }
        for rtr in topo["routers"]:
            result = verify_rib(tgen, "ipv4", rtr, input_dict)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step("Configure E BGP multi hop using the loopback addresses.")
    as_num = 100
    for node in topo["routers"]:
        as_num += 1
        topo["routers"][node].update(
            {
                "bgp": {
                    "local_as": as_num,
                    "address_family": {"ipv4": {"unicast": {"neighbor": {}}}},
                }
            }
        )
    for node in topo["routers"]:
        for rtr in topo["routers"]:
            if node is not rtr:
                topo["routers"][node]["bgp"]["address_family"]["ipv4"]["unicast"][
                    "neighbor"
                ].update(
                    {
                        rtr: {
                            "dest_link": {
                                "lo": {"source_link": "lo", "ebgp_multihop": 2}
                            }
                        }
                    }
                )

    result = create_router_bgp(tgen, topo, topo["routers"])
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that BGP neighbor is ESTABLISHED")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    step(
        "Configure couple of static routes in R0 and "
        "Redistribute static routes in R1 bgp."
    )

    for rtr in topo["routers"]:
        redistribute_ospf(tgen, topo, rtr, "static", delete=True)

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": 5,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r0 = {
        "r0": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}}
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    protocol = "bgp"
    for rtr in ["r1", "r2", "r3"]:
        result = verify_rib(tgen, "ipv4", rtr, input_dict, protocol=protocol)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Clear ospf neighbours in R0")
    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr)

    step("Verify that OSPF neighbours are reset and forms new adjacencies.")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Verify that BGP neighbours are reset and forms new adjacencies.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    protocol = "bgp"
    for rtr in ["r1", "r2", "r3"]:
        result = verify_rib(tgen, "ipv4", rtr, input_dict, protocol=protocol)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_ospf_rfc2328_appendinxE_p0(request):
    """
    Test OSPF appendinx E RFC2328.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")

    reset_config_on_routers(tgen)

    step("Verify that OSPF neighbours are Full.")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    redistribute_ospf(tgen, topo, "r0", "static")

    step("Configure static route with prefix 24, 16, 8 to check  ")
    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK_APP_E["ipv4"][0],
                    "no_of_ip": 1,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK_APP_E["ipv4"][1],
                    "no_of_ip": 1,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK_APP_E["ipv4"][2],
                    "no_of_ip": 1,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that ospf originates routes with mask 24, 16, 8")
    ip_net = NETWORK_APP_E["ipv4"][0]
    input_dict = {"r1": {"static_routes": [{"network": ip_net, "no_of_ip": 1}]}}

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ip_net = NETWORK_APP_E["ipv4"][1]
    input_dict = {"r1": {"static_routes": [{"network": ip_net, "no_of_ip": 1}]}}

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ip_net = NETWORK_APP_E["ipv4"][2]
    input_dict = {"r1": {"static_routes": [{"network": ip_net, "no_of_ip": 1}]}}

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete static route with prefix 24, 16, 8 to check  ")
    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK_APP_E["ipv4"][0],
                    "no_of_ip": 1,
                    "next_hop": "Null0",
                    "delete": True,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK_APP_E["ipv4"][1],
                    "no_of_ip": 1,
                    "next_hop": "Null0",
                    "delete": True,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK_APP_E["ipv4"][2],
                    "no_of_ip": 1,
                    "next_hop": "Null0",
                    "delete": True,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_cost_tc52_p0(request):
    """OSPF Cost - verifying ospf interface cost functionality"""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)

    step(
        "Configure ospf cost as 20 on interface between R0 and R1. "
        "Configure ospf cost as 30 between interface between R0 and R2."
    )

    r0_ospf_cost = {
        "r0": {"links": {"r1": {"ospf": {"cost": 20}}, "r2": {"ospf": {"cost": 30}}}}
    }
    result = config_ospf_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that cost is updated in the ospf interface between"
        " r0 and r1 as 30 and r0 and r2 as 20"
    )
    dut = "r0"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=r0_ospf_cost)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Swap the costs between interfaces on r0, between r0 and r1 to 30"
        ", r0 and r2 to 20"
    )

    r0_ospf_cost = {
        "r0": {"links": {"r1": {"ospf": {"cost": 30}}, "r2": {"ospf": {"cost": 20}}}}
    }
    result = config_ospf_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that cost is updated in the ospf interface between r0 "
        "and r1 as 30 and r0 and r2 as 20."
    )
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=r0_ospf_cost)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" Un configure cost from the interface r0 - r1.")

    r0_ospf_cost = {"r0": {"links": {"r1": {"ospf": {"cost": 30, "del_action": True}}}}}
    result = config_ospf_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {"links": {"r1": {"ospf": {"cost": 10}}, "r2": {"ospf": {"cost": 20}}}}
    }
    step(
        "Verify that cost is updated in the ospf interface between r0"
        " and r1 as 10 and r0 and r2 as 20."
    )

    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" Un configure cost from the interface r0 - r2.")

    r0_ospf_cost = {"r0": {"links": {"r2": {"ospf": {"cost": 20, "del_action": True}}}}}
    result = config_ospf_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that cost is updated in the ospf interface between r0"
        "and r1 as 10 and r0 and r2 as 10"
    )

    input_dict = {
        "r0": {"links": {"r1": {"ospf": {"cost": 10}}, "r2": {"ospf": {"cost": 10}}}}
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
