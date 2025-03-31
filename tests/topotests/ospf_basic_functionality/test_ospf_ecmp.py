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
from time import sleep

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
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    step,
    shutdown_bringup_interface,
)
from lib.topolog import logger

from lib.topojson import build_config_from_json
from lib.ospf import (
    verify_ospf_neighbor,
    config_ospf_interface,
    verify_ospf_rib,
    redistribute_ospf,
)

pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]


topo = None


# Global variables
NETWORK = {
    "ipv4": [
        "11.0.20.1/32",
        "11.0.20.2/32",
        "11.0.20.3/32",
        "11.0.20.4/32",
        "11.0.20.5/32",
    ]
}
"""
TOPOLOGY :
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

TESTCASES :
1. Verify OSPF ECMP with max path configured as 8 (ECMPconfigured at FRR level)
2. Verify OSPF ECMP with max path configured as 2 (Edge having 2 uplink ports)
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
    json_file = "{}/ospf_ecmp.json".format(CWD)
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


def teardown_module():
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


def test_ospf_ecmp_tc16_p0(request):
    """
    Verify OSPF ECMP.

    Verify OSPF ECMP with max path configured as 8 (ECMP
    configured at FRR level)
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    step("Configure 8 interfaces between R1 and R2 and enable ospf in area 0.")
    reset_config_on_routers(tgen)
    step("Verify that OSPF is up with 8 neighborship sessions.")
    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Configure a static route in R0 and redistribute in OSPF.")

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

    dut = "r0"
    redistribute_ospf(tgen, topo, dut, "static")

    step("Verify that route in R2 in stalled with 8 next hops.")
    nh = []
    for _ in range(1, 7):
        nh.append(topo["routers"]["r0"]["links"]["r1-link1"]["ipv4"].split("/")[0])

    nh2 = topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0]

    nh.append(nh2)

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("shut no shut all the interfaces on the remote router - R2")
    dut = "r1"
    for intfr in range(1, 7):
        intf = topo["routers"]["r1"]["links"]["r0-link{}".format(intfr)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, False)

    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: OSPF routes are present \n Error: {}".format(
        tc_name, result
    )

    protocol = "ospf"
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: routes are still present \n Error: {}".format(
        tc_name, result
    )

    for intfr in range(1, 7):
        intf = topo["routers"]["r1"]["links"]["r0-link{}".format(intfr)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, True)

    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("shut no shut on all the interfaces on DUT (r1)")
    for intfr in range(1, 7):
        intf = topo["routers"]["r1"]["links"]["r0-link{}".format(intfr)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, False)

    for intfr in range(1, 7):
        intf = topo["routers"]["r1"]["links"]["r0-link{}".format(intfr)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that all the neighbours are up and routes are installed"
        " with 8 next hop in ospf and ip route tables on R1."
    )

    step("Verify that OSPF is up with 8 neighborship sessions.")
    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" Un configure static route on R0")

    dut = "r0"
    redistribute_ospf(tgen, topo, dut, "static", delete=True)

    # Wait for R0 to flush external LSAs.
    sleep(10)

    step("Verify that route is withdrawn from R2.")
    dut = "r1"
    result = verify_ospf_rib(
        tgen, dut, input_dict, next_hop=nh, retry_timeout=10, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: OSPF routes are present \n Error: {}".format(
        tc_name, result
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
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: routes are still present \n Error: {}".format(
        tc_name, result
    )

    step("Re configure the static route in R0.")
    dut = "r0"
    redistribute_ospf(tgen, topo, dut, "static")

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_ecmp_tc17_p0(request):
    """
    Verify OSPF ECMP.

    Verify OSPF ECMP with max path configured as 2 (Edge having 2 uplink ports)
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    step("Configure 2 interfaces between R1 and R2 & enable ospf in area 0.")
    reset_config_on_routers(tgen)
    step("Verify that OSPF is up with 2 neighborship sessions.")
    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Configure a static route in R0 and redistribute in OSPF.")

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

    dut = "r0"
    redistribute_ospf(tgen, topo, dut, "static")

    step("Verify that route in R2 in stalled with 2 next hops.")

    nh1 = topo["routers"]["r0"]["links"]["r1-link1"]["ipv4"].split("/")[0]
    nh2 = topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0]
    nh = [nh1, nh2]

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" Un configure static route on R0")

    dut = "r0"
    redistribute_ospf(tgen, topo, dut, "static", delete=True)
    # sleep till the route gets withdrawn
    sleep(10)

    step("Verify that route is withdrawn from R2.")
    dut = "r1"
    result = verify_ospf_rib(
        tgen, dut, input_dict, next_hop=nh, retry_timeout=10, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: OSPF routes are present \n Error: {}".format(
        tc_name, result
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
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: routes are still present \n Error: {}".format(
        tc_name, result
    )

    step("Reconfigure the static route in R0.Change ECMP value to 2.")
    dut = "r0"
    redistribute_ospf(tgen, topo, dut, "static")

    step("Configure cost on R0 as 100")
    r0_ospf_cost = {"r0": {"links": {"r1": {"ospf": {"cost": 100}}}}}
    result = config_ospf_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
