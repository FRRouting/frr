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
    step,
    verify_rib,
    stop_router,
    start_router,
    create_static_routes,
    start_router_daemons,
    kill_router_daemons,
)

from lib.ospf import verify_ospf_neighbor, verify_ospf_rib, create_router_ospf

from lib.topolog import logger
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]

# Global variables
topo = None

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
Topology:
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

TESTCASES =
1. Verify ospf functionality after restart ospfd.
2. Verify ospf functionality after restart FRR service.
3. Verify ospf functionality when staticd is restarted.
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
    json_file = "{}/ospf_chaos.json".format(CWD)
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
def test_ospf_chaos_tc31_p1(request):
    """Verify ospf functionality after restart ospfd."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    step(
        "Create static routes(10.0.20.1/32) in R1 and redistribute "
        "to OSPF using route map."
    )

    # Create Static routes
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

    ospf_red_r0 = {"r0": {"ospf": {"redistribute": [{"redist_type": "static"}]}}}
    result = create_router_ospf(tgen, topo, ospf_red_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify OSPF neighbors after base config is done.")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Verify that route is advertised to R1.")
    dut = "r1"
    protocol = "ospf"
    nh = topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0]
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Kill OSPFd daemon on R0.")
    kill_router_daemons(tgen, "r0", ["ospfd"])

    step("Verify OSPF neighbors are down after killing ospfd in R0")
    dut = "r0"
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Verify that route advertised to R1 are deleted from RIB and FIB.")
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: OSPF routes are present \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: routes are still present \n Error: {}".format(
        tc_name, result
    )

    step("Bring up OSPFd daemon on R0.")
    start_router_daemons(tgen, "r0", ["ospfd"])

    step("Verify OSPF neighbors are up after bringing back ospfd in R0")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "All the neighbours are up and routes are installed before the"
        " restart. Verify OSPF route table and ip route table."
    )
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Kill OSPFd daemon on R1.")
    kill_router_daemons(tgen, "r1", ["ospfd"])

    step("Verify OSPF neighbors are down after killing ospfd in R1")
    dut = "r1"
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Bring up OSPFd daemon on R1.")
    start_router_daemons(tgen, "r1", ["ospfd"])

    step("Verify OSPF neighbors are up after bringing back ospfd in R1")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "All the neighbours are up and routes are installed before the"
        " restart. Verify OSPF route table and ip route table."
    )

    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_chaos_tc32_p1(request):
    """Verify ospf functionality after restart FRR service."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    step(
        "Create static routes(10.0.20.1/32) in R1 and redistribute "
        "to OSPF using route map."
    )

    # Create Static routes
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

    ospf_red_r0 = {"r0": {"ospf": {"redistribute": [{"redist_type": "static"}]}}}
    result = create_router_ospf(tgen, topo, ospf_red_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify OSPF neighbors after base config is done.")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Verify that route is advertised to R1.")
    dut = "r1"
    protocol = "ospf"

    nh = topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0]
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Restart frr on R0")
    stop_router(tgen, "r0")
    start_router(tgen, "r0")

    step("Verify OSPF neighbors are up after restarting R0")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "All the neighbours are up and routes are installed before the"
        " restart. Verify OSPF route table and ip route table."
    )
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Restart frr on R1")
    stop_router(tgen, "r1")
    start_router(tgen, "r1")

    step("Verify OSPF neighbors are up after restarting R1")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "All the neighbours are up and routes are installed before the"
        " restart. Verify OSPF route table and ip route table."
    )
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_chaos_tc34_p1(request):
    """
    verify ospf functionality when staticd is restarted.

    Verify ospf functionalitywhen staticroutes are
    redistributed & Staticd is restarted.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    step(
        "Create static routes(10.0.20.1/32) in R1 and redistribute "
        "to OSPF using route map."
    )

    # Create Static routes
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

    ospf_red_r0 = {"r0": {"ospf": {"redistribute": [{"redist_type": "static"}]}}}
    result = create_router_ospf(tgen, topo, ospf_red_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify OSPF neighbors after base config is done.")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Verify that route is advertised to R1.")
    dut = "r1"
    protocol = "ospf"
    nh = topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0]
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Kill staticd daemon on R0.")
    kill_router_daemons(tgen, "r0", ["staticd"])

    step("Verify that route advertised to R1 are deleted from RIB and FIB.")
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: OSPF routes are present \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: routes are still present \n Error: {}".format(
        tc_name, result
    )

    step("Bring up staticd daemon on R0.")
    start_router_daemons(tgen, "r0", ["staticd"])

    step("Verify OSPF neighbors are up after bringing back ospfd in R0")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "All the neighbours are up and routes are installed before the"
        " restart. Verify OSPF route table and ip route table."
    )
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Kill staticd daemon on R1.")
    kill_router_daemons(tgen, "r1", ["staticd"])

    step("Bring up staticd daemon on R1.")
    start_router_daemons(tgen, "r1", ["staticd"])

    step("Verify OSPF neighbors are up after bringing back ospfd in R1")
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "All the neighbours are up and routes are installed before the"
        " restart. Verify OSPF route table and ip route table."
    )

    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
