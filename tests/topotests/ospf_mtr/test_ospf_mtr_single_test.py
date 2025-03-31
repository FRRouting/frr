#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
# Copyright (C) 2025 The MITRE Corporation



"""OSPF Basic Functionality Automation."""
import os
import sys
import time
from functools import partial
import pytest
from copy import deepcopy
from ipaddress import IPv4Address
from lib.topotest import frr_unicode, router_output_cmp, run_and_expect

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
import ipaddress

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    step,
    create_interfaces_cfg,
    apply_raw_config,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

from lib.ospf import (
    verify_ospf_neighbor,
    config_ospf_interface,
    clear_ospf,
    verify_ospf_rib,
    verify_ospf_interface,
)

pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]
# Global variables
topo = None


"""
TOPOOLOGY =
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
1. OSPF IFSM -Verify state change events on p2p network.
2. OSPF Timers - Verify OSPF interface timer hello interval functionality
3. OSPF Timers - Verify OSPF interface timer dead interval functionality
4. Verify ospf show commands with json output.
5. Verify NFSM events when ospf nbr changes with different MTU values.
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
    json_file = "{}/ospf_mtr_single_test.json".format(CWD)
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


def test_ospf_mtr_p0(request):
    """OSPF MTR -Verify MTR routes."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    # Configure MTR
    step("Configure MTR.")
    
    # Add MTR configuration
    input_mtr_config = {
        "r0": {
            "raw_config": [
                "router ospf",
                "topology multicast tid 1",
                "interface lo",
                "ip address 1.0.1.17/32",
                "interface r0-r1-eth0",
                "ip address 10.0.0.1/24",
                "ip ospf area 0.0.0.0",
                "interface r0-r2-eth1",
                "ip address 10.0.1.1/24",
                "ip ospf area 0.0.0.0",
                "interface r0-r3-eth2",
                "ip address 10.0.2.1/24",
                "ip ospf network point-to-point",
                "ip ospf area 0.0.0.0",
                "ip ospf topology multicast cost 63",
                "router ospf",
                "ospf router-id 100.1.1.0",
            ]
        },
        "r1": {
            "raw_config": [
                "interface lo",
                "ip address 1.0.2.17/32",
                "interface r1-r0-eth0",
                "ip address 10.0.0.2/24",
                "ip ospf area 0.0.0.0",
                "interface r1-r2-eth1",
                "ip address 10.0.3.1/24",
                "ip ospf area 0.0.0.0",
                "interface r1-r3-eth2",
                "ip address 10.0.4.1/24",
                "ip ospf area 0.0.0.0",
                "interface r1-r3-eth3",
                "ip address 10.0.5.1/24",
                "router ospf",
                "ospf router-id 100.1.1.1",
            ]
        },
        "r2": {
            "raw_config": [
                "interface lo",
                "ip address 1.0.3.17/32",
                "interface r2-r0-eth0",
                "ip address 10.0.1.2/24",
                "ip ospf area 0.0.0.0",
                "interface r2-r1-eth1",
                "ip address 10.0.3.2/24",
                "ip ospf area 0.0.0.0",
                "interface r2-r3-eth2",
                "ip address 10.0.6.1/24",
                "ip ospf area 0.0.0.0",
                "router ospf",
                "ospf router-id 100.1.1.2",
            ]
        },
        "r3": {
            "raw_config": [
                "router ospf",
                "topology multicast tid 1",
                "interface lo",
                "ip address 1.0.4.17/32",
                "interface r3-r0-eth0",
                "ip address 10.0.2.2/24",
                "ip ospf network point-to-point",
                "ip ospf area 0.0.0.0",
                "ip ospf topology multicast cost 63",
                "interface r3-r1-eth1",
                "ip address 10.0.4.2/24",
                "ip ospf area 0.0.0.0",
                "interface r3-r1-eth2",
                "ip address 10.0.5.2/24",
                "ip ospf area 0.0.0.0",
                "ip ospf topology multicast cost 64",
                "interface r3-r2-eth3",
                "ip address 10.0.6.2/24",
                "ip ospf area 0.0.0.0", 
                "router ospf",
                "ospf router-id 100.1.1.3",
            ]
        }
    }
    apply_raw_config(tgen, input_mtr_config)

    step("Verify OSPF MTR routes.")
    # show ip ospf route
    cmd = "show ip ospf route topology all"
    dut = "r0"
    rtr0 = tgen.routers()[dut]

    reffile = os.path.join(CWD, "{}/{}_expected_mtr.txt".format(dut, dut))
    if os.path.exists(reffile):
        expected = open(reffile).read()

    test_func = partial(router_output_cmp,
            rtr0,
            cmd, # "show ip ospf route topology all", 
            expected,
    )
    logger.info('Testcase "%s": Waiting for router "%s" convergence', tc_name,
            dut)
    result, diff = run_and_expect(test_func, "", count=80, wait=1)
   
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
