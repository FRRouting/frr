#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#

"""
<example>.py: Test <example tests>.
"""

import os
import sys
import time
import json
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

# Required to instantiate the topology builder class.

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    verify_rib,
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence
from lib.topojson import build_topo_from_json, build_config_from_json


# TODO: select markers based on daemons used during test
# pytest module level markers
"""
pytestmark = pytest.mark.bfdd # single marker
pytestmark = [
	pytest.mark.bgpd,
	pytest.mark.ospfd,
	pytest.mark.ospf6d
] # multiple markers
"""


# Reading the data from JSON File for topology and configuration creation
jsonFile = "{}/example_topojson.json".format(CWD)

try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

# Global variables
bgp_convergence = False
input_dict = {}


def build_topo(tgen):
    "Build function"

    # This function only purpose is to create topology
    # as defined in input json file.
    #
    # Example
    #
    # Creating 2 routers having single links in between,
    # which is used to establised BGP neighborship

    # Building topology from json file
    build_topo_from_json(tgen, topo)


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
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # This function only purpose is to create configuration
    # as defined in input json file.
    #
    # Example
    #
    # Creating configuration defined in input JSON
    # file, example, BGP config, interface config, static routes
    # config, prefix list config

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    logger.info("Running setup_module() done")


def teardown_module(mod):
    """
    Teardown the pytest environment

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()


def test_bgp_convergence(request):
    "Test BGP daemon convergence"

    tgen = get_topogen()
    global bgp_convergence
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert (
        bgp_convergence is True
    ), "test_bgp_convergence failed.. \n" " Error: {}".format(bgp_convergence)

    logger.info("BGP is converged successfully \n")
    write_test_footer(tc_name)


def test_static_routes(request):
    "Test to create and verify static routes."

    tgen = get_topogen()
    if bgp_convergence is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Static routes are created as part of initial configuration,
    # verifying RIB
    dut = "r3"
    next_hop = ["10.0.0.1", "10.0.0.5"]
    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": "100.0.20.1/32",
                    "no_of_ip": 9,
                    "admin_distance": 100,
                    "next_hop": "10.0.0.1",
                }
            ]
        }
    }
    # Uncomment below to debug
    # tgen.mininet_cli()
    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=next_hop)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
