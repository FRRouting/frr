#!/usr/bin/env python

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
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
Following tests are covered to test BGP basic functionality:

Test steps
- Create topology (setup module)
  Creating 4 routers topology, r1, r2, r3 are in IBGP and
  r3, r4 are in EBGP
- Bring up topology
- Verify for bgp to converge
- Modify/Delete and verify router-id
- Modify and verify bgp timers
- Create and verify static routes
- Modify and verify admin distance for existing static routes
- Test advertise network using network command
- Verify clear bgp
- Test bgp convergence with loopback interface
- Test advertise network using network command
"""

import os
import sys
import json
import time
import pytest
from copy import deepcopy

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
    reset_config_on_routers,
    create_static_routes,
    verify_rib,
    verify_admin_distance_for_static_routes,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_router_id,
    modify_as_number,
    verify_as_numbers,
    clear_bgp_and_verify,
    verify_bgp_timers_and_functionality,
)
from lib.topojson import build_topo_from_json, build_config_from_json

# Reading the data from JSON File for topology creation
jsonFile = "{}/bgp_basic_functionality.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

# Global Variable
KEEPALIVETIMER = 2
HOLDDOWNTIMER = 6


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

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(CreateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global BGP_CONVERGENCE
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

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


def test_modify_and_delete_router_id(request):
    """ Test to modify, delete and verify router-id. """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Modify router id
    input_dict = {
        "r1": {"bgp": {"router_id": "12.12.12.12"}},
        "r2": {"bgp": {"router_id": "22.22.22.22"}},
        "r3": {"bgp": {"router_id": "33.33.33.33"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying router id once modified
    result = verify_router_id(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Delete router id
    input_dict = {
        "r1": {"bgp": {"del_router_id": True}},
        "r2": {"bgp": {"del_router_id": True}},
        "r3": {"bgp": {"del_router_id": True}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying router id once deleted
    # Once router-id is deleted, highest interface ip should become
    # router-id
    result = verify_router_id(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_config_with_4byte_as_number(request):
    """
    Configure BGP with 4 byte ASN and verify it works fine
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    input_dict = {
        "r1": {"bgp": {"local_as": 131079}},
        "r2": {"bgp": {"local_as": 131079}},
        "r3": {"bgp": {"local_as": 131079}},
        "r4": {"bgp": {"local_as": 131080}},
    }
    result = modify_as_number(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_as_numbers(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_BGP_config_with_invalid_ASN_p2(request):
    """
    Configure BGP with invalid ASN(ex - 0, reserved ASN) and verify test case
    ended up with error
    """

    tgen = get_topogen()
    global BGP_CONVERGENCE

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Api call to modify AS number
    input_dict = {
        "r1": {"bgp": {"local_as": 0,}},
        "r2": {"bgp": {"local_as": 0,}},
        "r3": {"bgp": {"local_as": 0,}},
        "r4": {"bgp": {"local_as": 64000,}},
    }
    result = modify_as_number(tgen, topo, input_dict)
    try:
        assert result is True
    except AssertionError:
        logger.info("Expected behaviour: {}".format(result))
        logger.info("BGP config is not created because of invalid ASNs")

    write_test_footer(tc_name)


def test_BGP_config_with_2byteAS_and_4byteAS_number_p1(request):
    """
    Configure BGP with 4 byte and 2 byte ASN and verify BGP is converged
    """

    tgen = get_topogen()
    global BGP_CONVERGENCE

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Api call to modify AS number
    input_dict = {
        "r1": {"bgp": {"local_as": 131079}},
        "r2": {"bgp": {"local_as": 131079}},
        "r3": {"bgp": {"local_as": 131079}},
        "r4": {"bgp": {"local_as": 111}},
    }
    result = modify_as_number(tgen, topo, input_dict)
    if result != True:
        assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    result = verify_as_numbers(tgen, topo, input_dict)
    if result != True:
        assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Api call verify whether BGP is converged
    result = verify_bgp_convergence(tgen, topo)
    if result != True:
        assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    write_test_footer(tc_name)


def test_bgp_timers_functionality(request):
    """
    Test to modify bgp timers and verify timers functionality.
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to modfiy BGP timerse
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {
                                            "keepalivetimer": KEEPALIVETIMER,
                                            "holddowntimer": HOLDDOWNTIMER,
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, deepcopy(input_dict))
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Api call to clear bgp, so timer modification would take place
    clear_bgp_and_verify(tgen, topo, "r1")

    # Verifying bgp timers functionality
    result = verify_bgp_timers_and_functionality(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_static_routes(request):
    """ Test to create and verify static routes. """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to create static routes
    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": "10.0.20.1/32",
                    "no_of_ip": 9,
                    "admin_distance": 100,
                    "next_hop": "10.0.0.2",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "static"},
                                {"redist_type": "connected"},
                            ]
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    next_hop = ["10.0.0.2", "10.0.0.5"]
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=next_hop, protocol=protocol
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_admin_distance_for_existing_static_routes(request):
    """ Test to modify and verify admin distance for existing static routes."""

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": "10.0.20.1/32",
                    "admin_distance": 10,
                    "next_hop": "10.0.0.2",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying admin distance  once modified
    result = verify_admin_distance_for_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_advertise_network_using_network_command(request):
    """ Test advertise networks using network command."""

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "20.0.0.0/32", "no_of_network": 10},
                                {"network": "30.0.0.0/32", "no_of_network": 10},
                            ]
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r2"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_clear_bgp_and_verify(request):
    """
    Created few static routes and verified all routes are learned via BGP
    cleared BGP and verified all routes are intact
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # clear ip bgp
    result = clear_bgp_and_verify(tgen, topo, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_with_loopback_interface(request):
    """
    Test BGP with loopback interface

    Adding keys:value pair  "dest_link": "lo" and "source_link": "lo"
    peer dict of input json file for all router's creating config using
    loopback interface. Once BGP neighboship is up then verifying BGP
    convergence
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    for routerN in sorted(topo["routers"].keys()):
        for bgp_neighbor in topo["routers"][routerN]["bgp"]["address_family"]["ipv4"][
            "unicast"
        ]["neighbor"].keys():

            # Adding ['source_link'] = 'lo' key:value pair
            topo["routers"][routerN]["bgp"]["address_family"]["ipv4"]["unicast"][
                "neighbor"
            ][bgp_neighbor]["dest_link"] = {"lo": {"source_link": "lo",}}

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "1.0.2.17/32", "next_hop": "10.0.0.2"},
                {"network": "1.0.3.17/32", "next_hop": "10.0.0.6"},
            ]
        },
        "r2": {
            "static_routes": [
                {"network": "1.0.1.17/32", "next_hop": "10.0.0.1"},
                {"network": "1.0.3.17/32", "next_hop": "10.0.0.10"},
            ]
        },
        "r3": {
            "static_routes": [
                {"network": "1.0.1.17/32", "next_hop": "10.0.0.5"},
                {"network": "1.0.2.17/32", "next_hop": "10.0.0.9"},
                {"network": "1.0.4.17/32", "next_hop": "10.0.0.14"},
            ]
        },
        "r4": {"static_routes": [{"network": "1.0.3.17/32", "next_hop": "10.0.0.13"}]},
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Api call verify whether BGP is converged
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
