#!/usr/bin/env python

#
# Modified work Copyright (c) 2019 by VMware, Inc. ("VMware")
# Original work Copyright (c) 2018 by Network Device Education
# Foundation, Inc. ("NetDEF")
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
Following tests are covered to test AS-Path functionality:

Setup module:
- Create topology (setup module)
- Bring up topology
- Verify BGP convergence

Test cases:
1. Test next_hop attribute and verify best path is installed as per
   reachable next_hop
2. Test aspath attribute and verify best path is installed as per
   shortest AS-Path
3. Test localpref attribute and verify best path is installed as per
   shortest local-preference
4. Test weight attribute and and verify best path is installed as per
   highest weight
5. Test origin attribute and verify best path is installed as per
   IGP>EGP>INCOMPLETE rule
6. Test med attribute and verify best path is installed as per lowest
   med value
7. Test admin distance and verify best path is installed as per lowest
   admin distance

Teardown module:
- Bring down the topology
- stop routers

"""

import os
import sys
import pdb
import json
import time
import inspect
import ipaddress
from time import sleep
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from mininet.topo import Topo
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

# Required to instantiate the topology builder class.
from lib.common_config import (
    start_topology, write_test_header,
    write_test_footer, reset_config_on_routers,
    verify_rib, create_static_routes,
    create_prefix_lists, verify_prefix_lists,
    create_route_maps, check_address_types
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence, create_router_bgp,
    clear_bgp_and_verify, verify_best_path_as_per_bgp_attribute,
    verify_best_path_as_per_admin_distance, modify_as_number,
    verify_as_numbers
)
from lib.topojson import build_topo_from_json, build_config_from_json

# Reading the data from JSON File for topology creation
jsonFile = "{}/bgp_path_attributes.json".format(CWD)

try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

# Address read from env variables
ADDR_TYPES = check_address_types()

####
class CreateTopo(Topo):
    """
    Test CreateTopo - topology 1

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Building topology and configuration from json file
        build_topo_from_json(tgen, topo)


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global ADDR_TYPES

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: %s", testsuite_run_time)
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

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Checking BGP convergence
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, ("setup_module :Failed \n Error:"
                            " {}".format(result))

    logger.info("Running setup_module() done")


def teardown_module():
    """
    Teardown the pytest environment
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info("Testsuite end time: %s",
                time.asctime(time.localtime(time.time())))
    logger.info("=" * 40)


#####################################################
##
##   Testcases
##
#####################################################

def test_next_hop_attribute(request):
    """
    Verifying route are not getting installed in, as next_hop is
    unreachable, Making next hop reachable using next_hop_self
    command and verifying routes are installed.
    """

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict = {
        "r7": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.50.2.0/32"
                                },
                                {
                                    "network": "200.60.2.0/32"
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200:50:2::/128"
                                },
                                {
                                    "network": "200:60:2::/128"
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying RIB routes
    dut = "r1"
    protocol = "bgp"
    # Verification should fail as nexthop-self is not enabled
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
                            protocol=protocol, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error: "\
            "{} routes are not present in RIB".format(addr_type, tc_name)

    # Configure next-hop-self to bgp neighbor
    input_dict_1 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying RIB routes
    dut = "r1"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
                            protocol=protocol)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_aspath_attribute(request):
    " Verifying AS_PATH attribute functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict = {
        "r7": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.50.2.0/32"
                                },
                                {
                                    "network": "200.60.2.0/32"
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200:50:2::/128"
                                },
                                {
                                    "network": "200:60:2::/128"
                                }
                            ]
                        }
                    }
                }
            }
        },
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "aspath"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   {"r7": input_dict["r7"]},
                                                   attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    # Modify AS-Path and verify best path is changed
    # Create Prefix list

    input_dict_2 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_ls_1_ipv4": [{
                        "seqid": 10,
                        "network": "200.0.0.0/8",
                        "le": "32",
                        "action": "permit"
                    }]
                },
                "ipv6": {
                    "pf_ls_1_ipv6": [{
                        "seqid": 10,
                        "network": "200::/8",
                        "le": "128",
                        "action": "permit"
                    }]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Create route map
    input_dict_3 = {
        "r3": {
            "route_maps": {
                "RMAP_AS_PATH": [{
                    "action": "permit",
                    "match": {
                        "ipv4": {
                            "prefix_lists": "pf_ls_1_ipv4"
                        }
                    },
                    "set": {
                        "aspath": {
                            "as_num": "111 222",
                            "as_action": "prepend"
                        }
                    }
                },
                {
                    "action": "permit",
                    "match": {
                        "ipv6": {
                            "prefix_lists": "pf_ls_1_ipv6"
                        }
                    },
                    "set": {
                        "aspath": {
                            "as_num": "111 222",
                            "as_action": "prepend"
                        }
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r5": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {"name": "RMAP_AS_PATH",
                                                 "direction": "in"}
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r5": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {"name": "RMAP_AS_PATH",
                                                 "direction": "in"}
                                            ]
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
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "aspath"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   {"r7": input_dict["r7"]},
                                                   attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_localpref_attribute(request):
    " Verifying LOCAL PREFERENCE attribute functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict = {
        "r7": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.50.2.0/32"
                                },
                                {
                                    "network": "200.60.2.0/32"
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200:50:2::/128"
                                },
                                {
                                    "network": "200:60:2::/128"
                                }
                            ]
                        }
                    }
                }
            }
        },
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Create Prefix list
    input_dict_2 = {
        "r2": {
            "prefix_lists": {
                "ipv4": {
                    "pf_ls_1_ipv4": [{
                        "seqid": 10,
                        "network": "200.0.0.0/8",
                        "le": "32",
                        "action": "permit"
                    }]
                },
                "ipv6": {
                    "pf_ls_1_ipv6": [{
                        "seqid": 10,
                        "network": "200::/8",
                        "le": "128",
                        "action": "permit"
                    }]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Create route map
    input_dict_3 = {
        "r2": {
            "route_maps": {
                "RMAP_LOCAL_PREF": [{
                    "action": "permit",
                    "seq_id": "10",
                    "match": {
                        "ipv4": {
                            "prefix_lists": "pf_ls_1_ipv4"
                        }
                    },
                    "set": {
                        "localpref": 1111
                    }
                },
                {
                    "action": "permit",
                    "seq_id": "20",
                    "match": {
                        "ipv6": {
                            "prefix_lists": "pf_ls_1_ipv6"
                        }
                    },
                    "set": {
                        "localpref": 1111
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "route_maps": [
                                                {"name": "RMAP_LOCAL_PREF",
                                                 "direction": "in"}
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "route_maps": [
                                                {"name": "RMAP_LOCAL_PREF",
                                                 "direction": "in"}
                                            ]
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
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "localpref"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   {"r7": input_dict["r7"]},
                                                   attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    # Modify route map
    input_dict_3 = {
        "r2": {
            "route_maps": {
                "RMAP_LOCAL_PREF": [{
                    "action": "permit",
                    "seq_id": "10",
                    "match": {
                        "ipv4": {
                            "prefix_lists": "pf_ls_1_ipv4"
                        }
                    },
                    "set": {
                        "localpref": 50
                    }
                },
                {
                    "action": "permit",
                    "seq_id": "20",
                    "match": {
                        "ipv6": {
                            "prefix_lists": "pf_ls_1_ipv6"
                        }
                    },
                    "set": {
                        "localpref": 50
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "localpref"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   {"r7": input_dict["r7"]},
                                                   attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_weight_attribute(request):
    """
    Test configure/modify weight attribute and
    verify best path is installed as per highest weight
    """

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict = {
        "r7": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.50.2.0/32"
                                },
                                {
                                    "network": "200.60.2.0/32"
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200:50:2::/128"
                                },
                                {
                                    "network": "200:60:2::/128"
                                }
                            ]
                        }
                    }
                }
            }
        },
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Create Prefix list
    input_dict_2 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "pf_ls_1_ipv4": [{
                        "seqid": 10,
                        "network": "200.0.0.0/8",
                        "le": "32",
                        "action": "permit"
                    }]
                },
                "ipv6": {
                    "pf_ls_1_ipv6": [{
                        "seqid": 10,
                        "network": "200::/8",
                        "le": "128",
                        "action": "permit"
                    }]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Create route map
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMAP_WEIGHT": [{
                    "action": "permit",
                    "seq_id": "5",
                    "match": {
                        "ipv4": {
                            "prefix_lists": "pf_ls_1_ipv4"
                        }
                    },
                    "set": {
                        "weight": 500
                    }
                },
                {
                    "action": "permit",
                    "seq_id": "10",
                    "match": {
                        "ipv6": {
                            "prefix_lists": "pf_ls_1_ipv6"
                        }
                    },
                    "set": {
                        "weight": 500
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [
                                                {"name": "RMAP_WEIGHT",
                                                 "direction": "in"}
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [
                                                {"name": "RMAP_WEIGHT",
                                                 "direction": "in"}
                                            ]
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
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "weight"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   {"r7": input_dict["r7"]},
                                                   attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    # Modify route map
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMAP_WEIGHT": [{
                    "action": "permit",
                    "seq_id": "5",
                    "match": {
                        "ipv4": {
                            "prefix_lists": "pf_ls_1_ipv4"
                        }
                    },
                    "set": {
                        "weight": 1000
                    }
                },
                {
                    "action": "permit",
                    "seq_id": "10",
                    "match": {
                        "ipv6": {
                            "prefix_lists": "pf_ls_1_ipv6"
                        }
                    },
                    "set": {
                        "weight": 1000
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "weight"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   {"r7": input_dict["r7"]},
                                                   attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_origin_attribute(request):
    """
    Test origin attribute and verify best path is
    installed as per IGP>EGP>INCOMPLETE rule
    """

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.50.2.0/32"
                                },
                                {
                                    "network": "200.60.2.0/32"
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200:50:2::/128"
                                },
                                {
                                    "network": "200:60:2::/128"
                                }
                            ]
                        }
                    }
                }
            }
        },
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r5": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "static"},
                                {"redist_type": "connected"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "static"},
                                {"redist_type": "connected"}
                            ]
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Api call to create static routes
    input_dict_3 = {
        "r5": {
            "static_routes": [
                {
                    "network": "200.50.2.0/32",
                    "next_hop": "Null0"
                },
                {
                    "network": "200.60.2.0/32",
                    "next_hop": "Null0"
                },
                {
                    "network": "200:50:2::/128",
                    "next_hop": "Null0"
                },
                {
                    "network": "200:60:2::/128",
                    "next_hop": "Null0"
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "origin"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   {"r4": input_dict["r4"]},
                                                   attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_med_attribute(request):
    """
    Test configure/modify MED attribute and verify best path
    is installed as per lowest med value
    """

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.50.2.0/32"
                                },
                                {
                                    "network": "200.60.2.0/32"
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200:50:2::/128"
                                },
                                {
                                    "network": "200:60:2::/128"
                                }
                            ]
                        }
                    }
                }
            }
        },
        "r5": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.50.2.0/32"
                                },
                                {
                                    "network": "200.60.2.0/32"
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200:50:2::/128"
                                },
                                {
                                    "network": "200:60:2::/128"
                                }
                            ]
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Create Prefix list
    input_dict_2 = {
        "r2": {
            "prefix_lists": {
                "ipv4": {
                    "pf_ls_r2_ipv4": [{
                        "seqid": 10,
                        "network": "200.0.0.0/8",
                        "le": "32",
                        "action": "permit"
                    }]
                },
                "ipv6": {
                    "pf_ls_r2_ipv6": [{
                        "seqid": 20,
                        "network": "200::/8",
                        "le": "128",
                        "action": "permit"
                    }]
                }
            }
        },
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_ls_r3_ipv4": [{
                        "seqid": 10,
                        "network": "200.0.0.0/8",
                        "le": "32",
                        "action": "permit"
                    }]
                },
                "ipv6": {
                    "pf_ls_r3_ipv6": [{
                        "seqid": 20,
                        "network": "200::/8",
                        "le": "128",
                        "action": "permit"
                    }]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Create route map
    input_dict_3 = {
        "r2": {
            "route_maps": {
                "RMAP_MED_R2": [{
                    "action": "permit",
                    "seq_id": "10",
                    "match": {
                        "ipv4": {
                            "prefix_lists": "pf_ls_r2_ipv4"
                        }
                    },
                    "set": {
                        "med": 100
                    }
                },
                {
                    "action": "permit",
                    "seq_id": "20",
                    "match": {
                        "ipv6": {
                            "prefix_lists": "pf_ls_r2_ipv6"
                        }
                    },
                    "set": {
                        "med": 100
                    }
                }]
            }
        },
        "r3": {
            "route_maps": {
                "RMAP_MED_R3": [{
                    "action": "permit",
                    "seq_id": "10",
                    "match": {
                        "ipv4": {
                            "prefix_lists": "pf_ls_r3_ipv4"
                        }
                    },
                    "set": {
                        "med": 10
                    }
                },
                {
                    "action": "permit",
                    "seq_id": "20",
                    "match": {
                        "ipv6": {
                            "prefix_lists": "pf_ls_r3_ipv6"
                        }
                    },
                    "set": {
                        "med": 10
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "route_maps": [
                                                {"name": "RMAP_MED_R2",
                                                 "direction": "in"}
                                            ]
                                        }
                                    }
                                },
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "route_maps": [
                                                {"name": "RMAP_MED_R2",
                                                 "direction": "in"}
                                            ]
                                        }
                                    }
                                },
                                "r1": {
                                    "dest_link": {
                                        "r2": {"next_hop_self": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                },
                                "r5": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {"name": "RMAP_MED_R3",
                                                 "direction": "in"}
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"next_hop_self": True}
                                    }
                                },
                                "r5": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {"name": "RMAP_MED_R3",
                                                 "direction": "in"}
                                            ]
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

    result = create_router_bgp(tgen, topo,  input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "med"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   input_dict, attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    # Modify route-map to set med value
    input_dict_3 = {
        "r3": {
            "route_maps": {
                "RMAP_MED_R3": [{
                    "action": "permit",
                    "seq_id": "10",
                    "match": {
                        "ipv4": {
                            "prefix_lists": "pf_ls_r3_ipv4"
                        }
                    },
                    "set": {
                        "med": 200
                    }
                },
                {
                    "action": "permit",
                    "seq_id": "20",
                    "match": {
                        "ipv6": {
                            "prefix_lists": "pf_ls_r3_ipv6"
                        }
                    },
                    "set": {
                        "med": 200
                    }
                }]
            }
        }
    }

    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "med"
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_bgp_attribute(tgen, addr_type, dut,
                                                   input_dict, attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_admin_distance(request):
    " Verifying admin distance functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to create static routes
    input_dict = {
        "r2": {
            "static_routes": [
                {
                    "network": "200.50.2.0/32",
                    "admin_distance": 80,
                    "next_hop": "10.0.0.14"
                },
                {
                    "network": "200.50.2.0/32",
                    "admin_distance": 60,
                    "next_hop": "10.0.0.18"
                },
                {
                    "network": "200:50:2::/128",
                    "admin_distance": 80,
                    "next_hop": "fd00::1"
                },
                {
                    "network": "200:50:2::/128",
                    "admin_distance": 60,
                    "next_hop": "fd00::1"
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_2 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "static"},
                                {"redist_type": "connected"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "static"},
                                {"redist_type": "connected"}
                            ]
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    # Verifying best path
    dut = "r1"
    attribute = "admin_distance"

    input_dict = {
    "ipv4": {
        "r2": {
            "static_routes": [{
                    "network": "200.50.2.0/32",
                    "admin_distance": 80,
                    "next_hop": "10.0.0.14"
                },
                {
                    "network": "200.50.2.0/32",
                    "admin_distance": 60,
                    "next_hop": "10.0.0.18"
                }
            ]
        }
    },
    "ipv6": {
        "r2": {
            "static_routes": [{
                    "network": "200:50:2::/128",
                    "admin_distance": 80,
                    "next_hop": "fd00::1"
                },
                {
                    "network": "200:50:2::/128",
                    "admin_distance": 60,
                    "next_hop": "fd00::1"
                }]
            }
        }
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(tgen, addr_type, dut,
                                                        input_dict[addr_type],
                                                        attribute)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
