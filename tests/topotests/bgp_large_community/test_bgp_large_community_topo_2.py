#!/usr/bin/env python

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
#Inc. ("NetDEF") in this file.
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
test_bgp_large_community_topo_1.py: Test BGP large community.

Following tests are covered:
1. Verify the standard large-community-lists can permit or deny
   large community attribute only in the correct canonical format.
2. Verify the expanded large-community-lists can permit or deny
   large community attribute both in the correct canonical format
   as well as REG_EX.
3. Verify that we can modify a large-community-list is in use,
   to add/remove attribute value and it takes immediate effect.
4. Verify that large community attribute gets advertised when
   route-map is applied to a neighbor and cleared when route-map
   is removed.
5. Verify that duplicate BGP Large Community values are NOT be transmitted.
6. Verify if we want to remove all the large-community attributes from a
   set of prefix we can set the value as NONE.
7. Redistribute connected and static routes in BGP process with a route-map
   appending/removing L-comm attributes.
8. Verify if we want to remove specific large-community values from
   a set of prefix we can make use of DELETE operation based on L-comm list.
9. Verify that if community values are NOT be advertised to a specific
   neighbour, we negate send-community command.
   (Send-community all is enabled by default for all neighbors)
10. Verify that large-community lists can not be configured without providing
    specific L-community values(for match/delete operation in a route-map).
11. Verify that Match_EXACT clause should pass only if all of the L-comm
    values configured (horizontally) in the community list is present in
    the prefix.  There must be no additional L-communities in the prefix.
12. Verify that Match_ALL clause should pass only if ALL of the L-comm values
    configured (horizontally) in the community list is present in the prefix.
    There could be additional L-communities in the prefix that are not present
    in the L-comm list.
13. Verify that Match_ANY clause should pass only if at-least any one L-comm
    value configured(vertically) in large-community list, is present in prefixes.
14. Verify large-community lists operation in a route-map with match RegEx
    statements.
"""

import os
import sys
import json
import pytest
import time

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
# Import topoJson from lib, to create topology and initial configuration
from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo

from lib.common_config import (
    start_topology, write_test_header,
    write_test_footer, reset_config_on_routers,
    create_route_maps, create_bgp_community_lists,
    create_prefix_lists, verify_bgp_community, step,
    verify_create_community_list, delete_route_maps,
    verify_route_maps, create_static_routes,
    check_address_types
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence, create_router_bgp,
    clear_bgp_and_verify
)
from lib.topojson import build_topo_from_json, build_config_from_json

# Reading the data from JSON File for topology and configuration creation
jsonFile = "{}/bgp_large_community_topo_2.json".format(CWD)

try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

# Global variables
bgp_convergence = False

NETWORKS = {"ipv4": ["200.50.2.0/32"], "ipv6": ["1::1/128"]}


class GenerateTopo(Topo):
    """
    Test topology builder

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        "Build function"
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
    logger.info("="*40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(GenerateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Checking BGP convergence
    global bgp_convergence, ADDR_TYPES

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    # Ipv4
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, ("setup_module :Failed \n Error:"
                                     " {}".format(bgp_convergence))
    ADDR_TYPES = check_address_types()

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

    logger.info("Testsuite end time: {}".\
                format(time.asctime(time.localtime(time.time()))))
    logger.info("="*40)

#####################################################
#
#   Testcases
#
#####################################################


def test_create_bgp_standard_large_community_list(request):
    """
    Create standard large-community-list and verify it can permit
    or deny large community attribute only in the correct canonical
    format.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)

    step("Create srtandard large community list")
    input_dict = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "LC_1_STD",
                    "value": "2:1:1 2:1:2 1:2:3",
                    "large": True
                },
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "LC_2_STD",
                    "value": "3:1:1 3:1:2",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify BGP large community is created")
    result = verify_create_community_list(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create srtandard large community list with in-correct values")
    input_dict = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "LC_1_STD_ERR",
                    "value": "0:0:0",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    ## TODO should fail
    step("Verify BGP large community is created")
    result = verify_create_community_list(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    write_test_footer(tc_name)


def test_create_bgp_expanded_large_community_list(request):
    """
    Create expanded large-community-list and verify it can permit
    or deny large community attribute both in the correct canonical
    format as well as REG_EX
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create expanded large community list")
    input_dict = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "expanded",
                    "action": "permit",
                    "name": "LC_1_EXP",
                    "value": "1:1:200 1:2:* 3:2:1",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify BGP large community is created")
    result = verify_create_community_list(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    write_test_footer(tc_name)


def test_modify_large_community_lists_referenced_by_rmap(request):
    """
    This test is to verify that we can modify a large-community-list
    is in use, add/remove attribute value and it takes immediate effect.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create standard large community list")
    input_dict_1 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "LC_DEL",
                    "value": "1:2:1 1:3:1 2:1:1 2:2:2 3:3:3",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create route map")
    input_dict_2 = {
        "r1": {
            "route_maps": {
                "RM_R2_OUT": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "1:2:1 1:3:1 2:10:1 3:3:3 4:4:4 5:5:5",
                                "action": "additive"
                            }
                        }
                    }
                ]
            }
        },
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_comm_list": {
                                "id": "LC_DEL",
                                "delete": True
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map and advertise networks")
    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ],
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [{
                                                "name": "RM_R2_OUT",
                                                "direction": "out"
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
                            ],
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [{
                                                "name": "RM_R2_OUT",
                                                "direction": "out"
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify Community-list")
    dut = "r4"
    input_dict_4 = {
        "largeCommunity": "2:10:1 4:4:4 5:5:5"
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_lists_with_rmap_apply_and_remove(request):
    """
    This test is to verify that large community attribute gets advertised when
    route-map is applied to a neighbor and cleared when route-map is removed
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create route map")
    input_dict_1 = {
        "r4": {
            "route_maps": {
                "RM_LC1": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "200:200:1 200:200:10 200:200:20000",
                                "action": "additive"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map and advertise networks")
    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
                            ]
                        }
                    }
                }
            }
        },
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r6": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_LC1",
                                                "direction": "out"
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r6": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_LC1",
                                                "direction": "out"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list")
    dut = "r6"
    input_dict_4 = {
        "largeCommunity": "200:200:1 200:200:10 200:200:20000"
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Delete route map reference by community-list")
    input_dict_3 = {
        "r4": {
            "route_maps": ["RM_LC1"]
        }
    }
    result = delete_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify route map is deleted")
    result = verify_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list")
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_4, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_duplicate_large_community_list_attributes_not_transitive(request):
    """
    This test is to verify that duplicate BGP Large Community values
    are NOT be transmitted.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create route map")
    input_dict_1 = {
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "0:0:1 0:0:10 0:0:100 2:0:1 2:0:2 2:0:3"
                                       " 2:0:4 2:0:5",
                                "action": "additive"
                            }
                        }
                    }
                ],
                "RM_R4_OUT": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "0:0:1 0:0:10 0:0:10000 2:0:1 2:0:2",
                                "action": "additive"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map and advertise networks")
    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
                            ]
                        }
                    }
                }
            }
        },
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
                                        }
                                    }
                                },
                                "r6": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
                                        }
                                    }
                                },
                                "r6": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list")
    dut = "r6"
    input_dict_4 = {
        "largeCommunity":
            "0:0:1 0:0:10 0:0:100 0:0:10000 2:0:1 2:0:2 2:0:3 2:0:4 2:0:5"
    }
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_lists_with_rmap_set_none(request):
    """
    This test is to verify if we want to remove all the large-community
    attributes from a set of prefix we can set the value as NONE.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create route map")
    input_dict_1 = {
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "0:0:1 0:0:10 0:0:100 2:0:1 2:0:2 2:0:3"
                                       " 2:0:4",
                                "action": "additive"
                            }
                        }
                    }
                ]
            }
        },
        "r6": {
            "route_maps": {
                "RM_R6_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "none"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map")
    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
                            ]
                        }
                    }
                }
            }
        },
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r6": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r6": {
                                            "route_maps": [{
                                                "name": "RM_R6_IN",
                                                "direction": "in"
                                            }]
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
                                        "r6": {
                                            "route_maps": [{
                                                "name": "RM_R6_IN",
                                                "direction": "in"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify Community-list")
    dut = "r6"
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      expected=False)
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_lcomm_lists_with_redistribute_static_connected_rmap(request):
    """
    This test is to verify redistribute connected and static ipv4 routes
    in BGP process with a route-map appending/removing L-comm attributes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("create static routes")
    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": "200.50.2.0/32",
                    "next_hop": "10.0.0.6"
                },
                {
                    "network": "1::1/128",
                    "next_hop": "fd00:0:0:1::2"
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("redistribute static routes")
    input_dict_1 = {
        "r1":{
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {
                                    "redist_type": "static",
                                    "attribute": "route-map RM_R2_OUT"
                                },
                                {
                                    "redist_type": "connected",
                                    "attribute": "route-map RM_R2_OUT"
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {
                                    "redist_type": "static",
                                    "attribute": "route-map RM_R2_OUT"
                                },
                                {
                                    "redist_type": "connected",
                                    "attribute": "route-map RM_R2_OUT"
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create route map")
    input_dict_3 = {
        "r1": {
            "route_maps": {
                 "RM_R2_OUT": [{
                     "action": "permit",
                     "set": {
                         "large_community": {"num":"55:55:55 555:555:555"}
                     }
                 }]
            }
         }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list for static and connected ipv4 route on"
         " r2")

    input_dict_5 = {
        "largeCommunity": "55:55:55 555:555:555"
    }

    if "ipv4" in ADDR_TYPES:
        dut = "r2"
        networks = ["200.50.2.0/32", "1.0.1.17/32"]
        result = verify_bgp_community(tgen, "ipv4", dut, networks,
                                      input_dict_5)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

        step("Verify large-community-list for static and connected ipv4 route"
             " on r4")
        dut = "r4"
        networks = ["200.50.2.0/32", "1.0.1.17/32"]
        result = verify_bgp_community(tgen, "ipv4", dut, networks,
                                      input_dict_5)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    if "ipv6" in ADDR_TYPES:
        step("Verify large-community-list for static and connected ipv6 route"
             " on r2")
        dut = "r2"
        networks = ["1::1/128", "2001:db8:f::1:17/128"]
        result = verify_bgp_community(tgen, "ipv6", dut, networks,
                                      input_dict_5)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

        step("Verify large-community-list for static and connected ipv6 route"
             " on r4")
        dut = "r4"
        networks = ["1::1/128", "2001:db8:f::1:17/128"]
        result = verify_bgp_community(tgen, "ipv6", dut, networks,
                                      input_dict_5)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_lists_with_rmap_set_delete(request):
    """
    This test is to verify if we want to remove specific large-community
    values from a set of prefix we can make use of DELETE operation based
    on L-comm list
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("configure route_map")
    input_dict_2 = {
        "r6": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "Test",
                    "value": "1:2:1 1:1:10 1:3:100",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create route map")
    input_dict_3 = {
        "r6": {
            "route_maps": {
                "RM_R6_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_comm_list": {
                                "id": "Test",
                                "delete": True
                            }
                        }
                    }
                ]
            }
        },
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "1:2:1 1:1:10 1:3:100 2:1:1 2:2:2 2:3:3"
                                       " 2:4:4 2:5:5",
                                "action": "additive"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map and advertise networks")
    input_dict_4 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
                            ]
                        }
                    }
                }
            }
        },
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r6": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r6": {
                                            "route_maps": [{
                                                "name": "RM_R6_IN",
                                                "direction": "in"
                                            }]
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
                                        "r6": {
                                            "route_maps": [{
                                                "name": "RM_R6_IN",
                                                "direction": "in"
                                            }]
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

    step("Verify large-community-list")
    dut = "r6"
    input_dict_5 = {
        "largeCommunity": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
    }
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_5)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_lists_with_no_send_community(request):
    """
    This test is to verify if we want to remove specific large-community
    values from a set of prefix we can make use of DELETE operation based
    on L-comm list
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create route map")
    input_dict_2 = {
        "r5": {
            "route_maps": {
                "RM_R6_OUT": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map and advertise networks")
    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
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
                            "neighbor": {
                                "r6": {
                                    "dest_link": {
                                        "r5": {
                                            "route_maps": [{
                                                "name": "RM_R6_OUT",
                                                "direction": "out"
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r6": {
                                    "dest_link": {
                                        "r5": {
                                            "route_maps": [{
                                                "name": "RM_R6_OUT",
                                                "direction": "out"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list")
    dut = "r6"
    input_dict_4 = {
        "largeCommunity": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
    }
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Configure neighbor for no-send-community")
    input_dict_5 = {
        "r5": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r6": {
                                    "dest_link": {
                                        "r5": {
                                            "no_send_community": "large"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r6": {
                                    "dest_link": {
                                        "r5": {
                                            "no_send_community": "large"
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
    result = create_router_bgp(tgen, topo, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify Community-list")
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_4, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_create_large_community_lists_with_no_attribute_values(request):
    """
    This test is to verify that large-community lists can not be
    configured without providing specific L-community values
    (for match/delete operation in a route-map).
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create standard large commumity-list")
    input_dict_1 = {
        "r5": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "Test1",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_1)
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    write_test_footer(tc_name)


def test_large_community_lists_with_rmap_match_exact(request):
    """
    This test is to verify that Match_EXACT clause should pass
    only if all of the L-comm values configured (horizontally)
    in the community list is present in the prefix. There must
    be no additional L-communities in the prefix.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create route map")
    input_dict_2 = {
        "r2": {
            "route_maps": {
                "RM_R4_OUT": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map and advertise networks")
    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
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
                                "r4": {
                                    "dest_link": {
                                        "r2": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
                                        "r2": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create standard large commumity-list")
    input_dict_4 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "EXACT",
                    "value": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify BGP large community is created")
    result = verify_create_community_list(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create route map")
    input_dict_5 = {
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {
                            "large-community-list": ["EXACT"],
                            "match_exact": True
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map")
    input_dict_6 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_6)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list")
    dut = "r4"
    input_dict_4 = {
        "largeCommunity": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
    }
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_lists_with_rmap_match_all(request):
    """
    This test is to verify that Match_ALL clause should pass
    only if ALL of the L-comm values configured (horizontally)
    in the community list are present in the prefix. There
    could be additional L-communities in the prefix that are
    not present in the L-comm list.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create route map")
    input_dict_2 = {
        "r2": {
            "route_maps": {
                "RM_R4_OUT": [{
                    "action": "permit",
                    "set": {
                        "large_community": {
                            "num": "1:1:1 1:2:3 2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
                        }
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map")
    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
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
                                "r4": {
                                    "dest_link": {
                                        "r2": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
                                        "r2": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create standard large commumity-list")
    input_dict_4 = {
        "r3": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ALL",
                    "value": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify BGP large community is created")
    result = verify_create_community_list(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create route map")
    input_dict_5 = {
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {
                            "large-community-list": {
                                "id": "ALL"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map")
    input_dict_6 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_6)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list")
    dut = "r4"
    input_dict_4 = {
        "largeCommunity": "1:1:1 1:2:3 2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
    }
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_lists_with_rmap_match_any(request):
    """
    This test is to verify that Match_ANY clause should pass
    only if at-least any one L-comm value configured(vertically)
    in large-community list, is present in prefixes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create route map")
    input_dict_2 = {
        "r2": {
            "route_maps": {
                "RM_R4_OUT": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map")
    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
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
                                "r4": {
                                    "dest_link": {
                                        "r2": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
                                        "r2": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create standard large commumity-list")
    input_dict_4 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "2:1:1",
                    "large": True
                },
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "2:2:1",
                    "large": True
                },
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "2:3:1",
                    "large": True
                },
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "2:4:1",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify BGP large community is created")
    result = verify_create_community_list(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create route map")
    input_dict_5 = {
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {
                            "large-community-list": {
                                "id": "ANY"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map")
    input_dict_6 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_6)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list")
    dut = "r4"
    input_dict_7 = {
        "largeCommunity": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
    }
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_lists_with_rmap_match_regex(request):
    """
    This test is to verify large-community lists" operation in a route-map
    with match RegEx statements. Match clause should pass only if the
    complete string of L-comm values are matched
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Create route map")
    input_dict_2 = {
        "r2": {
            "route_maps": {
                "RM_R4_OUT": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": "1:1:1 1:1:2 2:1:3 2:1:4 2:1:5",
                            },
                            "community": {
                                "num": "1:1 1:2 1:3 1:4 1:5"
                            }
                        }
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map")
    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.50.2.0/32"}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "1::1/128"}
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
                                "r4": {
                                    "dest_link": {
                                        "r2": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
                                        "r2": {
                                            "route_maps": [{
                                                "name": "RM_R4_OUT",
                                                "direction": "out"
                                            }]
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
    result = create_router_bgp(tgen, topo,input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create standard large commumity-list")
    input_dict_4 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ALL",
                    "value": "1:1:1 2:1:3 2:1:4 2:1:5",
                    "large": True
                },
                {
                    "community_type": "expanded",
                    "action": "permit",
                    "name": "EXP_ALL",
                    "value": "1:1:1 2:1:[3-5]",
                    "large": True
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify BGP large community is created")
    result = verify_create_community_list(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create route map")
    input_dict_5 = {
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {
                            "large_community_list": {
                                "id": "ALL",
                            },
                        },
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Configure neighbor for route map")
    input_dict_6 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
                                        "r4": {
                                            "route_maps": [{
                                                "name": "RM_R4_IN",
                                                "direction": "in"
                                            }]
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
    result = create_router_bgp(tgen, topo, input_dict_6)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Verify large-community-list")
    dut = "r4"
    input_dict_7 = {
        "largeCommunity": "1:1:1 1:1:2 2:1:3 2:1:4 2:1:5"
    }
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Delete route map reference by community-list")
    input_dict_3 = {
        "r4": {
            "route_maps": ["RM_R4_IN"]
        }
    }
    result = delete_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    result = verify_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("Create route map")
    input_dict_5 = {
        "r4": {
            "route_maps": {
                "RM_R4_IN": [
                    {
                        "action": "permit",
                        "seq_id": "20",
                        "match": {
                            "large_community_list": {
                                "id": "EXP_ALL",
                            },
                        },
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result)

    step("clear ip bgp")
    result = clear_bgp_and_verify(tgen, topo, 'r4')
    assert result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, result)

    step("Verify large-community-list")
    dut = "r4"
    input_dict_7 = {
        "largeCommunity": "1:1:1 1:1:2 2:1:3 2:1:4 2:1:5"
    }
    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, dut, NETWORKS[adt],
                                      input_dict_7, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
