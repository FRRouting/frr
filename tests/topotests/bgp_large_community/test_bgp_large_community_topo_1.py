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
Following tests are covered to test large-community/community functionality:
1.  Verify if large community attribute can be configured only in correct
    canonical format.
2.  Verify that the community attribute value, which we have advertised are
    received in correct format and values, at the receiving end.
3.  Verify BGP Large Community attribute"s transitive property attribute.
4.  Verify that BGP Large Communities attribute are malformed, if the length of
    the BGP Large Communities Attribute value, expressed in octets,
    is not a non-zero multiple of 12.
5.  Verify if overriding large community values works fine.
6.  Verify that large community values" aggregation works fine.
7.  Standard community also work fine in conjunction with large-community.
8.  Matching prefixes based on attributes other than prefix list and make use
    of set clause (IPV6).
9.  Matching prefixes based on attributes other than prefix list and make use
    of set clause (IPV4).
10. Verify community and large-community list operations in route-map with all
    clause (exact, all, any, regex) works.
11. Verify that any value in BGP Large communities for boundary values.
12. Clear BGP neighbor-ship and check if large community and community
    attributes are getting re-populated.

"""

import pytest
import time
from os import path as os_path
import sys
from json import load as json_load

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo

from lib.common_config import (
    start_topology, write_test_header,
    write_test_footer, reset_config_on_routers,
    create_route_maps, create_bgp_community_lists,
    create_prefix_lists, verify_bgp_community, step,
    check_address_types
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence, create_router_bgp,
    clear_bgp_and_verify
)
from lib.topojson import build_topo_from_json, build_config_from_json

# Save the Current Working Directory to find configuration files.
CWD = os_path.dirname(os_path.realpath(__file__))
sys.path.append(os_path.join(CWD, "../"))
sys.path.append(os_path.join(CWD, "../lib/"))

# Reading the data from JSON File for topology and configuration creation
jsonFile = "{}/bgp_large_community_topo_1.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json_load(topoJson)
except IOError:
    logger.info("Could not read file:", jsonFile)

# Global variables
bgp_convergence = False
NETWORK = {
    "ipv4": ["200.50.2.0", "200.50.2.1", "200.50.2.0"],
    "ipv6": ["1::1", "1::2", "1::0"]
}
MASK = {"ipv4": "32", "ipv6": "128"}
NET_MASK = {"ipv4": "24", "ipv6": "120"}
IPV4_NET = ["200.50.2.0"]
IPV6_NET = ["1::0"]
CONFIG_ROUTER_R1 = False
CONFIG_ROUTER_R2 = False
CONFIG_ROUTER_ADDITIVE = False
ADDR_TYPES = []
LARGE_COMM = {
    "r1": "1:1:1 1:2:1 1:3:1 1:4:1 1:5:1",
    "r2": "2:1:1 2:2:1 2:3:1 2:4:1 2:5:1",
    "mal_1": "1:1 1:2 1:3 1:4 1:5",
    "pf_list_1": "0:0:1 0:0:10 0:0:100",
    "pf_list_2": "0:0:2 0:0:20 0:0:200",
    "agg_1": "0:0:1 0:0:2 0:0:10 0:0:20 0:0:100 0:0:200 2:1:1 "
             "2:2:1 2:3:1 2:4:1 2:5:1",
    "agg_2": "0:0:2 0:0:20 0:0:200 2:1:1 "
             "2:2:1 2:3:1 2:4:1 2:5:1"
}
STANDARD_COMM = {
    "r1": "1:1 1:2 1:3 1:4 1:5",
    "r2": "2:1 2:2 2:3 2:4 2:5",
    "mal_1": "1 2 3 4 5",
    "pf_list_1": "0:1 0:10 0:100",
    "pf_list_2": "0:2 0:20 0:200",
    "agg_1": "0:1 0:2 0:10 0:20 0:100 0:200 2:1 2:2 2:3 2:4 2:5",
    "agg_2": "0:2 0:20 0:200 2:1 2:2 2:3 2:4 2:5"
}


class CreateTopo(Topo):
    """
    Test topology builder


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
    global ADDR_TYPES
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

    # Checking BGP convergence
    global bgp_convergence

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    ##tgen.mininet_cli()
    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, ("setup_module :Failed \n Error:"
                                     " {}".format(bgp_convergence))

    ADDR_TYPES = check_address_types()
    logger.info("Running setup_module() done")


def teardown_module():
    """
    Teardown the pytest environment

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info("Testsuite end time: {}".
                format(time.asctime(time.localtime(time.time()))))
    logger.info("=" * 40)


def config_router_r1(tgen, topo, tc_name):
    global CONFIG_ROUTER_R1

    input_dict_1 = {
        "r1": {
            "route_maps": {
                "LC1": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": LARGE_COMM["r1"]
                            },
                            "community": {
                                "num": STANDARD_COMM["r1"]
                            }
                        }
                    }
                ]
            }
        }
    }

    step("Configuring LC1 on r1")
    result = create_route_maps(tgen, input_dict_1)
    assert result is True, "Test case {} : Failed \n Error: {}".format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "%s/%s" % (
                                        NETWORK["ipv4"][0], MASK["ipv4"]),
                                    "no_of_network": 4
                                }
                            ],
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {
                                            "route_maps": [{
                                                "name": "LC1",
                                                "direction": "out"
                                            }]
                                        }
                                    }
                                },
                                "r3": {
                                    "dest_link": {
                                        "r1-link1": {
                                            "route_maps": [{
                                                "name": "LC1",
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
                                {
                                    "network": "%s/%s" % (
                                        NETWORK["ipv6"][0], MASK["ipv6"]),
                                    "no_of_network": 4
                                }
                            ],
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {
                                            "route_maps": [{
                                                "name": "LC1",
                                                "direction": "out"
                                            }]
                                        }
                                    }
                                },
                                "r3": {
                                    "dest_link": {
                                        "r1-link1": {
                                            "route_maps": [{
                                                "name": "LC1",
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

    step("Applying LC1 on r1 neighbors and advertising networks")
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Test case {} : Failed \n Error: {}".format(
        tc_name, result)

    CONFIG_ROUTER_R1 = True


def config_router_r2(tgen, topo, tc_name):
    global CONFIG_ROUTER_R2

    input_dict = {
        "r2": {
            "route_maps": {
                "LC2": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": LARGE_COMM["r2"]
                            },
                            "community": {
                                "num": STANDARD_COMM["r2"]
                            }
                        }
                    }
                ]
            }
        }
    }

    step("Configuring route-maps LC2 on r2")
    result = create_route_maps(tgen, input_dict)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    input_dict_1 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "route_maps": [{
                                                "name": "LC2",
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
                                        "r2-link1": {
                                            "route_maps": [{
                                                "name": "LC2",
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

    step("Applying LC2 on r2 neighbors in out direction")
    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    CONFIG_ROUTER_R2 = True


def config_router_additive(tgen, topo, tc_name):
    global CONFIG_ROUTER_ADDITIVE

    input_dict = {
        "r2": {
            "route_maps": {
                "LC2": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {
                                "num": LARGE_COMM["r2"],
                                "action": "additive"
                            },
                            "community": {
                                "num": STANDARD_COMM["r2"],
                                "action": "additive"
                            }
                        }
                    }
                ]
            }
        }
    }

    step("Configuring LC2 with community attributes as additive")
    result = create_route_maps(tgen, input_dict)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    # tgen.mininet_cli()
    CONFIG_ROUTER_ADDITIVE = True


def config_for_as_path(tgen, topo, tc_name):
    config_router_r1(tgen, topo, tc_name)

    config_router_r2(tgen, topo, tc_name)

    # Create ipv6 prefix list
    input_dict_1 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "%s/%s" % (NETWORK["ipv4"][0],
                                                  MASK["ipv4"]),
                            "action": "permit"
                        }
                    ],
                    "pf_list_2": [
                        {
                            "seqid": "10",
                            "network": "%s/%s" % (NETWORK["ipv4"][1],
                                                  MASK["ipv4"]),
                            "action": "permit"
                        }
                    ]
                },
                "ipv6": {
                    "pf_list_3": [
                        {
                            "seqid": "10",
                            "network": "%s/%s" % (NETWORK["ipv6"][0],
                                                  MASK["ipv6"]),
                            "action": "permit"
                        }
                    ],
                    "pf_list_4": [
                        {
                            "seqid": "10",
                            "network": "%s/%s" % (NETWORK["ipv6"][1],
                                                  MASK["ipv6"]),
                            "action": "permit"
                        }
                    ]
                }

            }
        }
    }

    step("Configuring prefix-lists on r1 to filter networks")
    result = create_prefix_lists(tgen, input_dict_1)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    input_dict_2 = {
        "r1": {
            "route_maps": {
                "LC1": [
                    {
                        "action": "permit",
                        "seq_id": 10,
                        "match": {
                            "ipv4": {
                                "prefix_lists": "pf_list_1"
                            }
                        },
                        "set": {
                            "large_community": {
                                "num": LARGE_COMM["pf_list_1"]
                            },
                            "community": {
                                "num": STANDARD_COMM["pf_list_1"]
                            }
                        }
                    },
                    {
                        "action": "permit",
                        "seq_id": 20,
                        "match": {
                            "ipv6": {
                                "prefix_lists": "pf_list_3"
                            }
                        },
                        "set": {
                            "large_community": {
                                "num": LARGE_COMM["pf_list_1"]
                            },
                            "community": {
                                "num": STANDARD_COMM["pf_list_1"]
                            }
                        }
                    },
                    {
                        "action": "permit",
                        "seq_id": 30,
                        "match": {
                            "ipv4": {
                                "prefix_lists": "pf_list_2"
                            }
                        },
                        "set": {
                            "large_community": {
                                "num": LARGE_COMM["pf_list_2"]
                            },
                            "community": {
                                "num": STANDARD_COMM["pf_list_2"]
                            }
                        }
                    },
                    {
                        "action": "permit",
                        "seq_id": 40,
                        "match": {
                            "ipv6": {
                                "prefix_lists": "pf_list_4"
                            }
                        },
                        "set": {
                            "large_community": {
                                "num": LARGE_COMM["pf_list_2"]
                            },
                            "community": {
                                "num": STANDARD_COMM["pf_list_2"]
                            }
                        }
                    }
                ]
            }
        }
    }

    step("Applying prefix-lists match in route-map LC1 on r1. Setting"
         " community attritbute for filtered networks")
    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    config_router_additive(tgen, topo, tc_name)

    input_dict_3 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": LARGE_COMM["pf_list_1"],
                    "large": True
                },
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": STANDARD_COMM["pf_list_1"],
                }
            ]
        }
    }

    step("Configuring bgp community lists on r4")
    result = create_bgp_community_lists(tgen, input_dict_3)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    input_dict_4 = {
        "r4": {
            "route_maps": {
                "LC4": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {
                            "large_community_list": {"id": "ANY"},
                            "community_list": {"id": "ANY"}
                        },
                        "set": {
                            "aspath": {
                                "as_num": "4000000",
                                "as_action": "prepend"
                            }
                        }
                    }
                ]
            }
        }
    }

    step("Applying community list on route-map on r4")
    result = create_route_maps(tgen, input_dict_4)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    input_dict_5 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r5": {
                                    "dest_link": {
                                        "r4-link1": {
                                            "route_maps": [{
                                                "name": "LC4",
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
                                "r5": {
                                    "dest_link": {
                                        "r4-link1": {
                                            "route_maps": [{
                                                "name": "LC4",
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

    step("Applying route-map LC4 out from r4 to r5 ")
    result = create_router_bgp(tgen, topo, input_dict_5)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)


#####################################################
#
#   Test cases
#
#####################################################
def test_large_community_set(request):
    """
    Verify if large community attribute can be configured only in correct
    canonical format.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # API call to modify router id
    # input_dict dictionary to be provided to configure route_map
    input_dict = {
        "r1": {
            "route_maps": {
                "LC1": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {
                            "large_community": {"num": LARGE_COMM["r1"]},
                            "community": {"num": STANDARD_COMM["r1"]}
                        }
                    }
                ]
            }
        }
    }

    step("Trying to set bgp communities")
    result = create_route_maps(tgen, input_dict)
    assert result is True, "Test case {} : Failed \n Error: {}".format(
        tc_name, result)

    write_test_footer(tc_name)


def test_large_community_advertise(request):
    """
    Verify that the community attribute value, which we have advertised are
    received in correct format and values, at the receiving end.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    config_router_r1(tgen, topo, tc_name)

    input_dict = {
        "largeCommunity": LARGE_COMM["r1"],
        "community": STANDARD_COMM["r1"],
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r2", [NETWORK[adt][0]],
                                      input_dict)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result)

        result = verify_bgp_community(tgen, adt, "r3", [NETWORK[adt][0]],
                                      input_dict)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_transitive(request):
    """
    Verify BGP Large Community attribute"s transitive property attribute.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)

    config_router_r1(tgen, topo, tc_name)

    input_dict_1 = {
        "largeCommunity": LARGE_COMM["r1"],
        "community": STANDARD_COMM["r1"]
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r4", [NETWORK[adt][0]],
                                      input_dict_1)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result)

    write_test_footer(tc_name)


def test_large_community_override(request):
    """
    Verify if overriding large community values works fine.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    config_router_r1(tgen, topo, tc_name)

    config_router_r2(tgen, topo, tc_name)

    input_dict_3 = {
        "largeCommunity": LARGE_COMM["r2"],
        "community": STANDARD_COMM["r2"]
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r4", [NETWORK[adt][1]],
                                      input_dict_3)
        assert result is True, "Test case {} : Failed \n Error: {}". \
            format(tc_name, result)

    write_test_footer(tc_name)


def test_large_community_additive(request):
    """
    Verify that large community values" aggregation works fine.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    config_router_r1(tgen, topo, tc_name)

    config_router_r2(tgen, topo, tc_name)

    config_router_additive(tgen, topo, tc_name)

    input_dict_1 = {
        "largeCommunity": "%s %s" % (LARGE_COMM["r1"], LARGE_COMM["r2"]),
        "community": "%s %s" % (STANDARD_COMM["r1"], STANDARD_COMM["r2"])
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r4", [NETWORK[adt][0]],
                                      input_dict_1)
        assert result is True, "Test case {} : Failed \n Error: {}". \
            format(tc_name, result)

    write_test_footer(tc_name)


def test_large_community_match_as_path(request):
    """
    Matching prefixes based on attributes other than prefix list and make use
    of set clause.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    config_for_as_path(tgen, topo, tc_name)

    input_dict = {
        "largeCommunity": "%s %s" % (
            LARGE_COMM["pf_list_1"], LARGE_COMM["r2"]),
        "community": "%s %s" % (
            STANDARD_COMM["pf_list_1"], STANDARD_COMM["r2"]),
    }

    input_dict_1 = {
        "largeCommunity": "%s %s" % (
            LARGE_COMM["pf_list_2"], LARGE_COMM["r2"]),
        "community": "%s %s" % (
            STANDARD_COMM["pf_list_2"], STANDARD_COMM["r2"]),
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r5", [NETWORK[adt][0]],
                                      input_dict)
        assert result is True, "Test case {} : Failed \n Error: {}". \
            format(tc_name, result)

        result = verify_bgp_community(tgen, adt, "r5", [NETWORK[adt][1]],
                                      input_dict_1, expected=False)

        assert result is not True, "Test case {} : Should fail \n Error: {}". \
            format(tc_name, result)

    write_test_footer(tc_name)


def test_large_community_match_all(request):
    """
    Verify community and large-community list operations in route-map with all
    clause (exact, all, any, regex) works.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    config_router_r1(tgen, topo, tc_name)

    config_router_r2(tgen, topo, tc_name)

    config_router_additive(tgen, topo, tc_name)

    input_dict_1 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "1:1:1",
                    "large": True
                },
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ALL",
                    "value": "1:1:1 1:2:1 1:3:1 1:4:1 1:5:1 2:1:1 2:2:1",
                    "large": True
                },
                {
                    "community_type": "expanded",
                    "action": "permit",
                    "name": "EXP_ALL",
                    "value": "1:1:1 1:2:1 1:3:1 1:4:1 1:5:1 2:[1-5]:1",
                    "large": True
                }
            ]
        }
    }

    step("Create bgp community lists for ANY, EXACT and EXP_ALL match")

    result = create_bgp_community_lists(tgen, input_dict_1)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    input_dict_2 = {
        "r4": {
            "route_maps": {
                "LC4": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {"large-community-list": {"id": "ANY"}}
                    },
                    {
                        "action": "permit",
                        "seq_id": "20",
                        "match": {"large-community-list": {"id": "EXACT"}}
                    },
                    {
                        "action": "permit",
                        "seq_id": "30",
                        "match": {"large-community-list": {"id": "EXP_ALL"}}
                    }
                ]
            }
        }
    }

    step("Applying bgp community lits on LC4 route-map")
    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    input_dict_3 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r5": {
                                    "dest_link": {
                                        "r4-link1": {
                                            "route_maps": [{
                                                "name": "LC4",
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
                                "r5": {
                                    "dest_link": {
                                        "r4-link1": {
                                            "route_maps": [{
                                                "name": "LC4",
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

    step("Apply route-mpa LC4 on r4 for r2 neighbor, direction 'in'")

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    input_dict_4 = {
        "largeCommunity": "1:1:1 1:2:1 1:3:1 1:4:1 1:5:1 2:1:1 2:2:1 2:3:1 "
                          "2:4:1 2:5:1"
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r4", [NETWORK[adt][0]],
                                      input_dict_4)
        assert result is True, "Test case {} : Should fail \n Error: {}". \
            format(tc_name, result)

    write_test_footer(tc_name)


#@pytest.mark.skip(reason="as-set not working for ipv6")
def test_large_community_aggregate_network(request):
    """
    Restart router and check if large community and community
    attributes are getting re-populated.
    """

    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)

    config_for_as_path(tgen, topo, tc_name)

    input_dict = {
        "community": STANDARD_COMM["agg_1"],
        "largeCommunity": LARGE_COMM["agg_1"]
    }

    input_dict_1 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "aggregate_address": [
                                {
                                    "network": "%s/%s" % (
                                        NETWORK["ipv4"][2], NET_MASK["ipv4"]),
                                    "as_set": True
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "aggregate_address": [
                                {
                                    "network": "%s/%s" % (
                                        NETWORK["ipv6"][2], NET_MASK["ipv6"]),
                                    "as_set": True
                                }
                            ]
                        }
                    }
                }
            }
        }
    }

    step("Configuring aggregate address as-set on r2")
    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Test case {} : Failed \n Error: {}".format(
        tc_name, result)

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r4",
                                      ["%s/%s" % (NETWORK[adt][2],
                                                  NET_MASK[adt])],
                                      input_dict)
        assert result is True, "Test case {} : Failed \n Error: {}". \
            format(tc_name, result)

    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "%s/%s" % (
                                        NETWORK["ipv4"][0], MASK["ipv4"]),
                                    "no_of_network": 1,
                                    "delete": True
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "%s/%s" % (
                                        NETWORK["ipv6"][0], MASK["ipv6"]),
                                    "no_of_network": 1,
                                    "delete": True
                                }
                            ]
                        }
                    }
                }
            }
        }
    }

    step("Stop advertising one of the networks")
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Test case {} : Failed \n Error: {}".format(
        tc_name, result)

    input_dict_3 = {
        "community": STANDARD_COMM["agg_2"],
        "largeCommunity": LARGE_COMM["agg_2"]
    }

    for adt in ADDR_TYPES:
        step("Verifying bgp community values on r5 is also modified")
        result = verify_bgp_community(tgen, adt, "r4",
                                      ["%s/%s" % (NETWORK[adt][2],
                                                  NET_MASK[adt])],
                                      input_dict_3)
        assert result is True, "Test case {} : Failed \n Error: {}". \
            format(tc_name, result)

    write_test_footer(tc_name)


def test_large_community_boundary_values(request):
    """
    Verify that any value in BGP Large communities for boundary values.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    input_dict = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "0:-1"
                }
            ]
        }
    }

    step("Checking boundary value for community 0:-1")
    result = create_bgp_community_lists(tgen, input_dict)
    assert result is not True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    step("Checking community attribute 0:65536")
    input_dict_2 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "0:65536"
                }
            ]
        }
    }

    step("Checking boundary value for community 0:65536")
    result = create_bgp_community_lists(tgen, input_dict_2)
    assert result is not True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)

    step("Checking boundary value for community 0:4294967296")
    input_dict_3 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "0:4294967296",
                    "large": True
                }
            ]
        }
    }

    result = create_bgp_community_lists(tgen, input_dict_3)
    assert result is not True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)
    step("Checking boundary value for community 0:-1:1")

    input_dict_4 = {
        "r4": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "ANY",
                    "value": "0:-1:1",
                    "large": True
                }
            ]
        }
    }

    result = create_bgp_community_lists(tgen, input_dict_4)
    assert result is not True, "Test case {} : Failed \n Error: {}". \
        format(tc_name, result)


def test_large_community_after_clear_bgp(request):
    """
    Clear BGP neighbor-ship and check if large community and community
    attributes are getting re-populated.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    config_router_r1(tgen, topo, tc_name)

    input_dict = {
        "largeCommunity": LARGE_COMM["r1"],
        "community": STANDARD_COMM["r1"]
    }

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r2", [NETWORK[adt][0]],
                                      input_dict)
        assert result is True, "Test case {} : Failed \n Error: {}". \
            format(tc_name, result)

    step("Clearing BGP on r1")
    clear_bgp_and_verify(tgen, topo, "r1")

    for adt in ADDR_TYPES:
        result = verify_bgp_community(tgen, adt, "r2", [NETWORK[adt][0]],
                                      input_dict)
        assert result is True, "Test case {} : Failed \n Error: {}". \
            format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
