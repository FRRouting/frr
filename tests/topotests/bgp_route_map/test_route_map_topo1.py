#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

import sys
import time
import pytest
import os

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

# Required to instantiate the topology builder class.
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    verify_rib,
    create_route_maps,
    create_static_routes,
    create_prefix_lists,
    check_address_types,
    reset_config_on_routers,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_attributes,
)
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


#################################
# TOPOLOGY
#################################
"""

                    +-------+
           +------- |  R2   |
          |         +-------+
         |               |
     +-------+           |
     |  R1   |           |
     +-------+           |
        |                |
        |           +-------+          +-------+
        +---------- |  R3   |----------|  R4   |
                    +-------+          +-------+

"""

#################################
# TEST SUMMARY
#################################
"""
Following tests are covered to test route-map functionality:
TC_34:
    Verify if route-maps is applied in both inbound and
    outbound direction to same neighbor/interface.
TC_36:
    Test permit/deny statements operation in route-maps with a
    permutation and combination of permit/deny in prefix-lists
TC_35:
    Test multiple sequence numbers in a single route-map for different
    match/set clauses.
TC_37:
    Test add/remove route-maps with multiple set
    clauses and without any match statement.(Set only)
TC_38:
    Test add/remove route-maps with multiple match
    clauses and without any set statement.(Match only)
"""

# Global variables
bgp_convergence = False
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()

# Global variables
bgp_convergence = False
NETWORK = {"ipv4": ["11.0.20.1/32", "20.0.20.1/32"], "ipv6": ["1::1/128", "2::1/128"]}
MASK = {"ipv4": "32", "ipv6": "128"}
NEXT_HOP = {"ipv4": "10.0.0.2", "ipv6": "fd00::2"}
ADDR_TYPES = check_address_types()


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
    json_file = "{}/bgp_route_map_topo1.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Checking BGP convergence
    global bgp_convergence

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "setup_module :Failed \n Error:" " {}".format(
        bgp_convergence
    )

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

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


def test_route_map_inbound_outbound_same_neighbor_p0(request):
    """
    TC_34:
    Verify if route-maps is applied in both inbound and
    outbound direction to same neighbor/interface.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    for adt in ADDR_TYPES:

        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[adt][0],
                        "no_of_ip": 9,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Api call to redistribute static routes
        input_dict_1 = {
            "r1": {
                "bgp": {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"},
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"},
                                ]
                            }
                        },
                    },
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_2 = {
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK[adt][1],
                        "no_of_ip": 9,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Api call to redistribute static routes
        input_dict_5 = {
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
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"},
                                ]
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_5)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_2 = {
            "r3": {
                "prefix_lists": {
                    "ipv4": {
                        "pf_list_1_ipv4": [
                            {
                                "seqid": 10,
                                "action": "permit",
                                "network": NETWORK["ipv4"][0],
                            }
                        ],
                        "pf_list_2_ipv4": [
                            {
                                "seqid": 10,
                                "action": "permit",
                                "network": NETWORK["ipv4"][1],
                            }
                        ],
                    },
                    "ipv6": {
                        "pf_list_1_ipv6": [
                            {
                                "seqid": 100,
                                "action": "permit",
                                "network": NETWORK["ipv6"][0],
                            }
                        ],
                        "pf_list_2_ipv6": [
                            {
                                "seqid": 100,
                                "action": "permit",
                                "network": NETWORK["ipv6"][1],
                            }
                        ],
                    },
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        for addr_type in ADDR_TYPES:
            input_dict_6 = {
                "r3": {
                    "route_maps": {
                        "rmap_match_tag_1_{}".format(addr_type): [
                            {
                                "action": "deny",
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                                    }
                                },
                            }
                        ],
                        "rmap_match_tag_2_{}".format(addr_type): [
                            {
                                "action": "permit",
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_2_{}".format(addr_type)
                                    }
                                },
                            }
                        ],
                    }
                }
            }
            result = create_route_maps(tgen, input_dict_6)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        # Configure neighbor for route map
        input_dict_7 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r4": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_tag_1_ipv4",
                                                        "direction": "in",
                                                    },
                                                    {
                                                        "name": "rmap_match_tag_1_ipv4",
                                                        "direction": "out",
                                                    },
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
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_tag_1_ipv6",
                                                        "direction": "in",
                                                    },
                                                    {
                                                        "name": "rmap_match_tag_1_ipv6",
                                                        "direction": "out",
                                                    },
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for adt in ADDR_TYPES:
        # Verifying RIB routes
        dut = "r3"
        protocol = "bgp"
        input_dict_2 = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK[adt][1]],
                        "no_of_ip": 9,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }

        result = verify_rib(
            tgen, adt, dut, input_dict_2, protocol=protocol, expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

        # Verifying RIB routes
        dut = "r4"
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK[adt][0]],
                        "no_of_ip": 9,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }
        result = verify_rib(
            tgen, adt, dut, input_dict, protocol=protocol, expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} FIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    write_test_footer(tc_name)


@pytest.mark.parametrize(
    "prefix_action, rmap_action",
    [("permit", "permit"), ("permit", "deny"), ("deny", "permit"), ("deny", "deny")],
)
def test_route_map_with_action_values_combination_of_prefix_action_p0(
    request, prefix_action, rmap_action
):
    """
    TC_36:
    Test permit/deny statements operation in route-maps with a permutation and
    combination of permit/deny in prefix-lists
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    for adt in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[adt][0],
                        "no_of_ip": 9,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Api call to redistribute static routes
        input_dict_1 = {
            "r1": {
                "bgp": {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"},
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"},
                                ]
                            }
                        },
                    },
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Permit in perfix list and route-map
        input_dict_2 = {
            "r3": {
                "prefix_lists": {
                    "ipv4": {
                        "pf_list_1_ipv4": [
                            {"seqid": 10, "network": "any", "action": prefix_action}
                        ]
                    },
                    "ipv6": {
                        "pf_list_1_ipv6": [
                            {"seqid": 100, "network": "any", "action": prefix_action}
                        ]
                    },
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        for addr_type in ADDR_TYPES:
            input_dict_3 = {
                "r3": {
                    "route_maps": {
                        "rmap_match_pf_1_{}".format(addr_type): [
                            {
                                "action": rmap_action,
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                                    }
                                },
                            }
                        ]
                    }
                }
            }
            result = create_route_maps(tgen, input_dict_3)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        # Configure neighbor for route map
        input_dict_7 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_ipv4",
                                                        "direction": "in",
                                                    }
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
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        dut = "r3"
        protocol = "bgp"
        input_dict_2 = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK[adt][0]],
                        "no_of_ip": 9,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }

        # tgen.mininet_cli()
        if "deny" in [prefix_action, rmap_action]:
            result = verify_rib(
                tgen, adt, dut, input_dict_2, protocol=protocol, expected=False
            )
            assert result is not True, (
                "Testcase {} : Failed \n "
                "Expected: Routes should not be present in {} FIB \n "
                "Found: {}".format(tc_name, dut, result)
            )
        else:
            result = verify_rib(tgen, adt, dut, input_dict_2, protocol=protocol)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )


def test_route_map_multiple_seq_different_match_set_clause_p0(request):
    """
    TC_35:
    Test multiple sequence numbers in a single route-map for different
    match/set clauses.
    """

    tgen = get_topogen()
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    for adt in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[adt][0],
                        "no_of_ip": 1,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

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
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"},
                                ]
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create ip prefix list
        input_dict_2 = {
            "r3": {
                "prefix_lists": {
                    "ipv4": {
                        "pf_list_1_ipv4": [
                            {"seqid": 10, "network": "any", "action": "permit"}
                        ]
                    },
                    "ipv6": {
                        "pf_list_1_ipv6": [
                            {"seqid": 100, "network": "any", "action": "permit"}
                        ]
                    },
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        for addr_type in ADDR_TYPES:
            input_dict_3 = {
                "r3": {
                    "route_maps": {
                        "rmap_match_pf_1_{}".format(addr_type): [
                            {
                                "action": "permit",
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_2_{}".format(addr_type)
                                    }
                                },
                                "set": {"path": {"as_num": 500}},
                            },
                            {
                                "action": "permit",
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_2_{}".format(addr_type)
                                    }
                                },
                                "set": {
                                    "locPrf": 150,
                                },
                            },
                            {
                                "action": "permit",
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                                    }
                                },
                                "set": {"metric": 50},
                            },
                        ]
                    }
                }
            }
            result = create_route_maps(tgen, input_dict_3)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        # Configure neighbor for route map
        input_dict_4 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r4": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r4": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for adt in ADDR_TYPES:
        # Verifying RIB routes
        dut = "r3"
        protocol = "bgp"
        input_dict = {
            "r3": {
                "route_maps": {
                    "rmap_match_pf_list1": [
                        {
                            "set": {
                                "metric": 50,
                            }
                        }
                    ],
                }
            }
        }

        static_routes = [NETWORK[adt][0]]

        time.sleep(2)
        result = verify_bgp_attributes(
            tgen, adt, dut, static_routes, "rmap_match_pf_list1", input_dict
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        dut = "r4"
        result = verify_bgp_attributes(
            tgen, adt, dut, static_routes, "rmap_match_pf_list1", input_dict
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        logger.info("Testcase " + tc_name + " :Passed \n")

        # Uncomment next line for debugging
        # tgen.mininet_cli()


def test_route_map_set_only_no_match_p0(request):
    """
    TC_37:
    Test add/remove route-maps with multiple set
    clauses and without any match statement.(Set only)
    """

    tgen = get_topogen()
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    for adt in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[adt][0],
                        "no_of_ip": 1,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

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
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"},
                                ]
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        input_dict_3 = {
            "r3": {
                "route_maps": {
                    "rmap_match_pf_1": [
                        {
                            "action": "permit",
                            "set": {"metric": 50, "locPrf": 150, "weight": 4000},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Configure neighbor for route map
        input_dict_4 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r4": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r4": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    time.sleep(2)
    for adt in ADDR_TYPES:
        input_dict_4 = {
            "r3": {
                "route_maps": {
                    "rmap_match_pf_1": [
                        {
                            "action": "permit",
                            "set": {
                                "metric": 50,
                            },
                        }
                    ]
                }
            }
        }
        # Verifying RIB routes
        static_routes = [NETWORK[adt][0]]
        result = verify_bgp_attributes(
            tgen, adt, "r3", static_routes, "rmap_match_pf_1", input_dict_3
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_attributes(
            tgen, adt, "r4", static_routes, "rmap_match_pf_1", input_dict_4
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        logger.info("Testcase " + tc_name + " :Passed \n")

        # Uncomment next line for debugging
        # tgen.mininet_cli()


def test_route_map_match_only_no_set_p0(request):
    """
    TC_38:
    Test add/remove route-maps with multiple match
    clauses and without any set statement.(Match only)
    """

    tgen = get_topogen()
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    for adt in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[adt][0],
                        "no_of_ip": 1,
                        "next_hop": NEXT_HOP[adt],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

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
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"},
                                ]
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create ip prefix list
        input_dict_2 = {
            "r1": {
                "prefix_lists": {
                    "ipv4": {
                        "pf_list_1_ipv4": [
                            {"seqid": 10, "network": "any", "action": "permit"}
                        ]
                    },
                    "ipv6": {
                        "pf_list_1_ipv6": [
                            {"seqid": 100, "network": "any", "action": "permit"}
                        ]
                    },
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        for addr_type in ADDR_TYPES:
            input_dict_3 = {
                "r1": {
                    "route_maps": {
                        "rmap_match_pf_1_{}".format(addr_type): [
                            {
                                "action": "permit",
                                "set": {
                                    "metric": 50,
                                    "locPrf": 150,
                                },
                            }
                        ]
                    }
                }
            }
            result = create_route_maps(tgen, input_dict_3)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        # Configure neighbor for route map
        input_dict_4 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_ipv4",
                                                        "direction": "out",
                                                    }
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
                                    "r3": {
                                        "dest_link": {
                                            "r1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create ip prefix list
        input_dict_5 = {
            "r3": {
                "prefix_lists": {
                    "ipv4": {
                        "pf_list_1_ipv4": [
                            {"seqid": 10, "network": "any", "action": "permit"}
                        ]
                    },
                    "ipv6": {
                        "pf_list_1_ipv6": [
                            {"seqid": 100, "network": "any", "action": "permit"}
                        ]
                    },
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_5)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        for addr_type in ADDR_TYPES:
            input_dict_6 = {
                "r3": {
                    "route_maps": {
                        "rmap_match_pf_2_{}".format(addr_type): [
                            {
                                "action": "permit",
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                                    }
                                },
                            }
                        ]
                    }
                }
            }
            result = create_route_maps(tgen, input_dict_6)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        # Configure neighbor for route map
        input_dict_7 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_2_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r4": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_2_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_2_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r4": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_2_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for adt in ADDR_TYPES:
        # Verifying RIB routes
        static_routes = [NETWORK[adt][0]]
        result = verify_bgp_attributes(
            tgen, adt, "r3", static_routes, "rmap_match_pf_1", input_dict_3
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
