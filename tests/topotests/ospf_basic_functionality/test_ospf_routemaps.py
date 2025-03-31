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
    create_prefix_lists,
    verify_rib,
    create_static_routes,
    step,
    create_route_maps,
    verify_prefix_lists,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.ospf import (
    verify_ospf_neighbor,
    verify_ospf_rib,
    create_router_ospf,
    redistribute_ospf,
)

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
routerids = ["100.1.1.0", "100.1.1.1", "100.1.1.2", "100.1.1.3"]

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
1. OSPF Route map - Verify OSPF route map support functionality.
2. Verify OSPF route map support functionality when route map is not
    configured at system level but configured in OSPF
3. Verify OSPF route map support functionality with set/match clauses
    /call/continue/goto in a route-map to see if it takes immediate effect.
4. Verify OSPF route map support functionality
    when route map actions are toggled.
5. Verify OSPF route map support  functionality with multiple sequence
    numbers in a single  route-map for different match/set clauses.
6. Verify OSPF route map support functionality when we add/remove route-maps
    with multiple set clauses and without any match statement.(Set only)
7.  Verify OSPF route map support functionality when we
    add/remove route-maps with multiple match clauses and without
    any set statement.(Match only)
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
    json_file = "{}/ospf_routemaps.json".format(CWD)
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


def test_ospf_routemaps_functionality_tc19_p0(request):
    """
    OSPF Route map - Verify OSPF route map support functionality.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    step("Create static routes(10.0.20.1/32 and 10.0.20.2/32) in R0")
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

    redistribute_ospf(tgen, topo, "r0", "static")

    dut = "r1"
    lsid = NETWORK["ipv4"][0].split("/")[0]
    rid = routerids[0]
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    redistribute_ospf(tgen, topo, "r0", "static", delete=True)

    step("Create prefix-list in R0 to permit 10.0.20.1/32 prefix &  deny 10.0.20.2/32")

    # Create ip prefix list
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {
                            "seqid": 10,
                            "network": NETWORK["ipv4"][0],
                            "action": "permit",
                        },
                        {"seqid": 11, "network": "any", "action": "deny"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create route map
    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure route map rmap1 and redistribute static routes to"
        " ospf using route map rmap1"
    )

    redistribute_ospf(tgen, topo, "r0", "static", route_map="rmap_ipv4")

    step("Change prefix rules to permit 10.0.20.2 and deny 10.0.20.1")
    # Create ip prefix list
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {
                            "seqid": 10,
                            "network": NETWORK["ipv4"][1],
                            "action": "permit",
                        },
                        {"seqid": 11, "network": "any", "action": "deny"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that route 10.0.20.2 is allowed and 10.0.20.1 is denied.")
    dut = "r1"
    input_dict = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv4"][1], "no_of_ip": 1, "next_hop": "Null0"}
            ]
        }
    }
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": 1, "next_hop": "Null0"}
            ]
        }
    }
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
    ), "Testcase {} : Failed \n  r1: routes are present in fib \n Error: {}".format(
        tc_name, result
    )

    step("Delete and reconfigure prefix list.")
    # Create ip prefix list
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {
                            "seqid": 10,
                            "network": NETWORK["ipv4"][1],
                            "action": "permit",
                            "delete": True,
                        },
                        {
                            "seqid": 11,
                            "network": "any",
                            "action": "deny",
                            "delete": True,
                        },
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": 5, "next_hop": "Null0"}
            ]
        }
    }
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
    ), "Testcase {} : Failed \n  r1: OSPF routes are present \n Error: {}".format(
        tc_name, result
    )

    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {
                            "seqid": 10,
                            "network": NETWORK["ipv4"][1],
                            "action": "permit",
                        },
                        {"seqid": 11, "network": "any", "action": "deny"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that route 10.0.20.2 is allowed and 10.0.20.1 is denied.")
    dut = "r1"
    input_dict = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv4"][1], "no_of_ip": 1, "next_hop": "Null0"}
            ]
        }
    }
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": 1, "next_hop": "Null0"}
            ]
        }
    }
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

    write_test_footer(tc_name)


def test_ospf_routemaps_functionality_tc20_p0(request):
    """
    OSPF route map support functionality.

    Verify OSPF route map support functionality when route map is not
    configured at system level but configured in OSPF

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    step("Create static routes(10.0.20.1/32 and 10.0.20.2/32) in R0")
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

    step("Redistribute to ospf using route map ( non existent route map)")
    redistribute_ospf(tgen, topo, "r0", "static", route_map="rmap_ipv4")

    step(
        "Verify that routes are not allowed in OSPF even tough no "
        "matching routing map is configured."
    )

    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, retry_timeout=4, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: OSPF routes are present \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        input_dict,
        protocol=protocol,
        retry_timeout=4,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n  r1: routes are still present \n Error: {}".format(
        tc_name, result
    )

    step(
        "configure the route map with the same name that is used "
        "in the ospf with deny rule."
    )

    # Create route map
    routemaps = {"r0": {"route_maps": {"rmap_ipv4": [{"action": "deny"}]}}}
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that now route map is activated & routes are denied in OSPF.")
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

    # Create route map
    routemaps = {"r0": {"route_maps": {"rmap_ipv4": [{"action": "deny"}]}}}
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that now route map is activated & routes are denied in OSPF.")
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

    step("Delete the route map.")
    # Create route map
    routemaps = {
        "r0": {"route_maps": {"rmap_ipv4": [{"action": "deny", "delete": True}]}}
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that routes are allowed in OSPF even tough "
        "no matching routing map is configured."
    )
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

    write_test_footer(tc_name)


def test_ospf_routemaps_functionality_tc21_p0(request):
    """
    OSPF route map support functionality.

    Verify OSPF route map support functionality with set/match clauses
    /call/continue/goto in a route-map to see if it takes immediate effect.

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

    redistribute_ospf(tgen, topo, "r0", "static", route_map="rmap_ipv4")

    # Create route map
    routemaps = {
        "r0": {"route_maps": {"rmap_ipv4": [{"action": "permit", "seq_id": 10}]}}
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that route is advertised to R2.")
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    # Create route map
    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [{"action": "permit", "delete": True, "seq_id": 10}]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" Configure route map with set clause (set metric)")
    # Create route map
    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [{"action": "permit", "set": {"med": 123}, "seq_id": 10}]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that configured metric is applied to ospf routes.")
    dut = "r1"
    protocol = "ospf"

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure route map with match clause (match metric) with "
        "some actions(change metric)."
    )
    # Create route map
    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "match": {"med": 123},
                        "set": {"med": 150},
                        "seq_id": 10,
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure route map with call clause")

    # Create ip prefix list
    input_dict_2 = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {"seqid": 10, "network": "any", "action": "permit"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create route map
    input_dict_3 = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                        "set": {"med": 150},
                        "call": "rmap_match_pf_2_ipv4",
                        "seq_id": 10,
                    }
                ],
                "rmap_match_pf_2_ipv4": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                        "set": {"med": 200},
                        "seq_id": 10,
                    }
                ],
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create route map
    routemaps = {"r0": {"route_maps": {"rmap_ipv4": [{"delete": True}]}}}
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure route map with continue clause")

    # Create route map
    input_dict_3 = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                        "set": {"med": 150},
                        "continue": "30",
                        "seq_id": 10,
                    },
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                        "set": {"med": 100},
                        "seq_id": 20,
                    },
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                        "set": {"med": 50},
                        "seq_id": 30,
                    },
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure route map with goto clause")
    # Create route map
    input_dict_3 = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                        "goto": "30",
                    },
                    {
                        "action": "permit",
                        "seq_id": "20",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                        "set": {"med": 100},
                    },
                    {
                        "action": "permit",
                        "seq_id": "30",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                        "set": {"med": 200},
                    },
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_routemaps_functionality_tc24_p0(request):
    """
    OSPF Route map - Multiple set clauses.

    Verify OSPF route map support functionality when we
    add/remove route-maps with multiple match clauses and without
    any set statement.(Match only)

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    step(
        "Create static routes(10.0.20.1/32) in R1 and redistribute to "
        "OSPF using route map."
    )
    # Create Static routes
    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": 1,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    redistribute_ospf(tgen, topo, "r0", "static", route_map="rmap_ipv4")

    # Create ip prefix list
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {"seqid": 10, "network": "any", "action": "permit"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that prefix-list is created in R0.")
    result = verify_prefix_lists(tgen, pfx_list)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Prefix list not  present. Error: {}".format(
        tc_name, result
    )

    # Create route map
    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that metric falls back to original metric for ospf routes.")
    dut = "r1"
    protocol = "ospf"

    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Create static routes(10.0.20.1/32) in R1 and redistribute to "
        "OSPF using route map."
    )
    # Create Static routes
    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][1],
                    "no_of_ip": 1,
                    "next_hop": "Null0",
                    "tag": 1000,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create ip prefix list
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {"seqid": 10, "network": "any", "action": "permit"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that prefix-list is created in R0.")
    result = verify_prefix_lists(tgen, pfx_list)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Prefix list not  present. Error: {}".format(
        tc_name, result
    )

    # Create route map
    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [{"action": "permit", "match": {"ipv4": {"tag": "1000"}}}]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that metric falls back to original metric for ospf routes.")
    dut = "r1"
    protocol = "ospf"

    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the match clause with tag in route map")
    # Create route map
    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"tag": "1000", "delete": True}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that metric falls back to original metric for ospf routes.")
    dut = "r1"
    protocol = "ospf"

    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the match clause with metric in route map.")

    # Create route map
    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_routemaps_functionality_tc25_p0(request):
    """
    OSPF route map support functionality.

    Verify OSPF route map support functionality
    when route map actions are toggled.

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

    ospf_red_r0 = {
        "r0": {
            "ospf": {
                "redistribute": [{"redist_type": "static", "route_map": "rmap_ipv4"}]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_red_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step("Configure route map with permit rule")
    # Create route map
    routemaps = {"r0": {"route_maps": {"rmap_ipv4": [{"action": "permit"}]}}}
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that route is advertised to R1.")
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step("Configure route map with deny rule")
    # Create route map
    routemaps = {
        "r0": {"route_maps": {"rmap_ipv4": [{"seq_id": 10, "action": "deny"}]}}
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Verify that route is not advertised to R1.")
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, expected=False)
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)


def test_ospf_routemaps_functionality_tc22_p0(request):
    """
    OSPF Route map - Multiple sequence numbers.

    Verify OSPF route map support  functionality with multiple sequence
    numbers in a single  route-map for different match/set clauses.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config as per the topology")

    reset_config_on_routers(tgen)

    step(
        "Configure route map with seq number 10 to with ip prefix"
        " permitting route 10.0.20.1/32 in R1"
    )
    step(
        "Configure route map with seq number 20 to with  ip prefix"
        "  permitting route 10.0.20.2/32 in R1"
    )

    # Create route map
    input_dict_3 = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                    },
                    {
                        "action": "permit",
                        "seq_id": "20",
                        "match": {"ipv4": {"prefix_lists": "pf_list_2_ipv4"}},
                    },
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {"seqid": 10, "network": NETWORK["ipv4"][0], "action": "permit"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_2_ipv4": [
                        {"seqid": 10, "network": NETWORK["ipv4"][1], "action": "permit"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure static routes 10.0.20.1/32 and 10.0.20.2 in R1")
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

    step("Configure redistribute static route with route map.")
    ospf_red_r0 = {
        "r0": {
            "ospf": {
                "redistribute": [{"redist_type": "static", "route_map": "rmap_ipv4"}]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_red_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": 2,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that both routes are learned in R1 and R2")
    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change route map with seq number 20 to deny.")
    # Create route map
    input_dict_3 = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "deny",
                        "seq_id": "20",
                        "match": {"ipv4": {"prefix_lists": "pf_list_2_ipv4"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify the route 10.0.20.2/32 is withdrawn and not present "
        "in the routing table of R0 and R1."
    )

    input_dict = {
        "r0": {"static_routes": [{"network": NETWORK["ipv4"][1], "next_hop": "Null0"}]}
    }

    dut = "r1"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, expected=False)
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    dut = "r2"
    protocol = "ospf"
    result = verify_ospf_rib(tgen, dut, input_dict, expected=False)
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
