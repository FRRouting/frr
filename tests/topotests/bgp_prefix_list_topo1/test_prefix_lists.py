#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test prefix-list functionality:

Test steps
- Create topology (setup module)
  Creating 4 routers topology, r1, r2, r3 are in IBGP and
  r3, r4 are in EBGP
- Bring up topology
- Verify for bgp to converge

IP prefix-list tests
- Test ip prefix-lists IN permit
- Test ip prefix-lists OUT permit
- Test ip prefix-lists IN deny and permit any
- Test delete ip prefix-lists
- Test ip prefix-lists OUT deny and permit any
- Test modify ip prefix-lists IN permit to deny
- Test modify ip prefix-lists IN deny to permit
- Test modify ip prefix-lists OUT permit to deny
- Test modify prefix-lists OUT deny to permit
- Test ip prefix-lists implicit deny
"""

import sys
import time
import os
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

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
    create_prefix_lists,
    verify_prefix_lists,
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, create_router_bgp, clear_bgp_and_verify
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd]


# Global variables
bgp_convergence = False


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
    json_file = "{}/prefix_lists.json".format(CWD)
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
    global BGP_CONVERGENCE

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error:" " {}".format(
        BGP_CONVERGENCE
    )

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

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#   Tests starting
#
#####################################################


def test_ip_prefix_lists_in_permit(request):
    """
    Create ip prefix list and test permit prefixes IN direction
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Create Static routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "20.0.20.1/32", "no_of_ip": 1, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [{"seqid": 10, "network": "any", "action": "permit"}]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure bgp neighbor with prefix list
    input_dict_3 = {
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
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "prefix_lists": [
                                                {"name": "pf_list_1", "direction": "in"}
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ip_prefix_lists_out_permit(request):
    """
    Create ip prefix list and test permit prefixes out direction
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create Static routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "10.0.20.1/32", "no_of_ip": 1, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create Static routes
    input_dict_1 = {
        "r1": {
            "static_routes": [
                {"network": "20.0.20.1/32", "no_of_ip": 1, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_5 = {
        "r3": {
            "static_routes": [
                {"network": "10.0.0.2/30", "no_of_ip": 1, "next_hop": "10.0.0.9"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes

    # Create ip prefix list
    input_dict_2 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {"seqid": 10, "network": "20.0.20.1/32", "action": "permit"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure prefix list to bgp neighbor
    # Configure bgp neighbor with prefix list
    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {
                                            "prefix_lists": [
                                                {
                                                    "name": "pf_list_1",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            },
                            "redistribute": [
                                {"redist_type": "static"},
                                {"redist_type": "connected"},
                            ],
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict_1, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} FIB \n "
        "Found: {}".format(tc_name, dut, result)
    )

    write_test_footer(tc_name)


def test_ip_prefix_lists_in_deny_and_permit_any(request):
    """
    Create ip prefix list and test permit/deny prefixes IN direction
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create Static Routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "10.0.20.1/32", "no_of_ip": 1, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes
    # Create ip prefix list
    input_dict_2 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {"seqid": "10", "network": "10.0.20.1/32", "action": "deny"},
                        {"seqid": "11", "network": "any", "action": "permit"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure bgp neighbor with prefix list
    input_dict_3 = {
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
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "prefix_lists": [
                                                {"name": "pf_list_1", "direction": "in"}
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    # Configure prefix list to bgp neighbor
    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} BGP RIB \n "
        "Found: {}".format(tc_name, dut, result)
    )

    write_test_footer(tc_name)


def test_delete_prefix_lists(request):
    """
    Delete ip prefix list
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {"seqid": "10", "network": "10.0.20.1/32", "action": "deny"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_prefix_lists(tgen, input_dict_2)
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    # Delete prefix list
    input_dict_2 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.20.1/32",
                            "action": "deny",
                            "delete": True,
                        }
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ip_prefix_lists_out_deny_and_permit_any(request):
    """
    Create ip prefix list and test deny/permit any prefixes OUT direction
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create Static Routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "10.0.20.1/32", "no_of_ip": 9, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create Static Routes
    input_dict_1 = {
        "r2": {
            "static_routes": [
                {"network": "20.0.20.1/32", "no_of_ip": 9, "next_hop": "10.0.0.1"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes

    # Create ip prefix list
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "deny",
                        },
                        {"seqid": "11", "network": "any", "action": "permit"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_4 = {
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
        },
        "r2": {
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
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "prefix_lists": [
                                                {
                                                    "name": "pf_list_1",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r4"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict_1, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r4"
    protocol = "bgp"
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} BGP RIB \n "
        "Found: {}".format(tc_name, dut, result)
    )

    write_test_footer(tc_name)


def test_modify_prefix_lists_in_permit_to_deny(request):
    """
    Modify ip prefix list and test permit to deny prefixes IN direction
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create Static Routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "10.0.20.1/32", "no_of_ip": 9, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes

    # Create ip prefix list
    input_dict_2 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "permit",
                        }
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_3 = {
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
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "prefix_lists": [
                                                {"name": "pf_list_1", "direction": "in"}
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Modify prefix list
    input_dict_1 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "deny",
                        },
                        {"seqid": "11", "network": "any", "action": "permit"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = "r3"
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} BGP RIB \n "
        "Found: {}".format(tc_name, dut, result)
    )

    write_test_footer(tc_name)


def test_modify_prefix_lists_in_deny_to_permit(request):
    """
    Modify ip prefix list and test deny to permit prefixes IN direction
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create Static Routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "10.0.20.1/32", "no_of_ip": 9, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes

    # Create ip prefix list
    input_dict_1 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "deny",
                        },
                        {"seqid": "11", "network": "any", "action": "permit"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_2 = {
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
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "prefix_lists": [
                                                {"name": "pf_list_1", "direction": "in"}
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} BGP RIB \n "
        "Found: {}".format(tc_name, dut, result)
    )

    # Modify  ip prefix list
    input_dict_1 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "permit",
                        }
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = "r3"
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_modify_prefix_lists_out_permit_to_deny(request):
    """
    Modify ip prefix list and test permit to deny prefixes OUT direction
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create Static Routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "10.0.20.1/32", "no_of_ip": 9, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes

    # Create ip prefix list
    input_dict_1 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "permit",
                        }
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_2 = {
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
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "prefix_lists": [
                                                {
                                                    "name": "pf_list_1",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r4"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Modify ip prefix list
    input_dict_1 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "deny",
                        },
                        {"seqid": "11", "network": "any", "action": "permit"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = "r3"
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r4"
    protocol = "bgp"
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} BGP RIB \n "
        "Found: {}".format(tc_name, dut, result)
    )

    write_test_footer(tc_name)


def test_modify_prefix_lists_out_deny_to_permit(request):
    """
    Modify ip prefix list and test deny to permit prefixes OUT direction
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create Static Routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "10.0.20.1/32", "no_of_ip": 9, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes
    # Create ip prefix list
    input_dict_1 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "deny",
                        },
                        {"seqid": "11", "network": "any", "action": "permit"},
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_2 = {
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
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "prefix_lists": [
                                                {
                                                    "name": "pf_list_1",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r4"
    protocol = "bgp"
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} BGP RIB \n "
        "Found: {}".format(tc_name, dut, result)
    )

    # Modify ip prefix list
    input_dict_1 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "permit",
                        }
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = "r3"
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r4"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ip_prefix_lists_implicit_deny(request):
    """
    Create ip prefix list and test implicit deny
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Create Static Routes
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "10.0.20.1/32", "no_of_ip": 9, "next_hop": "10.0.0.2"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create Static Routes
    input_dict_1 = {
        "r2": {
            "static_routes": [
                {"network": "20.0.20.1/32", "no_of_ip": 9, "next_hop": "10.0.0.1"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes
    # Create ip prefix list
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": "10",
                            "network": "10.0.0.0/8",
                            "le": "32",
                            "action": "permit",
                        }
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_4 = {
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
        },
        "r2": {
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
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "prefix_lists": [
                                                {
                                                    "name": "pf_list_1",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r4"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r4"
    protocol = "bgp"
    result = verify_rib(
        tgen, "ipv4", dut, input_dict_1, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} BGP RIB \n "
        "Found: {}".format(tc_name, dut, result)
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
