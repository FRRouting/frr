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
- Test modify prefix-list action
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
    step,
    create_route_maps,
    check_router_status,
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, create_router_bgp, clear_bgp

from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd]


# Global variables
bgp_convergence = False

IPV4_PF3 = "192.168.0.0/18"
IPV4_PF4 = "192.150.10.0/24"
IPV4_PF5 = "192.168.10.1/32"
IPV4_PF6 = "192.168.10.10/32"
IPV4_PF7 = "192.168.10.0/24"


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


def test_bug_prefix_lists_deny_to_permit_p1(request):
    """
    Verify modification of prefix-list action
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    # base config
    step("Configure IPV4  and IPv6 IBGP and EBGP session as mentioned in setup")
    step("Configure static routes on R2 with Null 0 nexthop")
    input_dict_1 = {
        "r2": {
            "static_routes": [
                {"network": IPV4_PF7, "no_of_ip": 1, "next_hop": "Null0"},
                {"network": IPV4_PF6, "no_of_ip": 1, "next_hop": "Null0"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Advertise static route in BGP using redistribute static command")
    input_dict_4 = {
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
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "All the static route advertised in R4 as BGP "
        "routes verify using 'show ip  bgp'and 'show bgp'"
    )
    dut = "r4"
    protocol = "bgp"

    input_dict_route = {
        "r4": {"static_routes": [{"network": IPV4_PF7}, {"network": IPV4_PF6}]}
    }

    result = verify_rib(tgen, "ipv4", dut, input_dict_route)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure IPv4 and IPv6 prefix-list")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {"seqid": "5", "network": IPV4_PF7, "action": "deny"}
                    ],
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {"seqid": "10", "network": IPV4_PF7, "action": "permit"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "configure route-map seq to permit IPV4 prefix list and seq"
        "2 to permit IPV6 prefix list and apply it to out direction on R3"
    )

    input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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
                                                    "name": "rmap_match_pf_1",
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
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_7)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on R4 should not have any IPv4 and IPv6 BGP routes using "
        "show ip bgp show bgp"
    )

    dut = "r4"
    protocol = "bgp"

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_route, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n" "Error : Routes are still present \n {}".format(
        tc_name, result
    )

    step("Modify IPv4/IPv6 prefix-list sequence 5 to another value on R3")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {"seqid": "5", "network": IPV4_PF4, "action": "deny"}
                    ],
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify  /24 and /120 routes present on"
        "R4 BGP table using show ip bgp show bgp"
    )
    input_dict = {"r4": {"static_routes": [{"network": IPV4_PF7}]}}

    dut = "r4"
    protocol = "bgp"

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change prefix-list to same as original on R3")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {"seqid": "5", "network": IPV4_PF7, "action": "deny"}
                    ],
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify  /24 and /120 routes removed on"
        "R4 BGP table using show ip bgp show bgp"
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n" "Error : Routes are still present \n {}".format(
        tc_name, result
    )

    step("Modify IPv4/IPv6 prefix-list sequence 5 to another value")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {"seqid": "5", "network": IPV4_PF4, "action": "deny"}
                    ],
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Clear BGP on R3 and verify the routes")
    clear_bgp(tgen, "ipv4", "r3")

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("On R3 add prefix-list permit any for IPv4 and IPv6 seq 15")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {"seqid": "15", "network": "any", "action": "permit"}
                    ],
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify /24 and /32 /120 and /128 routes are present on R4")
    result = verify_rib(tgen, "ipv4", dut, input_dict_route)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
