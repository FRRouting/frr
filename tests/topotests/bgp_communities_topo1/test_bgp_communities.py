#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test bgp community functionality:
- Verify routes are not advertised when NO-ADVERTISE Community is applied

"""

import os
import sys
import time
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
    check_address_types,
    step,
    create_route_maps,
    create_prefix_lists,
    create_route_maps,
    required_linux_kernel_version,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
)
from lib.topojson import build_config_from_json
from copy import deepcopy

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


# Global variables
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()
NETWORK = {"ipv4": "2.2.2.2/32", "ipv6": "22:22::2/128"}
NEXT_HOP_IP = {}


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >= 4.15")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_communities.json".format(CWD)
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
    global ADDR_TYPES

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


def test_bgp_no_advertise_community_p0(request):
    """
    Verify routes are not advertised when NO-ADVERTISE Community is applied

    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    reset_config_on_routers(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    NEXT_HOP_IP = {
        "ipv4": topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0],
        "ipv6": topo["routers"]["r0"]["links"]["r1"]["ipv6"].split("/")[0],
    }

    # configure static routes
    dut = "r3"
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static and connected in Router BGP " "in R1")

        input_dict_2 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "BGP neighbors are up, static and connected route advertised from"
            " R1 are present on R2 BGP table and RIB using show ip bgp and "
            " show ip route"
        )
        step(
            "Static and connected route advertised from R1 are present on R3"
            " BGP table and RIB using show ip bgp and show ip route"
        )

        dut = "r3"
        protocol = "bgp"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Configure prefix list P1 on R2 to permit route coming from R1")
        # Create ip prefix list
        input_dict_2 = {
            "r2": {
                "prefix_lists": {
                    addr_type: {
                        "pf_list_1_{}".format(addr_type): [
                            {"seqid": 10, "network": "any", "action": "permit"}
                        ]
                    }
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        input_dict_3 = {
            "r2": {
                "route_maps": {
                    "rmap_match_pf_1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": "5",
                            "match": {
                                addr_type: {"prefix_lists": "pf_list_1_" + addr_type}
                            },
                            "set": {"community": {"num": "no-advertise"}},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        step(
            "Apply route-map RM1 on R2, R2 to R3 BGP neighbor with no"
            " advertise community"
        )
        # Configure neighbor for route map
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_"
                                                        + addr_type,
                                                        "direction": "in",
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
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "After advertising no advertise community to BGP neighbor "
            "static and connected router got removed from R3 verify using "
            "show ip bgp & show ip route"
        )

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n Expected: "
            "Routes still present in {} router. Found: {}".format(tc_name, dut, result)
        )

        result = verify_rib(
            tgen, addr_type, dut, input_dict, protocol=protocol, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n  Expected: Routes still present in {} router. Found: {}".format(
            tc_name, dut, result
        )

        step("Remove and Add no advertise community")
        # Configure neighbor for route map
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_"
                                                        + addr_type,
                                                        "direction": "in",
                                                        "delete": True,
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
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "After removing no advertise community from BGP neighbor "
            "static and connected router got advertised to R3 and "
            "removing route-map, verify route using show ip bgp"
            " and show ip route"
        )

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict)
        assert (
            result is True
        ), "Testcase {} : Failed \n  Routes still present in R3 router. Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n  Routes still present in R3 router. Error: {}".format(
            tc_name, result
        )

    step("Repeat above steps when IBGP nbr configured between R1, R2 & R2, R3")
    topo1 = deepcopy(topo)

    topo1["routers"]["r1"]["bgp"]["local_as"] = "100"
    topo1["routers"]["r2"]["bgp"]["local_as"] = "100"
    topo1["routers"]["r3"]["bgp"]["local_as"] = "100"

    for rtr in ["r1", "r2", "r3"]:
        if "bgp" in topo1["routers"][rtr].keys():
            delete_bgp = {rtr: {"bgp": {"delete": True}}}
            result = create_router_bgp(tgen, topo1, delete_bgp)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
            config_bgp = {
                rtr: {"bgp": {"local_as": topo1["routers"][rtr]["bgp"]["local_as"]}}
            }
            result = create_router_bgp(tgen, topo1, config_bgp)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    build_config_from_json(tgen, topo1, save_bkup=False)

    step("verify bgp convergence before starting test case")

    bgp_convergence = verify_bgp_convergence(tgen, topo1)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    # configure static routes
    dut = "r3"
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static and connected in Router " "BGP in R1")

        input_dict_2 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "BGP neighbors are up, static and connected route advertised from"
            " R1 are present on R2 BGP table and RIB using show ip bgp and "
            " show ip route"
        )
        step(
            "Static and connected route advertised from R1 are present on R3"
            " BGP table and RIB using show ip bgp and show ip route"
        )

        dut = "r2"
        protocol = "bgp"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Configure prefix list P1 on R2 to permit route coming from R1")
        # Create ip prefix list
        input_dict_2 = {
            "r2": {
                "prefix_lists": {
                    addr_type: {
                        "pf_list_1_{}".format(addr_type): [
                            {"seqid": 10, "network": "any", "action": "permit"}
                        ]
                    }
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        input_dict_3 = {
            "r2": {
                "route_maps": {
                    "rmap_match_pf_1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": "5",
                            "match": {
                                addr_type: {"prefix_lists": "pf_list_1_" + addr_type}
                            },
                            "set": {"community": {"num": "no-advertise"}},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        step(
            "Apply route-map RM1 on R2, R2 to R3 BGP neighbor with no"
            " advertise community"
        )

        # Configure neighbor for route map
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_"
                                                        + addr_type,
                                                        "direction": "in",
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
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "After advertising no advertise community to BGP neighbor "
            "static and connected router got removed from R3 verify using "
            "show ip bgp & show ip route"
        )

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict)
        assert (
            result is True
        ), "Testcase {} : Failed \n  Routes still present in R3 router. Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n  Routes still present in R3 router. Error: {}".format(
            tc_name, result
        )

        step("Remove and Add no advertise community")
        # Configure neighbor for route map
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_pf_1_"
                                                        + addr_type,
                                                        "direction": "in",
                                                        "delete": True,
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
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "After removing no advertise community from BGP neighbor "
            "static and connected router got advertised to R3 and "
            "removing route verify using show ip bgp and "
            " show ip route"
        )

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict)
        assert (
            result is True
        ), "Testcase {} : Failed \n  Routes still present in R3 router. Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n  Routes still present in R3 router. Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
