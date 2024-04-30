#!/usr/bin/env python3
#
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2023 by VMware, Inc. ("VMware")
#
#
################################################################################
# Following tests are performed to validate BGP always compare MED functionality
################################################################################
"""
1. Verify the BGP always compare MED functionality in between eBGP Peers
2. Verify the BGP always compare MED functionality in between eBGP Peers with by changing different AD values
3. Verify the BGP always compare MED functionality in between eBGP Peers by changing MED values in middle routers
4. Verify that BGP Always compare MED functionality by restarting BGP, Zebra  and FRR services and clear BGP and
   shutdown BGP neighbor
5. Verify BGP always compare MED functionality by performing shut/noshut on the interfaces in between BGP neighbors
"""

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

from lib.common_config import (
    start_topology,
    write_test_header,
    create_static_routes,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    check_address_types,
    check_router_status,
    create_static_routes,
    create_prefix_lists,
    create_route_maps,
    kill_router_daemons,
    shutdown_bringup_interface,
    stop_router,
    start_router,
    delete_route_maps,
)

from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, verify_bgp_rib, create_router_bgp, clear_bgp
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Reading the data from JSON File for topology creation
topo = None

# Global variables
ADDR_TYPES = check_address_types()
NETWORK1_1 = {"ipv4": "192.168.20.1/32", "ipv6": "192:168:20::1/128"}
NETWORK1_2 = {"ipv4": "192.168.30.1/32", "ipv6": "192:168:30::1/128"}
NETWORK1_3 = {"ipv4": "192.168.40.1/32", "ipv6": "192:168:40::1/128"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}


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
    json_file = "{}/bgp_always_compare_med_topo1.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global ADDR_TYPES
    ADDR_TYPES = check_address_types()

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error: {}".format(
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


##########################################################################################################
#
#   Local API
#
##########################################################################################################


def initial_configuration(tgen, tc_name):
    """
    API to do initial set of configuration
    """

    step(
        "Configure IPv4 and IPv6, eBGP neighbors between R1,R2 and R3 routers as per base config"
    )

    step("Configure static routes in R4")
    for addr_type in ADDR_TYPES:
        input_static_r4 = {
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_static_r4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Configure redistribute static in R4")
        input_static_redist_r4 = {
            "r4": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_static_redist_r4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        # Create prefix list
        input_dict_23 = {
            "r2": {
                "prefix_lists": {
                    addr_type: {
                        "pf_ls_r2_{}".format(addr_type): [
                            {"network": NETWORK1_1[addr_type], "action": "permit"}
                        ]
                    }
                }
            },
            "r3": {
                "prefix_lists": {
                    "ipv4": {
                        "pf_ls_r3_{}".format(addr_type): [
                            {"network": NETWORK1_1[addr_type], "action": "permit"}
                        ]
                    }
                }
            },
        }
        result = create_prefix_lists(tgen, input_dict_23)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Create route map
        input_dict_23 = {
            "r2": {
                "route_maps": {
                    "RMAP_MED_R2": [
                        {
                            "action": "permit",
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_r2_{}".format(addr_type)
                                }
                            },
                            "set": {"med": 300},
                        }
                    ]
                }
            },
            "r3": {
                "route_maps": {
                    "RMAP_MED_R3": [
                        {
                            "action": "permit",
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_r3_{}".format(addr_type)
                                }
                            },
                            "set": {"med": 200},
                        }
                    ]
                }
            },
        }
        result = create_route_maps(tgen, input_dict_23)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_r2_r3 = {
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
                                                        "name": "RMAP_MED_R2",
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
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3": {
                                                "route_maps": [
                                                    {
                                                        "name": "RMAP_MED_R3",
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
        result = create_router_bgp(tgen, topo, input_dict_r2_r3)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )


##########################################################################################################
#
#   Testcases
#
##########################################################################################################


def test_verify_bgp_always_compare_med_functionality_bw_eBGP_peers_p0(request):
    """
    Verify the BGP always compare MED functionality in between eBGP Peers
    """

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)
    initial_configuration(tgen, tc_name)

    step(
        "Configure IPv4 and IPv6, eBGP neighbors between R1,R2 and R3 routers as per base config"
    )
    step(
        "Verify that IPv4 and IPv6 eBGP neighbors are configured in between routers by following "
        "commands and verify that best path chosen by lowest MED value"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'multi-path as-path relax' command at R1.")
    configure_bgp = {
        "r1": {"bgp": {"local_as": "100", "bestpath": {"aspath": "multipath-relax"}}}
    }
    result = create_router_bgp(tgen, topo, configure_bgp)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'multi-path as-path relax' command, "
        "its also chooses lowest MED to reach destination."
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh1 = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]
        nh2 = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=[nh1, nh2])
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'bgp always-compare-med' command at R1.")
    input_dict_r1 = {"r1": {"bgp": {"local_as": "100", "bgp_always_compare_med": True}}}
    result = create_router_bgp(tgen, topo, input_dict_r1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'bgp always-compare-med', its chooses lowest MED value path"
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Remove 'bgp always-compare-med' command at R1.")
    input_dict_r1 = {
        "r1": {"bgp": {"local_as": "100", "bgp_always_compare_med": False}}
    }
    result = create_router_bgp(tgen, topo, input_dict_r1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that 'bgp always-compare-med' command is removed")
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh1 = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]
        nh2 = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=[nh1, nh2])
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Remove 'multi-path as-path relax' command at R1")
    configure_bgp = {
        "r1": {
            "bgp": {
                "local_as": "100",
                "bestpath": {"aspath": "multipath-relax", "delete": True},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify route selection after removing 'multi-path as-path relax' command")
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_bgp_always_compare_med_functionality_bw_eBGP_peers_by_changing_AD_values_p0(
    request,
):
    """
    Verify the BGP always compare MED functionality in between eBGP Peers with by changing different AD values.
    """

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)
    initial_configuration(tgen, tc_name)

    step(
        "Configure IPv4 and IPv6, eBGP neighbors between R1,R2 and R3 routers as per base config"
    )
    step(
        "Verify that IPv4 and IPv6 eBGP neighbors are configured in between routers by following "
        "commands and verify that best path chosen by lowest MED value"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'bgp always-compare-med' command at R1.")
    input_dict_r1 = {"r1": {"bgp": {"local_as": "100", "bgp_always_compare_med": True}}}
    result = create_router_bgp(tgen, topo, input_dict_r1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'bgp always-compare-med', its chooses lowest MED value path"
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure AD value=100 at R2 and AD value=200 at R3 towards R1")
    input_dict_1 = {
        "r2": {
            "bgp": {
                "local_as": 200,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "distance": {"ebgp": 100, "ibgp": 100, "local": 100}
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "distance": {"ebgp": 100, "ibgp": 100, "local": 100}
                        }
                    },
                },
            }
        },
        "r3": {
            "bgp": {
                "local_as": 300,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "distance": {"ebgp": 200, "ibgp": 200, "local": 200}
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "distance": {"ebgp": 200, "ibgp": 200, "local": 200}
                        }
                    },
                },
            }
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that inspite of AD values, always lowest MED value is getting "
        "selected at destination router R1"
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_bgp_always_compare_med_functionality_bw_eBGP_peers_by_changing_MED_values_p1(
    request,
):
    """
    Verify the BGP always compare MED functionality in between eBGP Peers by changing MED values in middle routers
    """

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)
    initial_configuration(tgen, tc_name)

    step(
        "Configure IPv4 and IPv6, eBGP neighbors between R1,R2 and R3 routers as per base config"
    )
    step(
        "Verify that IPv4 and IPv6 eBGP neighbors are configured in between routers by following "
        "commands and verify that best path chosen by lowest MED value"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'multi-path as-path relax' command at R1.")
    configure_bgp = {
        "r1": {"bgp": {"local_as": "100", "bestpath": {"aspath": "multipath-relax"}}}
    }
    result = create_router_bgp(tgen, topo, configure_bgp)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'multi-path as-path relax' command, "
        "its also chooses lowest MED to reach destination."
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh1 = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]
        nh2 = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=[nh1, nh2])
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'bgp always-compare-med' command at R1.")
    input_dict_r1 = {"r1": {"bgp": {"local_as": "100", "bgp_always_compare_med": True}}}
    result = create_router_bgp(tgen, topo, input_dict_r1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'bgp always-compare-med', its chooses lowest MED value path"
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Change the MED value 150 in R2 router.")
    input_dict = {"r2": {"route_maps": ["RMAP_MED_R2"]}}
    result = delete_route_maps(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r2": {
                "route_maps": {
                    "RMAP_MED_R2": [
                        {
                            "action": "permit",
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_r2_{}".format(addr_type)
                                }
                            },
                            "set": {"med": 150},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that after changing MED, its chooses lowest MED value path")
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Change the MED value 100 in R3 router.")
    input_dict = {"r3": {"route_maps": ["RMAP_MED_R3"]}}
    result = delete_route_maps(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_dict_3 = {
            "r3": {
                "route_maps": {
                    "RMAP_MED_R3": [
                        {
                            "action": "permit",
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_r3_{}".format(addr_type)
                                }
                            },
                            "set": {"med": 100},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that after changing MED, its chooses lowest MED value path")
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_bgp_always_compare_med_functionality_by_restarting_daemons_clear_bgp_shut_neighbors_p1(
    request,
):
    """
    Verify that BGP Always compare MED functionality by restarting BGP, Zebra  and FRR services and clear BGP and shutdown BGP neighbor
    """

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)
    initial_configuration(tgen, tc_name)

    step(
        "Configure IPv4 and IPv6, eBGP neighbors between R1,R2 and R3 routers as per base config"
    )
    step(
        "Verify that IPv4 and IPv6 eBGP neighbors are configured in between routers by following "
        "commands and verify that best path chosen by lowest MED value"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'multi-path as-path relax' command at R1.")
    configure_bgp = {
        "r1": {"bgp": {"local_as": "100", "bestpath": {"aspath": "multipath-relax"}}}
    }
    result = create_router_bgp(tgen, topo, configure_bgp)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'multi-path as-path relax' command, "
        "its also chooses lowest MED to reach destination."
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh1 = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]
        nh2 = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=[nh1, nh2])
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'bgp always-compare-med' command at R1.")
    input_dict_r1 = {"r1": {"bgp": {"local_as": "100", "bgp_always_compare_med": True}}}
    result = create_router_bgp(tgen, topo, input_dict_r1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'bgp always-compare-med', its chooses lowest MED value path"
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Restart the BGPd/Zebra/FRR service on R1")
    for daemon in ["bgpd", "zebra", "frr"]:
        if daemon == "frr":
            stop_router(tgen, "r1")
            start_router(tgen, "r1")
        else:
            kill_router_daemons(tgen, "r1", daemon)

    step(
        "Verify after restarting dameons and frr services, its chooses lowest MED value path"
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Clear bgp on R1")
    clear_bgp(tgen, None, "r1")

    step("Verify after clearing BGP, its chooses lowest MED value path")
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Perform BGP neighborship shut/no shut")
    for action, keyword in zip([True, False], ["shut", "noshut"]):
        for addr_type in ADDR_TYPES:
            input_dict = {
                "r1": {
                    "bgp": {
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r3": {
                                            "dest_link": {"r1": {"shutdown": action}}
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
                tc_name, result
            )

        step("Verify after {} BGP, its chooses lowest MED value path".format(keyword))
        if action:
            for addr_type in ADDR_TYPES:
                input_static_r1 = {
                    "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
                }
                nh = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]

                result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )
        else:
            for addr_type in ADDR_TYPES:
                input_static_r1 = {
                    "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
                }
                nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

                result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

    write_test_footer(tc_name)


def test_verify_bgp_always_compare_med_functionality_by_shut_noshut_interfaces_bw_bgp_neighbors_p1(
    request,
):
    """
    Verify BGP always compare MED functionality by performing shut/noshut on the interfaces in between BGP neighbors
    """

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)
    initial_configuration(tgen, tc_name)

    step(
        "Configure IPv4 and IPv6, eBGP neighbors between R1,R2 and R3 routers as per base config"
    )
    step(
        "Verify that IPv4 and IPv6 eBGP neighbors are configured in between routers by following "
        "commands and verify that best path chosen by lowest MED value"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'multi-path as-path relax' command at R1.")
    configure_bgp = {
        "r1": {"bgp": {"local_as": "100", "bestpath": {"aspath": "multipath-relax"}}}
    }
    result = create_router_bgp(tgen, topo, configure_bgp)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'multi-path as-path relax' command, "
        "its also chooses lowest MED to reach destination."
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh1 = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]
        nh2 = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=[nh1, nh2])
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure 'bgp always-compare-med' command at R1.")
    input_dict_r1 = {"r1": {"bgp": {"local_as": "100", "bgp_always_compare_med": True}}}
    result = create_router_bgp(tgen, topo, input_dict_r1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that after applying 'bgp always-compare-med', its chooses lowest MED value path"
    )
    for addr_type in ADDR_TYPES:
        input_static_r1 = {
            "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
        }
        nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for action, keyword in zip([False, True], ["Shut", "No Shut"]):
        step(
            "{} the interface on the link between R3 & R4 and R2 & R4 routers".format(
                keyword
            )
        )
        intf2_4 = topo["routers"]["r2"]["links"]["r4"]["interface"]
        intf3_4 = topo["routers"]["r3"]["links"]["r4"]["interface"]
        for dut, intf in zip(["r2", "r3"], [intf2_4, intf3_4]):
            shutdown_bringup_interface(tgen, dut, intf, action)

        for addr_type in ADDR_TYPES:
            input_static_r1 = {
                "r1": {"static_routes": [{"network": NETWORK1_1[addr_type]}]}
            }
            nh = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

            if action:
                result = verify_bgp_rib(tgen, addr_type, "r1", input_static_r1)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, "r1", input_static_r1, next_hop=nh)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

            else:
                result = verify_bgp_rib(
                    tgen, addr_type, "r1", input_static_r1, expected=False
                )
                assert (
                    result is not True
                ), "Testcase {} :Failed \n Routes are still present in BGP table\n Error {}".format(
                    tc_name, result
                )

                result = verify_rib(
                    tgen, addr_type, "r1", input_static_r1, next_hop=nh, expected=False
                )
                assert (
                    result is not True
                ), "Testcase {} :Failed \n Routes are still present in FIB \n Error {}".format(
                    tc_name, result
                )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
