#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""

Following tests are covered in the script.

- Verify static route are blocked from route-map and prefix-list
    applied in BGP nbrs
- Verify Static route when FRR connected to 2 TOR
"""

import sys
import time
import os
import pytest
import platform
import ipaddress
from copy import deepcopy

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))
# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topotest import version_cmp

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    check_address_types,
    step,
    create_prefix_lists,
    create_route_maps,
    verify_prefix_lists,
    verify_route_maps,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    clear_bgp_and_verify,
    clear_bgp,
)
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()
NETWORK = {"ipv4": "2.2.2.2/32", "ipv6": "22:22::2/128"}
NEXT_HOP_IP = {}


def setup_module(mod):
    """
    Set up the pytest environment.
    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/static_routes_topo4_ebgp.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    if version_cmp(platform.release(), "4.19") < 0:
        error_msg = (
            'These tests will not run. (have kernel "{}", '
            "requires kernel >= 4.19)".format(platform.release())
        )
        pytest.skip(error_msg)

    # Checking BGP convergence

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # Api call verify whether BGP is converged
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Running setup_module() done")


def teardown_module(mod):
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


#####################################################
#
#   Tests starting
#
#####################################################
def test_static_routes_rmap_pfxlist_p0_tc7_ebgp(request):
    """
    Verify static route are blocked from route-map & prefix-list applied in BGP
    nbrs

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    reset_config_on_routers(tgen)
    step("Configure holddown timer = 1 keep alive = 3 in all the neighbors")
    step("verify bgp convergence before starting test case")

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step(
        "Configure 4 IPv4 and 4 IPv6 nbrs with password with mismatch "
        " authentication between FRR routers "
    )

    for addr_type in ADDR_TYPES:
        # Api call to modify BGP timers
        input_dict = {
            "r2": {
                "bgp": {
                    "local_as": "200",
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link0": {"password": "r2"},
                                            "r2-link1": {"password": "r2"},
                                            "r2-link2": {"password": "r2"},
                                            "r2-link3": {"password": "r2"},
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link0": {"password": "r2"},
                                            "r2-link1": {"password": "r2"},
                                            "r2-link2": {"password": "r2"},
                                            "r2-link3": {"password": "r2"},
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )
        clear_bgp(tgen, addr_type, "r2")

    step(" All BGP nbrs are down as authentication is mismatch on both  the sides")

    bgp_convergence = verify_bgp_convergence(tgen, topo, expected=False)
    assert (
        bgp_convergence is not True
    ), "Testcase {} :  Failed \n BGP nbrs must be down. Error: {}".format(
        tc_name, bgp_convergence
    )

    step(
        "Configure 4 IPv4 and 4 IPv6 nbrs with macthing password  "
        " authentication between FRR routers "
    )
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r2": {
                "bgp": {
                    "local_as": "200",
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link0": {"password": "r1"},
                                            "r2-link1": {"password": "r1"},
                                            "r2-link2": {"password": "r1"},
                                            "r2-link3": {"password": "r1"},
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link0": {"password": "r1"},
                                            "r2-link1": {"password": "r1"},
                                            "r2-link2": {"password": "r1"},
                                            "r2-link3": {"password": "r1"},
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            }
        }
        result = create_router_bgp(tgen, topo, deepcopy(input_dict))
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("All BGP nbrs are up as authentication is matched now")
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n  Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Create prefix list P1 to permit VM3 & deny VM1 v4 & v6 routes")
    step("Create prefix list P2 to permit VM6 IPv4 and IPv6 routes")
    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r2": {
                "prefix_lists": {
                    addr_type: {
                        "pf_list_1_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": topo["routers"]["r2"]["links"]["vm3"][
                                    addr_type
                                ],
                                "action": "permit",
                            },
                            {
                                "seqid": 20,
                                "network": topo["routers"]["r2"]["links"]["vm1"][
                                    addr_type
                                ],
                                "action": "deny",
                            },
                        ],
                        "pf_list_2_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": topo["routers"]["r2"]["links"]["vm6"][
                                    addr_type
                                ],
                                "action": "permit",
                            }
                        ],
                    }
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Prefix list created with matching networks deny or permit "
            "show ip prefix list"
        )
        result = verify_prefix_lists(tgen, input_dict_2)
        assert result is not True, "Testcase {} : Failed \n  Error: {}".format(
            tc_name, result
        )

        step("Redistribute all the routes (connected, static)")
        input_dict_2_r1 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_2_r2 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2_r2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_2_r3 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2_r3)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute connected in Router BGP")

        input_dict_2_r1 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "connected"}]}
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_2_r3 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "connected"}]}
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2_r3)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_2 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "connected"}]}
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Apply prefix list P1 on BGP neighbors 1 2 3 4 connected from  frr r1")
        # Configure prefix list to bgp neighbor
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link0": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_1_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_1_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_1_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link3": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_1_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
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

        step("Apply prefix list P2 on BGP nbrs 5 & 6 connected from FRR-2")
        # Configure prefix list to bgp neighbor
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r2-link0": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_2_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_2_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_2_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link3": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_2_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
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

        clear_bgp_and_verify(tgen, topo, "r2")

        step(
            "VM1 IPv4 and IPv6 Route which is denied using prefix list is "
            "not present on FRR1 side routing table , also not able to "
            "ping the routes show ip route"
        )

        dut = "r1"
        protocol = "bgp"
        ntwk_r2_vm1 = str(
            ipaddress.ip_interface(
                "{}".format(topo["routers"]["r2"]["links"]["vm1"][addr_type])
            ).network
        )
        input_dict = {"r1": {"static_routes": [{"network": ntwk_r2_vm1}]}}
        result4 = verify_rib(
            tgen, addr_type, dut, input_dict, protocol=protocol, expected=False
        )
        assert result4 is not True, (
            "Testcase {} : Failed , VM1 route is "
            "not filtered out via prefix list. \n Error: {}".format(tc_name, result4)
        )

        step(
            "VM4 and VM6 IPV4 and IPv6 address are present in local and "
            "FRR2 routing table show ip bgp show ip route"
        )

        dut = "r2"
        ntwk_r2_vm6 = str(
            ipaddress.ip_interface(
                "{}".format(topo["routers"]["r2"]["links"]["vm6"][addr_type])
            ).network
        )
        input_dict = {"r3": {"static_routes": [{"network": ntwk_r2_vm6}]}}
        result4 = verify_rib(tgen, addr_type, dut, input_dict)
        assert result4 is True, "Testcase {} : Failed.\n Error: {}".format(
            tc_name, result4
        )

        step("Remove prefix list from all the neighbors")
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link0": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_1_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                        "delete": True,
                                                    }
                                                ]
                                            },
                                            "r2-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_1_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                        "delete": True,
                                                    }
                                                ]
                                            },
                                            "r2-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_1_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                        "delete": True,
                                                    }
                                                ]
                                            },
                                            "r2-link3": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_1_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                        "delete": True,
                                                    }
                                                ]
                                            },
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

        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r2-link0": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_2_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                        "delete": True,
                                                    }
                                                ]
                                            },
                                            "r2-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_2_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                        "delete": True,
                                                    }
                                                ]
                                            },
                                            "r2-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_2_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                        "delete": True,
                                                    }
                                                ]
                                            },
                                            "r2-link3": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pf_list_2_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                        "delete": True,
                                                    }
                                                ]
                                            },
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

        clear_bgp_and_verify(tgen, topo, "r2")

        step("Create RouteMap_1 with prefix list P1 and weight 50")
        # Create route map
        rmap_dict = {
            "r2": {
                "route_maps": {
                    "rmap_pf_list_1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {"weight": 50},
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
        result = create_route_maps(tgen, rmap_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Create RouteMap_2 with prefix list P2 and weight 50")
        # Create route map
        rmap_dict = {
            "r2": {
                "route_maps": {
                    "rmap_pf_list_2_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {"weight": 50},
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_list_2_{}".format(addr_type)
                                }
                            },
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, rmap_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Verify Route-map created verify using show route-map")
        # verify rmap_pf_list_1 and rmap_pf_list_2 are present in router r2
        input_dict = {
            "r2": {
                "route_maps": [
                    "rmap_pf_list_1_{}".format(addr_type),
                    "rmap_pf_list_2_{}".format(addr_type),
                ]
            }
        }
        result = verify_route_maps(tgen, input_dict, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Apply policy RouteMap_1 nbrs 1 2 3 4 to FRR 1")
        # Configure prefix list to bgp neighbor
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link0": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_pf_list_1_"
                                                        "{}".format(addr_type),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_pf_list_1_"
                                                        "{}".format(addr_type),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_pf_list_1_"
                                                        "{}".format(addr_type),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_pf_list_1_"
                                                        "{}".format(addr_type),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
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

        step("Apply policy RouteMap_2 nbrs 5 and 6 to FRR2")
        # Configure prefix list to bgp neighbor
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r2-link0": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_pf_list_2_"
                                                        "{}".format(addr_type),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_pf_list_2_"
                                                        "{}".format(addr_type),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_pf_list_2_"
                                                        "{}".format(addr_type),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_pf_list_2_"
                                                        "{}".format(addr_type),
                                                        "direction": "out",
                                                    }
                                                ]
                                            },
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
            "After applying to BGP neighbors verify VM1 IPv4 and IPv6 Route"
            " which is denied using prefix list is not present on FRR side"
            " routing table , also not able to ping the routes show ip route"
            " and VM4 and VM6 IPV4 and IPv6 address are present in local and"
            " FRR routing table show ip bgp show ip route"
        )

        dut = "r1"
        protocol = "bgp"
        ntwk_r2_vm1 = str(
            ipaddress.ip_interface(
                "{}".format(topo["routers"]["r2"]["links"]["vm1"][addr_type])
            ).network
        )
        input_dict = {"r1": {"static_routes": [{"network": ntwk_r2_vm1}]}}
        result4 = verify_rib(
            tgen, addr_type, dut, input_dict, protocol=protocol, expected=False
        )
        assert (
            result4 is not True
        ), "Testcase {} : Failed \n routes are still present \n Error: {}".format(
            tc_name, result4
        )

        step("vm4 should be present in FRR1")
        dut = "r1"
        ntwk_r2_vm1 = str(
            ipaddress.ip_interface(
                "{}".format(topo["routers"]["r1"]["links"]["vm4"][addr_type])
            ).network
        )
        input_dict = {"r1": {"static_routes": [{"network": ntwk_r2_vm1}]}}
        result4 = verify_rib(tgen, addr_type, dut, input_dict)
        assert result4 is True, (
            "Testcase {} : Failed , VM1 route is "
            "not filtered out via prefix list. \n Error: {}".format(tc_name, result4)
        )

        step("vm4 should be present in FRR2")
        dut = "r2"
        ntwk_r2_vm1 = str(
            ipaddress.ip_interface(
                "{}".format(topo["routers"]["r1"]["links"]["vm4"][addr_type])
            ).network
        )
        input_dict = {"r1": {"static_routes": [{"network": ntwk_r2_vm1}]}}
        result4 = verify_rib(tgen, addr_type, dut, input_dict)
        assert result4 is True, (
            "Testcase {} : Failed , VM1 route is "
            "not filtered out via prefix list. \n Error: {}".format(tc_name, result4)
        )

        dut = "r3"
        protocol = "bgp"
        ntwk_r2_vm6 = str(
            ipaddress.ip_interface(
                "{}".format(topo["routers"]["r2"]["links"]["vm6"][addr_type])
            ).network
        )
        input_dict = {"r3": {"static_routes": [{"network": ntwk_r2_vm6}]}}
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed.\n Error: {}".format(
            tc_name, result4
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
