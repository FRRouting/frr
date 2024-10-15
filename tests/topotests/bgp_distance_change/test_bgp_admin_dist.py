#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

import sys
import time
import pytest
import inspect
import os


"""Following tests are covered to test bgp admin distance functionality.
TC_1:
    Verify bgp admin distance functionality when static route is
    configured same as ebgp learnt route

TC_2:
    Verify ebgp admin distance functionality with ECMP.

TC_3:
    Verify ibgp admin distance functionality when static route is
    configured same as bgp learnt route.
TC_4:
    Verify ibgp admin distance functionality with ECMP.

TC_7: Chaos - Verify bgp admin distance functionality with chaos.
"""

#################################
# TOPOLOGY
#################################
"""

                    +-------+
         +--------- |  R2   |
         |          +-------+
         |iBGP           |
     +-------+           |
     |  R1   |           |iBGP
     +-------+           |
         |               |
         |    iBGP   +-------+   eBGP   +-------+
         +---------- |  R3   |----------|  R4   |
                     +-------+          +-------+
                        |
                        |eBGP
                        |
                    +-------+
                    |  R5   |
                    +-------+


"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

# Required to instantiate the topology builder class.
from lib.common_config import (
    start_topology,
    write_test_header,
    step,
    write_test_footer,
    create_static_routes,
    verify_rib,
    create_route_maps,
    create_prefix_lists,
    check_address_types,
    reset_config_on_routers,
    check_router_status,
    stop_router,
    kill_router_daemons,
    start_router_daemons,
    start_router,
    get_frr_ipv6_linklocal,
    verify_fib_routes,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_best_path_as_per_admin_distance,
    clear_bgp,
)

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger

# Global variables
topo = None
bgp_convergence = False
pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

NETWORK = {
    "ipv4": [
        "192.168.20.1/32",
        "192.168.20.2/32",
        "192.168.21.1/32",
        "192.168.21.2/32",
        "192.168.22.1/32",
        "192.168.22.2/32",
    ],
    "ipv6": [
        "fc07:50::1/128",
        "fc07:50::2/128",
        "fc07:150::1/128",
        "fc07:150::2/128",
        "fc07:1::1/128",
        "fc07:1::2/128",
    ],
}

ADDR_TYPES = check_address_types()


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global topo

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_admin_dist.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Checking BGP convergence
    global bgp_convergence
    global ADDR_TYPES

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "setup_module :Failed \n Error:" " {}".format(
        bgp_convergence
    )
    logger.info("Running setup_module() done")


def teardown_module(mod):
    """teardown_module.

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
# Tests starting
#####################################################
def test_bgp_admin_distance_ebgp_ecmp_p0():
    """
    TC: 2
    Verify ebgp admin distance functionality with ECMP.
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip("skipping test case because of BGP Convergence failure at setup")

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step("Configure static route  in R4 and R5, redistribute in bgp")

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r4": {
                "static_routes": [{"network": NETWORK[addr_type], "next_hop": "Null0"}]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r5": {
                "static_routes": [{"network": NETWORK[addr_type], "next_hop": "Null0"}]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that route is learnt in DUT via ebgp")

    # Verifying RIB routes
    protocol = "bgp"
    input_dict = topo["routers"]
    dut = "r3"
    nhop = {"ipv4": [], "ipv6": []}
    nhop["ipv4"].append(topo["routers"]["r4"]["links"]["r3"]["ipv4"].split("/")[0])
    nhop["ipv4"].append(topo["routers"]["r5"]["links"]["r3"]["ipv4"].split("/")[0])
    nhop["ipv6"].append(get_frr_ipv6_linklocal(tgen, "r4", "r3-r4-eth1"))
    nhop["ipv6"].append(get_frr_ipv6_linklocal(tgen, "r5", "r1-r3-eth1"))

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Configure the static route  in R3 (Dut).")

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that static route is selected as best route in zebra.")

    # Verifying RIB routes
    protocol = "static"
    dut = "r3"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }

        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step(" Configure the admin distance of 254 to static route  in R3.")

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type][0],
                        "next_hop": "Null0",
                        "admin_distance": 254,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that bgp routes are selected as best routes in zebra.")
    protocol = "bgp"
    dut = "r3"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": 100,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "distance": {"ebgp": 254, "ibgp": 254, "local": 254}
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "distance": {"ebgp": 254, "ibgp": 254, "local": 254}
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that bgp routes are selected as best routes in zebra.")
    # Verifying RIB routes
    protocol = "bgp"
    dut = "r3"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Configure bgp admin distance 10 with CLI in dut.")
    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": 100,
                "address_family": {
                    "ipv4": {
                        "unicast": {"distance": {"ebgp": 10, "ibgp": 254, "local": 254}}
                    },
                    "ipv6": {
                        "unicast": {"distance": {"ebgp": 10, "ibgp": 254, "local": 254}}
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify ebgp routes have admin distance of 10 in dut.")

    protocol = "bgp"
    input_dict = topo["routers"]
    dut = "r3"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_rib(
            tgen, addr_type, dut, input_dict, protocol=protocol, admin_distance=10
        )
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step(
        "Configure route map with weight as 200 and apply to one of the "
        "neighbor (R4 neighbor)."
    )

    # Create Prefix list
    input_dict_2 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "pf_ls_1": [
                        {
                            "seqid": 10,
                            "network": NETWORK["ipv4"][0],
                            "le": "32",
                            "action": "permit",
                        }
                    ]
                },
                "ipv6": {
                    "pf_ls_1_ipv6": [
                        {
                            "seqid": 100,
                            "network": NETWORK["ipv6"][0],
                            "le": "128",
                            "action": "permit",
                        }
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create route map
    input_dict_3 = {
        "r3": {
            "route_maps": {
                "RMAP_WEIGHT": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_ls_1"}},
                        "set": {"weight": 200},
                    },
                    {
                        "action": "permit",
                        "match": {"ipv6": {"prefix_lists": "pf_ls_1_ipv6"}},
                        "set": {"weight": 200},
                    },
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
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
                                                    "name": "RMAP_WEIGHT",
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
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {
                                                    "name": "RMAP_WEIGHT",
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
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that bgp route is selected as best on by zebra in r3.")

    protocol = "bgp"
    dut = "r3"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_rib(
            tgen, addr_type, dut, input_dict, protocol=protocol, admin_distance=10
        )
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Static route should not be selected as best route.")
    protocol = "static"
    dut = "r3"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_fib_routes(
            tgen, addr_type, dut, input_dict, protocol=protocol, expected=False
        )
        assert (
            result4 is not True
        ), "Testcase {} : Failed. Wrong route is selected as best route.\n Error: {}".format(
            tc_name, result4
        )

    step("Reconfigure the static route without admin distance")

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type][0],
                        "next_hop": "Null0",
                        "admin_distance": 254,
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that static route is installed as best route.")
    protocol = "static"
    dut = "r3"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_rib(
            tgen, addr_type, dut, input_dict, protocol=protocol, fib=True
        )
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Unconfigure the static route in R3.")

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type][0],
                        "next_hop": "Null0",
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that bgp route is selected as best on by zebra in r3.")

    protocol = "bgp"
    dut = "r3"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Un configure the route map on R3.")

    # Configure neighbor for route map
    input_dict_4 = {
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
                                                    "name": "RMAP_WEIGHT",
                                                    "direction": "in",
                                                    "delete": True,
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
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {
                                                    "name": "RMAP_WEIGHT",
                                                    "direction": "in",
                                                    "delete": True,
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify bgp routes installed in zebra.")

    # Verifying RIB routes
    protocol = "bgp"
    input_dict = topo["routers"]
    dut = "r3"
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "next_hop": "Null0"}
                ]
            }
        }
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    write_test_footer(tc_name)


def test_bgp_admin_distance_ibgp_p0():
    """
    TC: 3
    Verify bgp admin distance functionality when static route is
    configured same as ibgp learnt route
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip("skipping test case because of BGP Convergence failure at setup")

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step("Configure bgp admin distance 200 with CLI in dut.")

    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": 100,
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
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp routes have admin distance of 200 in dut.")
    # Verifying best path
    dut = "r3"
    attribute = "admin_distance"

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": "192.168.22.1/32",
                        "admin_distance": 200,
                    },
                    {
                        "network": "192.168.22.2/32",
                        "admin_distance": 200,
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": "fc07:1::1/128",
                        "admin_distance": 200,
                    },
                    {
                        "network": "fc07:1::2/128",
                        "admin_distance": 200,
                    },
                ]
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Modify the admin distance value to 150.")

    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": 100,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "distance": {"ebgp": 150, "ibgp": 150, "local": 150}
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "distance": {"ebgp": 150, "ibgp": 150, "local": 150}
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp routes have admin distance of 150 in dut.")
    # Verifying best path
    dut = "r3"
    attribute = "admin_distance"

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": "192.168.22.1/32",
                        "admin_distance": 150,
                    },
                    {
                        "network": "192.168.22.2/32",
                        "admin_distance": 150,
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": "fc07:1::1/128",
                        "admin_distance": 150,
                    },
                    {
                        "network": "fc07:1::2/128",
                        "admin_distance": 150,
                    },
                ]
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Un configure the admin distance value on DUT")

    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": 100,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "distance": {
                                "ebgp": 150,
                                "ibgp": 150,
                                "local": 150,
                                "delete": True,
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "distance": {
                                "ebgp": 150,
                                "ibgp": 150,
                                "local": 150,
                                "delete": True,
                            }
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp routes have default admin distance in dut.")
    # Verifying best path
    dut = "r3"
    attribute = "admin_distance"

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": "192.168.22.1/32",
                        "admin_distance": 20,
                    },
                    {
                        "network": "192.168.22.2/32",
                        "admin_distance": 20,
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": "fc07:1::1/128",
                        "admin_distance": 20,
                    },
                    {
                        "network": "fc07:1::2/128",
                        "admin_distance": 20,
                    },
                ]
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Learn the same route via ebgp and ibgp peer. Configure admin "
        "distance of 200 in DUT for both ebgp and ibgp peer. "
    )

    step("Verify that ebgp route is preferred over ibgp.")

    # Verifying RIB routes
    protocol = "bgp"
    input_dict = topo["routers"]

    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Configure static route  Without any admin distance")

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [{"network": NETWORK[addr_type], "next_hop": "Null0"}]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that zebra selects static route.")
    protocol = "static"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [{"network": NETWORK[addr_type], "next_hop": "Null0"}]
            }
        }

        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Configure static route  with admin distance of 253")
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "admin_distance": 253,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that zebra selects bgp route.")
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Configure admin distance of 254 in bgp for route.")

    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": 100,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "distance": {"ebgp": 254, "ibgp": 254, "local": 254}
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "distance": {"ebgp": 254, "ibgp": 254, "local": 254}
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that zebra selects static route.")
    protocol = "static"

    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Delete the static route.")
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "admin_distance": 253,
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that zebra selects bgp route.")
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    write_test_footer(tc_name)


def test_bgp_admin_distance_chaos_p2():
    """
    TC: 7
    Chaos - Verify bgp admin distance functionality with chaos.
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip("skipping test case because of BGP Convergence failure at setup")

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step("Configure bgp admin distance 200 with CLI in dut.")

    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": 100,
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
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp routes have admin distance of 200 in dut.")
    # Verifying best path
    dut = "r3"
    attribute = "admin_distance"

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][0],
                        "admin_distance": 200,
                    },
                    {
                        "network": NETWORK["ipv4"][1],
                        "admin_distance": 200,
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"][0],
                        "admin_distance": 200,
                    },
                    {
                        "network": NETWORK["ipv6"][1],
                        "admin_distance": 200,
                    },
                ]
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Restart frr on R3")
    stop_router(tgen, "r3")
    start_router(tgen, "r3")

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Verify ebgp and ibgp routes have admin distance of 200 in dut.")
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Restart bgpd process on R3")
    kill_router_daemons(tgen, "r3", ["bgpd"])
    start_router_daemons(tgen, "r3", ["bgpd"])

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Verify ebgp and ibgp routes have admin distance of 200 in dut.")
    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Clear BGP")
    for rtr in topo["routers"]:
        clear_bgp(tgen, "ipv4", rtr)
        clear_bgp(tgen, "ipv6", rtr)

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Verify that zebra selects bgp route.")
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
