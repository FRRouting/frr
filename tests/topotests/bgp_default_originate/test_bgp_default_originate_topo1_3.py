#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
#                       Shreenidhi A R <rshreenidhi@vmware.com>
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#
"""
Following tests are covered.
10. Verify default-originate route after BGP and FRR process restart
11. Verify default-originate route after shut/no shut and clear BGP neighbor
"""
import os
import sys
import time
import pytest
from lib.topolog import logger
import json

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger

from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    modify_as_number,
    clear_bgp,
    verify_bgp_rib,
    get_dut_as_number,
    verify_rib_default_route,
    verify_fib_default_route,
)
from lib.common_config import (
    interface_status,
    verify_prefix_lists,
    verify_fib_routes,
    kill_router_daemons,
    start_router_daemons,
    shutdown_bringup_interface,
    step,
    required_linux_kernel_version,
    stop_router,
    start_router,
    create_route_maps,
    create_prefix_lists,
    get_frr_ipv6_linklocal,
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    create_static_routes,
    check_router_status,
    retry,
)

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers

# Global variables
topo = None
KEEPALIVETIMER = 1
HOLDDOWNTIMER = 3
# Global variables
NETWORK1_1 = {"ipv4": "198.51.1.1/32", "ipv6": "2001:DB8::1:1/128"}
NETWORK2_1 = {"ipv4": "198.51.1.2/32", "ipv6": "2001:DB8::1:2/128"}
DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}

r0_connected_address_ipv4 = "192.168.0.0/24"
r0_connected_address_ipv6 = "fd00::/64"
r1_connected_address_ipv4 = "192.168.1.0/24"
r1_connected_address_ipv6 = "fd00:0:0:1::/64"
r3_connected_address_ipv4 = "192.168.2.0/24"
r3_connected_address_ipv6 = "fd00:0:0:2::/64"
r4_connected_address_ipv4 = "192.168.3.0/24"
r4_connected_address_ipv6 = "fd00:0:0:3::/64"


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_default_originate_topo1.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls micronet initialization functions.
    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)
    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global ADDR_TYPES
    global BGP_CONVERGENCE
    global DEFAULT_ROUTES
    global DEFAULT_ROUTE_NXT_HOP_R1, DEFAULT_ROUTE_NXT_HOP_R3
    global R0_NETWORK_LOOPBACK, R0_NETWORK_LOOPBACK_NXTHOP, R1_NETWORK_LOOPBACK
    global R0_NETWORK_CONNECTED, R0_NETWORK_CONNECTED_NXTHOP, R1_NETWORK_CONNECTED, R1_NETWORK_CONNECTED_NXTHOP
    global R4_NETWORK_LOOPBACK, R4_NETWORK_LOOPBACK_NXTHOP, R3_NETWORK_LOOPBACK
    global R4_NETWORK_CONNECTED, R4_NETWORK_CONNECTED_NXTHOP, R3_NETWORK_CONNECTED, R3_NETWORK_CONNECTED_NXTHOP

    ADDR_TYPES = check_address_types()
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )
    # There are the global varibles used through out the file these are acheived only after building the topology.

    r0_loopback_address_ipv4 = topo["routers"]["r0"]["links"]["lo"]["ipv4"]
    r0_loopback_address_ipv4_nxt_hop = topo["routers"]["r0"]["links"]["r1"][
        "ipv4"
    ].split("/")[0]
    r0_loopback_address_ipv6 = topo["routers"]["r0"]["links"]["lo"]["ipv6"]
    r0_loopback_address_ipv6_nxt_hop = topo["routers"]["r0"]["links"]["r1"][
        "ipv6"
    ].split("/")[0]

    r1_loopback_address_ipv4 = topo["routers"]["r1"]["links"]["lo"]["ipv4"]
    r1_loopback_address_ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2"][
        "ipv4"
    ].split("/")[0]
    r1_loopback_address_ipv6 = topo["routers"]["r1"]["links"]["lo"]["ipv6"]
    r1_loopback_address_ipv6_nxt_hop = topo["routers"]["r1"]["links"]["r2"][
        "ipv6"
    ].split("/")[0]

    r4_loopback_address_ipv4 = topo["routers"]["r4"]["links"]["lo"]["ipv4"]
    r4_loopback_address_ipv4_nxt_hop = topo["routers"]["r4"]["links"]["r3"][
        "ipv4"
    ].split("/")[0]
    r4_loopback_address_ipv6 = topo["routers"]["r4"]["links"]["lo"]["ipv6"]
    r4_loopback_address_ipv6_nxt_hop = topo["routers"]["r4"]["links"]["r3"][
        "ipv6"
    ].split("/")[0]

    r3_loopback_address_ipv4 = topo["routers"]["r3"]["links"]["lo"]["ipv4"]
    r3_loopback_address_ipv4_nxt_hop = topo["routers"]["r3"]["links"]["r2"][
        "ipv4"
    ].split("/")[0]
    r3_loopback_address_ipv6 = topo["routers"]["r3"]["links"]["lo"]["ipv6"]
    r3_loopback_address_ipv6_nxt_hop = topo["routers"]["r3"]["links"]["r2"][
        "ipv6"
    ].split("/")[0]

    R0_NETWORK_LOOPBACK = {
        "ipv4": r0_loopback_address_ipv4,
        "ipv6": r0_loopback_address_ipv6,
    }
    R0_NETWORK_LOOPBACK_NXTHOP = {
        "ipv4": r0_loopback_address_ipv4_nxt_hop,
        "ipv6": r0_loopback_address_ipv6_nxt_hop,
    }

    R1_NETWORK_LOOPBACK = {
        "ipv4": r1_loopback_address_ipv4,
        "ipv6": r1_loopback_address_ipv6,
    }

    R0_NETWORK_CONNECTED = {
        "ipv4": r0_connected_address_ipv4,
        "ipv6": r0_connected_address_ipv6,
    }
    R0_NETWORK_CONNECTED_NXTHOP = {
        "ipv4": r0_loopback_address_ipv4_nxt_hop,
        "ipv6": r0_loopback_address_ipv6_nxt_hop,
    }

    R1_NETWORK_CONNECTED = {
        "ipv4": r1_connected_address_ipv4,
        "ipv6": r1_connected_address_ipv6,
    }
    R1_NETWORK_CONNECTED_NXTHOP = {
        "ipv4": r1_loopback_address_ipv4_nxt_hop,
        "ipv6": r1_loopback_address_ipv6_nxt_hop,
    }

    R4_NETWORK_LOOPBACK = {
        "ipv4": r4_loopback_address_ipv4,
        "ipv6": r4_loopback_address_ipv6,
    }
    R4_NETWORK_LOOPBACK_NXTHOP = {
        "ipv4": r4_loopback_address_ipv4_nxt_hop,
        "ipv6": r4_loopback_address_ipv6_nxt_hop,
    }

    R3_NETWORK_LOOPBACK = {
        "ipv4": r3_loopback_address_ipv4,
        "ipv6": r3_loopback_address_ipv6,
    }
    R4_NETWORK_CONNECTED = {
        "ipv4": r4_connected_address_ipv4,
        "ipv6": r4_connected_address_ipv6,
    }
    R4_NETWORK_CONNECTED_NXTHOP = {
        "ipv4": r4_loopback_address_ipv4_nxt_hop,
        "ipv6": r4_loopback_address_ipv6_nxt_hop,
    }

    R3_NETWORK_CONNECTED = {
        "ipv4": r3_connected_address_ipv4,
        "ipv6": r3_connected_address_ipv6,
    }
    R3_NETWORK_CONNECTED_NXTHOP = {
        "ipv4": r3_loopback_address_ipv4_nxt_hop,
        "ipv6": r3_loopback_address_ipv6_nxt_hop,
    }

    # populating the nexthop for default routes
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    interface = topo["routers"]["r1"]["links"]["r2"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv4"].split("/")[0]
    ipv6_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv6"].split("/")[0]
    DEFAULT_ROUTE_NXT_HOP_R1 = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}

    interface = topo["routers"]["r3"]["links"]["r2"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r3", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r3"]["links"]["r2"]["ipv4"].split("/")[0]
    ipv6_nxt_hop = topo["routers"]["r3"]["links"]["r2"]["ipv6"].split("/")[0]
    DEFAULT_ROUTE_NXT_HOP_R3 = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}

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


#####################################################
#
#                      Testcases
#
#####################################################


def test_verify_default_originate_after_BGP_and_FRR_restart_p2(request):
    """
    Summary: "Verify default-originate route after BGP and FRR process restart "
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    global topo
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    step("Configure EBGP between R0 to R1 and IBGP between R1 to R2")
    step("Configure EBGP between R2 to R3 and IBGP between R3 to R4")
    input_dict = {
        "r0": {
            "bgp": {
                "local_as": 999,
            }
        },
        "r1": {
            "bgp": {
                "local_as": 1000,
            }
        },
        "r2": {
            "bgp": {
                "local_as": 1000,
            }
        },
        "r3": {
            "bgp": {
                "local_as": 4000,
            }
        },
        "r4": {
            "bgp": {
                "local_as": 4000,
            }
        },
    }
    result = modify_as_number(tgen, topo, input_dict)
    try:
        assert result is True
    except AssertionError:
        logger.info("Expected behaviour: {}".format(result))
        logger.info("BGP config is not created because of invalid ASNs")
    step("After changing the BGP AS Path Verify the BGP Convergence")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert (
        BGP_CONVERGENCE is True
    ), " Failed convergence after chaning the AS number  :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Configure IPv4 and IPv6 static route (Sv4 , Sv6) on R0 and (S1v4, S1v6)on R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed to configure the static route on R0 \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert (
            result is True
        ), "Testcase {} :  Failed to configure the static route on R4  \n Error: {}".format(
            tc_name, result
        )

    step("verify IPv4 and IPv6 static route are configured and up on R0")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r0", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed  Route {} not found in R0 FIB  \n Error: {}".format(
            tc_name, NETWORK1_1, result
        )

    step("verify IPv4 and IPv6 static route are configured and up on R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r4", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed  Route {} not found in R4 FIB \n Error: {}".format(
            tc_name, NETWORK2_1, result
        )

    step(
        "Configure redistribute connected and static on R0 (R0-R1) on R4 ( R4-R3) IPv4 and IPv6 address family"
    )
    redistribute_static = {
        "r0": {
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
        },
        "r4": {
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
        },
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert (
        result is True
    ), "Testcase {} : Failed to configure the static route  \n Error: {}".format(
        tc_name, result
    )

    step("verify IPv4 and IPv6 static route are configured and up on R1")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r1", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed : Redistributed routes from R0 is not learned in Router R1 RIB \n Error: {}".format(
            tc_name, result
        )
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r1", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed : Redistributed routes from R0 is not learned in Router R1 FIB \n Error: {}".format(
            tc_name, result
        )

    step("verify IPv4 and IPv6 static route are configured and up on R3")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed : Redistributed routes from R4 is not learned in Router R3 RIB \n Error: {}".format(
            tc_name, result
        )
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R3_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r3", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Redistributed routes from R4 is not learned in Router R3 FIB \n Error: {}".format(
            tc_name, result
        )

    step("Configure IPv4 and IPv6 prefix-list on R1 for (Sv4 , Sv6) route")
    input_dict_3 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv4"],
                            "action": "permit",
                        }
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv6"],
                            "action": "permit",
                        }
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert (
        result is True
    ), "Testcase {} : Failed to configure the prefix lists \n Error: {}".format(
        tc_name, result
    )

    step("Verify the Prefix - lists")
    input_dict = {"r3": {"prefix_lists": ["Pv4", "Pv6"]}}
    result = verify_prefix_lists(tgen, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed to verify the prefix lists in router R3 \n Error: {}".format(
        tc_name, result
    )

    step("Configure IPv4 (RMv4)  and IPv6 (RMv6)  route-map on R1")
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "Pv6"}},
                    },
                ],
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert (
        result is True
    ), "Testcase {} : Failed to configure the route-map \n Error: {}".format(
        tc_name, result
    )

    step(
        "Configure default originate with route-map RMv4 and RMv6 for IPv4 and IPv6 bgp neighbors on R1 ( R1-R2) "
    )
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {"default_originate": {"r2": {"route_map": "RMv4"}}}
                    },
                    "ipv6": {
                        "unicast": {"default_originate": {"r2": {"route_map": "RMv6"}}}
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert (
        result is True
    ), "Testcase {} : Failed to configure the default-originate in R1 towards R2 \n Error: {}".format(
        tc_name, result
    )

    step("verify IPv4 and IPv6 default route received on R2 with R1 nexthop ")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
    )
    assert (
        result is True
    ), "Testcase {} : Failed : Default routes are not learned in  R2 FIB \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
    )
    assert (
        result is True
    ), "Testcase {} : Failed : Default routes are not learned in  R2 RIB\n Error: {}".format(
        tc_name, result
    )

    step(
        "Configure redistribute connected and static on R1 IPv4 and IPv6 address family"
    )
    redistribute_static = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {"redistribute": [{"redist_type": "connected"}]}
                    },
                    "ipv6": {
                        "unicast": {"redistribute": [{"redist_type": "connected"}]}
                    },
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify IPv4 and IPv6 static and loopback route advertised from R4 and R0  are received on R2"
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure default-originate on R3 for R3 to R2 IPv4 and IPv6 BGP neighbors ")
    local_as = get_dut_as_number(tgen, dut="r3")
    default_originate_config = {
        "r3": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {"unicast": {"default_originate": {"r2": {}}}},
                    "ipv6": {"unicast": {"default_originate": {"r2": {}}}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    STEP = """After configuring the Default Originate From R3 --> R2
        Both Default routes from R1 and R3 Should present in  R2 BGP RIB.
        'The Deafult Route from iBGP is preffered over EBGP' thus
        Default Route From R1->r2  should only present in R2 FIB  """
    step(STEP)

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n IBGP default route should be preffered over EBGP default-originate \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify the default route from R1 is  recieved both on RIB and FIB on R2")

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify the static and loopback route advertised from R0  and R4 are received on R2 "
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    # Allow for verification of the table version
    # as that restarting bgp on one router will cause
    # r2's version number should go up as that r1
    # is not directly connected to r2
    # where?
    @retry(retry_timeout=60)
    def verify_version_upgrade(dut, version):
        dut_new_ipv4_uni_json = json.loads(dut.vtysh_cmd("show bgp ipv4 uni json"))

        logger.info(
            "New version: {} comparing to old {}".format(
                dut_new_ipv4_uni_json["tableVersion"], version
            )
        )
        if version >= dut_new_ipv4_uni_json["tableVersion"]:
            return False

        return True

    r2 = tgen.gears["r2"]

    r2_bgp_ipv4_uni_json = json.loads(r2.vtysh_cmd("show bgp ipv4 uni json"))
    curr_version = r2_bgp_ipv4_uni_json["tableVersion"]

    step("BGP Daemon restart operation")
    routers = ["r1", "r2"]
    for dut in routers:
        step(
            "Restart BGPD process on {}, when all the processes are running use watchfrr ".format(
                dut
            )
        )

        kill_router_daemons(tgen, dut, ["bgpd"])
        # Let's ensure that r2's version has upgraded and then
        # let's check that the default route goes through
        # r3's connection.
        if dut == "r1":
            step("Ensure that r2 prefers r3's default route at this point in time")
            verify_version_upgrade(r2, curr_version)
            # write code to ensure r1 neighbor is down
            DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
            result = verify_fib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
                expected=True,
            )
            assert (
                result is True
            ), "Testcase {} : Failed \n IBGP default route should be prefeered over EBGP \n Error: {}".format(
                tc_name, result
            )

            result = verify_rib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
                expected=True,
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        start_router_daemons(tgen, dut, ["bgpd"])

        if dut == "r2":

            @retry(60)
            def check_pfx_received_sent(dut):
                output = json.loads(dut.vtysh_cmd("show bgp ipv4 uni summ json"))

                logger.info(output)
                if output["peerCount"] != 2:
                    logger.info(output["peerCount"])
                    logger.info("pc")
                    return False

                if output["peers"]["192.168.1.1"]["state"] != "Established":
                    logger.info("Not Established 192.168.1.1")
                    return False

                if output["peers"]["192.168.2.2"]["state"] != "Established":
                    logger.info("Not established 192.168.2.2")
                    return False

                if output["peers"]["192.168.1.1"]["pfxRcd"] != 6:
                    logger.info("1.1 prxRcd")
                    return False

                if output["peers"]["192.168.1.1"]["pfxSnt"] != 3:
                    logger.info("1.1 pfxsent")
                    return False

                if output["peers"]["192.168.2.2"]["pfxRcd"] != 4:
                    logger.info("2.2 pfxRcd")
                    return False

                if output["peers"]["192.168.2.2"]["pfxSnt"] != 9:
                    logger.info("2.2 pfxsnt")
                    return False

                return True

            check_pfx_received_sent(r2)
        step(
            "Verify the default route from R1 is  is recieved both on RIB and FIB on R2"
        )
        DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
        result = verify_fib_default_route(
            tgen,
            topo,
            dut="r2",
            routes=DEFAULT_ROUTES,
            expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
            expected=True,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib_default_route(
            tgen,
            topo,
            dut="r2",
            routes=DEFAULT_ROUTES,
            expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
            expected=True,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Verify the static and loopback route advertised from R0  and R4 are received on R2 "
        )
        for addr_type in ADDR_TYPES:
            static_routes_input = {
                "r2": {
                    "static_routes": [
                        {
                            "network": [NETWORK1_1[addr_type]],
                            "next_hop": NEXT_HOP_IP[addr_type],
                        },
                        {
                            "network": [NETWORK2_1[addr_type]],
                            "next_hop": NEXT_HOP_IP[addr_type],
                        },
                        {
                            "network": [R0_NETWORK_LOOPBACK[addr_type]],
                            "next_hop": R0_NETWORK_LOOPBACK[addr_type],
                        },
                        {
                            "network": [R0_NETWORK_CONNECTED[addr_type]],
                            "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                        },
                        {
                            "network": [R4_NETWORK_LOOPBACK[addr_type]],
                            "next_hop": R4_NETWORK_LOOPBACK[addr_type],
                        },
                        {
                            "network": [R4_NETWORK_CONNECTED[addr_type]],
                            "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                        },
                    ]
                }
            }

            result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

            result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step("Restarting  FRR routers  operation")
    """
    NOTE :  Verify that iBGP default route is preffered over eBGP default route
    """
    routers = ["r1", "r2"]
    for dut in routers:
        step(
            "Restart FRR router process on {}, when all the processes are running use watchfrr ".format(
                dut
            )
        )

        stop_router(tgen, dut)
        start_router(tgen, dut)

        result = verify_bgp_convergence(tgen, topo)
        assert (
            result is True
        ), " Testcase {} : After Restarting {} Convergence Failed".format(tc_name, dut)

        step("After restarting the FRR Router Verify the default originate ")
        DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
        result = verify_fib_default_route(
            tgen,
            topo,
            dut="r2",
            routes=DEFAULT_ROUTES,
            expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
            expected=True,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib_default_route(
            tgen,
            topo,
            dut="r2",
            routes=DEFAULT_ROUTES,
            expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
            expected=True,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Verify the default route from R1 is  is recieved both on RIB and FIB on R2"
        )

        DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
        result = verify_rib_default_route(
            tgen,
            topo,
            dut="r2",
            routes=DEFAULT_ROUTES,
            expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
            expected=True,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_fib_default_route(
            tgen,
            topo,
            dut="r2",
            routes=DEFAULT_ROUTES,
            expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} :  Failed\n IBGP default route should be preffered over EBGP default route \n Error: {}".format(
            tc_name, result
        )

        step(
            "Verify the static and loopback route advertised from R0  and R4 are received on R2 "
        )
        for addr_type in ADDR_TYPES:
            static_routes_input = {
                "r2": {
                    "static_routes": [
                        {
                            "network": [NETWORK1_1[addr_type]],
                            "next_hop": NEXT_HOP_IP[addr_type],
                        },
                        {
                            "network": [NETWORK2_1[addr_type]],
                            "next_hop": NEXT_HOP_IP[addr_type],
                        },
                        {
                            "network": [R0_NETWORK_LOOPBACK[addr_type]],
                            "next_hop": R0_NETWORK_LOOPBACK[addr_type],
                        },
                        {
                            "network": [R0_NETWORK_CONNECTED[addr_type]],
                            "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                        },
                        {
                            "network": [R4_NETWORK_LOOPBACK[addr_type]],
                            "next_hop": R4_NETWORK_LOOPBACK[addr_type],
                        },
                        {
                            "network": [R4_NETWORK_CONNECTED[addr_type]],
                            "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                        },
                    ]
                }
            }

            result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

            result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_verify_default_originate_after_shut_no_shut_bgp_neighbor_p1(request):
    """
    Summary: "Verify default-originate route after shut/no shut and clear BGP neighbor  "
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    global topo
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    step("Configure EBGP between R0 to R1 and IBGP between R1 to R2")
    step("Configure EBGP between R2 to R3 and IBGP between R3 to R4")
    input_dict = {
        "r0": {
            "bgp": {
                "local_as": 999,
            }
        },
        "r1": {
            "bgp": {
                "local_as": 1000,
            }
        },
        "r2": {
            "bgp": {
                "local_as": 1000,
            }
        },
        "r3": {
            "bgp": {
                "local_as": 4000,
            }
        },
        "r4": {
            "bgp": {
                "local_as": 4000,
            }
        },
    }
    result = modify_as_number(tgen, topo, input_dict)
    try:
        assert result is True
    except AssertionError:
        logger.info("Expected behaviour: {}".format(result))
        logger.info("BGP config is not created because of invalid ASNs")
    step("After changing the BGP AS Path Verify the BGP Convergence")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Configure one IPv4 and one IPv6 static route on R0 and R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify IPv4 and IPv6 static route configured on R0 and R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r0", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r4", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure redistribute connected and static on R0 (R0-R1) on R4 ( R4-R3) IPv4 and IPv6 address family"
    )
    redistribute_static = {
        "r0": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {
                                    "redist_type": "static",
                                },
                                {
                                    "redist_type": "connected",
                                },
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {
                                    "redist_type": "static",
                                },
                                {
                                    "redist_type": "connected",
                                },
                            ]
                        }
                    },
                }
            }
        },
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {
                                    "redist_type": "static",
                                },
                                {
                                    "redist_type": "connected",
                                },
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {
                                    "redist_type": "static",
                                },
                                {
                                    "redist_type": "connected",
                                },
                            ]
                        }
                    },
                }
            }
        },
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {
                                    "redist_type": "connected",
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {
                                    "redist_type": "connected",
                                }
                            ]
                        }
                    },
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify IPv4 and IPv6 static route configured on R1 from R0")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r1", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(tgen, addr_type, "r1", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify IPv4 and IPv6 static route configured on R3 from R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(tgen, addr_type, "r3", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure default-originate on R1 for R1 to R2 neighbor  for IPv4 and IPv6 peer "
    )
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {"unicast": {"default_originate": {"r2": {}}}},
                    "ipv6": {"unicast": {"default_originate": {"r2": {}}}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify IPv4 and IPv6 bgp default route received on R2 nexthop as R1")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    step(
        "After configuring default-originate command , verify default  routes are advertised on R2 from R0 and R4"
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure default-originate on R3 for R3 to R2 neighbor  for IPv4 and IPv6 peer"
    )
    local_as = get_dut_as_number(tgen, dut="r3")
    default_originate_config = {
        "r3": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {"unicast": {"default_originate": {"r2": {}}}},
                    "ipv6": {"unicast": {"default_originate": {"r2": {}}}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    STEP = """After configuring the Default Originate From R3 --> R2
        Both Default routes from R1 and R3 Should present in  R2 BGP RIB.
        'The Deafult Route from iBGP is preffered over EBGP' thus
        Default Route From R1->r2  should only present in R2 FIB  """
    step(STEP)

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n IBGP default route should be preffered over EBGP \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify the default route from R1 is  recieved both on RIB and FIB on R2")

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After configuring default-originate command , verify static ,connected and loopback  routes are advertised on R2 from R0 and R4"
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    # updating the topology with the updated AS-Number to avoid conflict in con configuring the AS
    updated_topo = topo
    updated_topo["routers"]["r0"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r0")
    updated_topo["routers"]["r1"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r1")
    updated_topo["routers"]["r2"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r2")
    updated_topo["routers"]["r3"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r3")
    updated_topo["routers"]["r4"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r4")

    step(
        "Shut  R1 to R2 IPv4 and IPv6 BGP neighbor from R1 IPv4 and IPv6 address family "
    )

    local_as = get_dut_as_number(tgen, dut="r1")
    shut_neighbor = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r1": {"shutdown": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r1": {"shutdown": True}}}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, updated_topo, shut_neighbor)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    interface = topo["routers"]["r2"]["links"]["r1"]["interface"]
    input_dict = {"r2": {"interface_list": [interface], "status": "down"}}

    result = interface_status(tgen, topo, input_dict)
    assert (
        result is True
    ), "Testcase {} : Bring down interface failed ! \n Error: {}".format(
        tc_name, result
    )

    step(
        "Verify IPv4 and IPv6 default static and loopback route which received from R1 are deleted from R2"
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }
        result = verify_bgp_rib(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n after shutting down interface routes are not expected \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n after shutting down interface routes are not expected  \n  Error: {}".format(
            tc_name, result
        )

    step("verify that  No impact on IPv4 IPv6 and default route received from R3 ")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step(
        "No-Shut  R1 to R2 IPv4 and IPv6 BGP neighbor from R1 IPv4 and IPv6 address family "
    )
    local_as = get_dut_as_number(tgen, dut="r1")
    shut_neighbor = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r1": {"shutdown": False}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r1": {"shutdown": False}}}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, updated_topo, shut_neighbor)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    interface = topo["routers"]["r2"]["links"]["r1"]["interface"]
    input_dict = {"r2": {"interface_list": [interface], "status": "up"}}

    result = interface_status(tgen, topo, input_dict)
    assert (
        result is True
    ), "Testcase {} : Bring up interface failed ! \n Error: {}".format(tc_name, result)

    step(
        "After no shut Verify IPv4 and IPv6 bgp default route next hop as R1 , static ,connected and loopback received on R2  from r0  and r4 "
    )

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step(
        "Shut  R3 to R2 IPv4 and IPv6 BGP neighbor from R2 IPv4 and IPv6 address family"
    )
    local_as = get_dut_as_number(tgen, dut="r3")
    shut_neighbor = {
        "r3": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r3": {"shutdown": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r3": {"shutdown": True}}}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, updated_topo, shut_neighbor)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    interface = topo["routers"]["r2"]["links"]["r3"]["interface"]
    input_dict = {"r2": {"interface_list": [interface], "status": "down"}}

    result = interface_status(tgen, topo, input_dict)
    assert (
        result is True
    ), "Testcase {} : Bring down interface failed ! \n Error: {}".format(
        tc_name, result
    )

    step(
        "Verify IPv4 and IPv6 default static and loopback route which received from R3 are deleted from R2 "
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }
        result = verify_bgp_rib(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed\n After shutting down the interface routes are not expected  \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n  After shutting down the interface routes are not expected \n  Error: {}".format(
            tc_name, result
        )

    step("Verify that Default route is removed  i.e advertised from R3")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n  After shutting down the interface Default route are not expected \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n After shutting down the interface Default route are not expected \n Error: {}".format(
        tc_name, result
    )

    step("Verify that No impact on IPv4 IPv6 and default route received from R1")

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "No-Shut  R3 to R2 IPv4 and IPv6 BGP neighbor from R2 IPv4 and IPv6 address family"
    )
    local_as = get_dut_as_number(tgen, dut="r3")
    shut_neighbor = {
        "r3": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r3": {"shutdown": False}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r3": {"shutdown": False}}}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, updated_topo, shut_neighbor)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    interface = topo["routers"]["r2"]["links"]["r3"]["interface"]
    input_dict = {"r2": {"interface_list": [interface], "status": "up"}}

    result = interface_status(tgen, topo, input_dict)
    assert (
        result is True
    ), "Testcase {} : Bring up interface failed ! \n Error: {}".format(tc_name, result)

    step(
        "Verify that a static ,connected and loopback  routes are received from R0 and R4 on R2 "
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step("verify that default route  is received on R2 from R1")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that default route  is received on R2 from R3")

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )
    step("Clear IPv4 and IP6 BGP session from R2 and R1 one by one ")
    routers = ["r1", "r2"]
    for dut in routers:
        for addr_type in ADDR_TYPES:

            clear_bgp(tgen, addr_type, dut)

            DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
            result = verify_rib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
                expected=True,
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
            result = verify_fib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
                expected=True,
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
            step("verify that default route  is received on R2 from R3")

            interface = topo["routers"]["r3"]["links"]["r2"]["interface"]
            ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r3", intf=interface)
            ipv4_nxt_hop = topo["routers"]["r3"]["links"]["r2"]["ipv4"].split("/")[0]
            DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
            DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}

            result = verify_rib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
                expected=True,
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
            result = verify_fib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
                expected=False,
            )
            assert result is not True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "Verify the static , loopback and connected routes received from r0 and r4"
        )
        for addr_type in ADDR_TYPES:
            static_routes_input = {
                "r2": {
                    "static_routes": [
                        {
                            "network": [NETWORK1_1[addr_type]],
                            "next_hop": NEXT_HOP_IP[addr_type],
                        },
                        {
                            "network": [NETWORK2_1[addr_type]],
                            "next_hop": NEXT_HOP_IP[addr_type],
                        },
                        {
                            "network": [R0_NETWORK_LOOPBACK[addr_type]],
                            "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                        },
                        {
                            "network": [R0_NETWORK_CONNECTED[addr_type]],
                            "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                        },
                        {
                            "network": [R4_NETWORK_LOOPBACK[addr_type]],
                            "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                        },
                        {
                            "network": [R4_NETWORK_CONNECTED[addr_type]],
                            "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                        },
                    ]
                }
            }

            result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

            result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step("Shut BGP neighbor interface R2 (R2 to R1) link ")
    intf_r2_r1 = topo["routers"]["r2"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r1, False)

    step("Verify the  bgp Convergence  ")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo, expected=False)
    assert (
        BGP_CONVERGENCE is not True
    ), " :Failed  After shutting interface BGP convergence is expected to be faileed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Verify  that default route from R1 got deleted from BGP and RIB table")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed\n After shuting interface default route should be removed from RIB  \n Error: {}".format(
        tc_name, result
    )

    step("No - Shut BGP neighbor interface R2 (R2 to R1) link ")
    intf_r2_r1 = topo["routers"]["r2"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r1, True)

    step("Verify the  bgp Convergence  ")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step("verify that default route  is received on R2 from R3")

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step("Verify the static , loopback and connected routes received from r0 and r4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Shut link from R3 to R2 from R3")
    intf_r3_r2 = topo["routers"]["r3"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "r3", intf_r3_r2, False)

    step("Verify the  bgp Convergence  ")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo, expected=False)
    assert (
        BGP_CONVERGENCE is not True
    ), "  :Failed \nAfter Shuting the interface BGP convegence is expected to be failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Verify  that default route from R3 got deleted from BGP and RIB table")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )
    step("No-Shut link from R3 to R2 from R3")

    ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv4"].split("/")[0]
    ipv6_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv6"].split("/")[0]

    DEFAULT_ROUTE_NXT_HOP_1 = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_nxt_hop}

    ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv4"].split("/")[0]
    ipv6_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv6"].split("/")[0]

    DEFAULT_ROUTE_NXT_HOP_3 = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_nxt_hop}

    intf_r3_r2 = topo["routers"]["r3"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "r3", intf_r3_r2, True)

    step("Verify the  bgp Convergence  ")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo, expected=True)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step("verify that default route  is received on R2 from R3")

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step("Verify the static , loopback and connected routes received from r0 and r4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R0_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R0_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R0_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R4_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R4_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R4_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
