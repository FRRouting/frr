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
5. Verify BGP  default originate route-map with OUT route-map
6. Verify BGP  default originate route-map with IN route-map
8. Verify BGP default route after removing default-originate
9. Verify default-originate route with GR
"""
import os
import sys
import time
import pytest
from lib.topolog import logger

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger

from lib.bgp import (
    verify_bgp_convergence,
    verify_graceful_restart,
    create_router_bgp,
    modify_as_number,
    verify_bgp_rib,
    get_dut_as_number,
    verify_rib_default_route,
    verify_fib_default_route,
    verify_bgp_advertised_routes_from_neighbor,
    verify_bgp_received_routes_from_neighbor,
)
from lib.common_config import (
    verify_prefix_lists,
    verify_fib_routes,
    kill_router_daemons,
    start_router_daemons,
    step,
    required_linux_kernel_version,
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
NETWORK1_1 = {"ipv4": "1.1.1.1/32", "ipv6": "1::1/128"}
NETWORK1_2 = {"ipv4": "1.1.1.2/32", "ipv6": "1::2/128"}
NETWORK2_1 = {"ipv4": "2.1.1.1/32", "ipv6": "2::1/128"}
NETWORK2_2 = {"ipv4": "2.1.1.2/32", "ipv6": "2::2/128"}
NETWORK3_1 = {"ipv4": "3.1.1.1/32", "ipv6": "3::1/128"}
NETWORK3_2 = {"ipv4": "3.1.1.2/32", "ipv6": "3::2/128"}
NETWORK4_1 = {"ipv4": "4.1.1.1/32", "ipv6": "4::1/128"}
NETWORK4_2 = {"ipv4": "4.1.1.2/32", "ipv6": "4::2/128"}
NETWORK5_1 = {"ipv4": "5.1.1.1/32", "ipv6": "5::1/128"}
NETWORK5_2 = {"ipv4": "5.1.1.2/32", "ipv6": "5::2/128"}
DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}

IPV4_RM = "RMVIPV4"
IPV6_RM = "RMVIPV6"

IPV4_RM1 = "RMVIPV41"
IPV6_RM1 = "RMVIPV61"

IPV4_RM2 = "RMVIPV42"
IPV6_RM2 = "RMVIPV62"

IPV4_PL_1 = "PV41"
IPV4_PL_2 = "PV42"

IPV6_PL_1 = "PV61"
IPV6_PL_2 = "PV62"


r1_ipv4_loopback = "1.0.1.0/24"
r2_ipv4_loopback = "1.0.2.0/24"
r3_ipv4_loopback = "1.0.3.0/24"
r4_ipv4_loopback = "1.0.4.0/24"
r1_ipv6_loopback = "2001:db8:f::1:0/120"
r2_ipv6_loopback = "2001:db8:f::2:0/120"
r3_ipv6_loopback = "2001:db8:f::3:0/120"
r4_ipv6_loopback = "2001:db8:f::4:0/120"

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
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global ADDR_TYPES
    global BGP_CONVERGENCE
    global DEFAULT_ROUTES
    global DEFAULT_ROUTE_NXT_HOP_R1, DEFAULT_ROUTE_NXT_HOP_R3
    global R0_NETWORK_LOOPBACK, R0_NETWORK_LOOPBACK_NXTHOP, R1_NETWORK_LOOPBACK, R1_NETWORK_LOOPBACK_NXTHOP
    global R0_NETWORK_CONNECTED, R0_NETWORK_CONNECTED_NXTHOP, R1_NETWORK_CONNECTED, R1_NETWORK_CONNECTED_NXTHOP
    global R4_NETWORK_LOOPBACK, R4_NETWORK_LOOPBACK_NXTHOP, R3_NETWORK_LOOPBACK, R3_NETWORK_LOOPBACK_NXTHOP
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
    R1_NETWORK_LOOPBACK_NXTHOP = {
        "ipv4": r1_loopback_address_ipv4_nxt_hop,
        "ipv6": r1_loopback_address_ipv6_nxt_hop,
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
    R3_NETWORK_LOOPBACK_NXTHOP = {
        "ipv4": r3_loopback_address_ipv4_nxt_hop,
        "ipv6": r3_loopback_address_ipv6_nxt_hop,
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
#                      Local API's
#
#####################################################


def configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut, peer):
    """
    This function groups the repetitive function calls into one function.
    """
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    return True


#####################################################
#
#                      Testcases
#
#####################################################


def test_verify_bgp_default_originate_route_map_in_OUT_p1(request):
    """
    test_verify_bgp_default_originate_route_map_in_OUT_p1
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

    step("Configure IPv4 and IPv6 , EBGP neighbor between R3 and R2")
    step("Configure IPv4 and IPv6 IBGP neighbor between R3 and R4")
    r0_local_as = topo["routers"]["r0"]["bgp"]["local_as"]
    r1_local_as = topo["routers"]["r1"]["bgp"]["local_as"]
    r2_local_as = topo["routers"]["r2"]["bgp"]["local_as"]
    r3_local_as = topo["routers"]["r3"]["bgp"]["local_as"]
    r4_local_as = topo["routers"]["r4"]["bgp"]["local_as"]
    input_dict = {
        "r0": {
            "bgp": {
                "local_as": r0_local_as,
            }
        },
        "r1": {
            "bgp": {
                "local_as": r1_local_as,
            }
        },
        "r2": {
            "bgp": {
                "local_as": r2_local_as,
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

    step(
        "Configure 2 IPv4 and 2 IPv6, Static route on R4 with next-hop as Null0 IPv4 route Sv41, Sv42, IPv6 route Sv61 Sv62"
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify IPv4 and IPv6 static route are configured and up on R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r4", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure redistribute static knob on R4 , for R4 to R3 neighbor ")
    redistribute_static = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    expected_routes = {
        "ipv4": [
            {"network": NETWORK1_1["ipv4"], "nexthop": NEXT_HOP_IP["ipv4"]},
            {"network": NETWORK2_1["ipv4"], "nexthop": NEXT_HOP_IP["ipv4"]},
        ],
        "ipv6": [
            {"network": NETWORK1_1["ipv6"], "nexthop": NEXT_HOP_IP["ipv4"]},
            {"network": NETWORK2_1["ipv6"], "nexthop": NEXT_HOP_IP["ipv4"]},
        ],
    }
    result = verify_bgp_advertised_routes_from_neighbor(
        tgen, topo, dut="r4", peer="r3", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After redistribute static verify the routes is recevied in router R3 in RIB and FIB"
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r3", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure IPv4 prefix-list Pv4 and and IPv6 prefix-list Pv6 on R3 to match BGP route Sv41, IPv6 route Sv61 with  permit option "
    )
    input_dict_3 = {
        "r3": {
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify IPv4 and IPv6 Prefix list got configured on R3")
    input_dict = {"r3": {"prefix_lists": ["Pv4", "Pv6"]}}
    result = verify_prefix_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure IPv4 and IPv6 route-map RMv4 and RMv6 matching prefix-list Pv4 and Pv6 with permit option "
    )
    input_dict_3 = {
        "r3": {
            "route_maps": {
                "RM4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                    },
                ],
                "RM6": [
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure IPv4 prefix-list Pv42 and and IPv6 prefix-list Pv62 on R3 to match BGP route Sv42, IPv6 route Sv62  with deny option"
    )
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "Pv42": [
                        {"seqid": "1", "network": NETWORK2_1["ipv4"], "action": "deny"}
                    ]
                },
                "ipv6": {
                    "Pv62": [
                        {"seqid": "1", "network": NETWORK2_1["ipv6"], "action": "deny"}
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify IPv4 and IPv6 Prefix list got configured on R3")
    input_dict = {"r3": {"prefix_lists": ["Pv42", "Pv62"]}}
    result = verify_prefix_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure IPv4 and IPv6 route-map (RMv42 and RMv62 )matching prefix-list Pv42 and Pv62 with permit option "
    )
    input_dict_3 = {
        "r3": {
            "route_maps": {
                "RMv42": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv42"}},
                    },
                ],
                "RMv62": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "Pv62"}},
                    },
                ],
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Apply IPv4 and IPv6 route-map RMv4 and RMv6 with default-originate on R3 , for R3 to R2 peers and Apply IPv4 and IPv6 out route-map RMv42 and RMv62 on R3 , for R3 to R2 peers "
    )
    local_as = get_dut_as_number(tgen, "r3")
    default_originate_config = {
        "r3": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {"default_originate": {"r2": {"route_map": "RM4"}}}
                    },
                    "ipv6": {
                        "unicast": {"default_originate": {"r2": {"route_map": "RM6"}}}
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    updated_topo = topo
    updated_topo["routers"]["r0"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r0")
    updated_topo["routers"]["r1"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r1")
    updated_topo["routers"]["r2"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r2")
    updated_topo["routers"]["r3"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r3")
    updated_topo["routers"]["r4"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r4")

    step(
        "Apply IPv4 and IPv6  route-map RMv42 and RMv62 on R3  (OUT Direction), for R3 to R2 peers "
    )
    input_dict_4 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {"name": "RMv42", "direction": "out"}
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
                                "r2": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {"name": "RMv62", "direction": "out"}
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

    result = create_router_bgp(tgen, updated_topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    NOTE = """
    After applying route-map on neighbor verify default BGP route IPv4  IPv6  route populated in R2 BGP and routing table , verify using "show ip bgp json" "show ipv6 bgp json" "show ip route json" "show ip route json"
    Sv42 and Sv62 route should not be  present on R2
    """
    step(NOTE)
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
                    }
                ]
            }
        }

        result = verify_fib_routes(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
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
                ]
            }
        }

        result = verify_fib_routes(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n Static routes are not expected due to conditions \nError: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n Static routes are not expected  due to conditions\n Error: {}".format(
            tc_name, result
        )

    step("Change IPv4 prefix-list Pv42 and and IPv6 prefix-list Pv62 deny to permit")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "Pv42": [
                        {
                            "seqid": "1",
                            "network": NETWORK2_1["ipv4"],
                            "action": "permit",
                        }
                    ]
                },
                "ipv6": {
                    "Pv62": [
                        {
                            "seqid": "1",
                            "network": NETWORK2_1["ipv6"],
                            "action": "permit",
                        }
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify IPv4 and IPv6 Prefix list got configured on R3")
    input_dict = {"r3": {"prefix_lists": ["Pv42", "Pv62"]}}
    result = verify_prefix_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    NOTE = """Default BGP route and IPv4 ( Sv42)  , IPv6 (Sv62)  route populated in R2 BGP and routing table"""
    step(NOTE)
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
                    }
                ]
            }
        }

        result = verify_fib_routes(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
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

    step("IPv4 prefix-list Pv4 and and IPv6 prefix-list Pv6 permit to deny ")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {"seqid": "1", "network": NETWORK1_1["ipv4"], "action": "deny"}
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {"seqid": "1", "network": NETWORK1_1["ipv6"], "action": "deny"}
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    NOTE = """
    Verify default-originate route (IPv4 and IPv6 ) not present on R2
    IPv4 ( Sv42)  , IPv6 (Sv62)  route populated in R2 BGP
    """
    step(NOTE)
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
                    }
                ]
            }
        }

        result = verify_fib_routes(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n default-route in FIB is not expected due to conditions \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n default-route in RIB is not expected due to conditions \n Error: {}".format(
            tc_name, result
        )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
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


def test_verify_bgp_default_originate_route_map_in_IN_p1(request):
    """Verify BGP  default originate route-map with IN route-map"""
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

    step("Configure IPv4 and IPv6 , EBGP neighbor between R1 and R2")
    step("Configure IPv4 and IPv6 , IBGP neighbor between R1 and R0")
    r0_local_as = topo["routers"]["r0"]["bgp"]["local_as"]
    r1_local_as = topo["routers"]["r1"]["bgp"]["local_as"]
    r2_local_as = topo["routers"]["r2"]["bgp"]["local_as"]
    r3_local_as = topo["routers"]["r3"]["bgp"]["local_as"]
    r4_local_as = topo["routers"]["r4"]["bgp"]["local_as"]
    input_dict = {
        "r0": {
            "bgp": {
                "local_as": 1000,
            }
        },
        "r1": {
            "bgp": {
                "local_as": 1000,
            }
        },
        "r2": {
            "bgp": {
                "local_as": r2_local_as,
            }
        },
        "r3": {
            "bgp": {
                "local_as": r3_local_as,
            }
        },
        "r4": {
            "bgp": {
                "local_as": r4_local_as,
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

    step(
        "Configure 2 IPv4 and 2 IPv6, Static route on R0 with next-hop as Null0 IPv4 route Sv41, Sv42, IPv6 route Sv61 Sv62"
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("verifyIPv4 and IPv6 static routes are configure and up on R0 ")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r0", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure redistribute static knob on R0 , for R0 to R1 IPv4 and IPv6 neighbor"
    )
    redistribute_static = {
        "r0": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify  IPv4 and IPv6 route received on R1  ")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r1", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure IPv4 prefix-list Pv4 and and IPv6 prefix-list Pv6 on R1 to match BGP route Sv41, Sv42, IPv6 route Sv61 Sv62"
    )
    input_dict_3 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv4"],
                            "action": "permit",
                        },
                        {
                            "seqid": "2",
                            "network": NETWORK2_1["ipv4"],
                            "action": "permit",
                        },
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv6"],
                            "action": "permit",
                        },
                        {
                            "seqid": "2",
                            "network": NETWORK2_1["ipv6"],
                            "action": "permit",
                        },
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify IPv4 and IPv6 Prefix list got configured on R1")
    input_dict = {"r1": {"prefix_lists": ["Pv4", "Pv6"]}}
    result = verify_prefix_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure IPv4 and IPv6 route-map RMv4 and RMv6 matching prefix-list Pv4 and Pv6 with deny option on R1"
    )
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "deny",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                    },
                ],
                "RMv6": [
                    {
                        "action": "deny",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "Pv6"}},
                    },
                ],
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Apply route-map IN direction in R1 (R1 to R0) IPv4 and IPv6 neighbor")
    updated_topo = topo
    updated_topo["routers"]["r0"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r0")
    updated_topo["routers"]["r1"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r1")
    updated_topo["routers"]["r2"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r2")
    updated_topo["routers"]["r3"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r3")
    updated_topo["routers"]["r4"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r4")

    local_as_r1 = get_dut_as_number(tgen, dut="r1")
    input_dict_4 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r0": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [
                                                {
                                                    "name": "RMv4",
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
                                "r0": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [
                                                {
                                                    "name": "RMv6",
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

    result = create_router_bgp(tgen, updated_topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    STEP = "After applying route-map verify that IPv4 route Sv41, Sv42, IPv6 route Sv61 Sv62 should not present on R1 BGP and routing table "
    step(STEP)

    step(
        "After applying route-map verify that IPv4 route Sv41, Sv42, IPv6 route Sv61 Sv62 should not present on R1 "
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
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(
            tgen, addr_type, "r1", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n default-route in FIB is not expected due to conditions  \nError: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen, addr_type, "r1", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n default-route in FIB is not expected due to conditions \nError: {}".format(
            tc_name, result
        )
    # Routes should come to dut but not the shown in RIB thus verifying using  show ip bgp nbr xxx received route
    step(
        " Verify the received routes \n using 'show ip bgp nbr xxx received route'  in Router R1"
    )
    expected_routes = {
        "ipv4": [
            {"network": NETWORK1_1["ipv4"], "nexthop": NEXT_HOP_IP["ipv4"]},
            {"network": NETWORK2_1["ipv4"], "nexthop": NEXT_HOP_IP["ipv4"]},
        ],
        "ipv6": [
            {"network": NETWORK1_1["ipv6"], "nexthop": NEXT_HOP_IP["ipv6"]},
            {"network": NETWORK2_1["ipv6"], "nexthop": NEXT_HOP_IP["ipv6"]},
        ],
    }
    result = verify_bgp_received_routes_from_neighbor(
        tgen, topo, dut="r1", peer="r0", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure default-originate on R1 for R1 to R2 IPv4 and IPv6 neighbor ")
    local_as_r1 = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as_r1,
                "address_family": {
                    "ipv4": {"unicast": {"default_originate": {"r2": {}}}},
                    "ipv6": {"unicast": {"default_originate": {"r2": {}}}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify Default originate knob is configured and default route advertised to R2 , verify on R1 "
    )
    expected_routes = {
        "ipv4": [
            {"network": "0.0.0.0/0", "nexthop": ""},
        ],
        "ipv6": [
            {"network": "::/0", "nexthop": ""},
        ],
    }
    result = verify_bgp_advertised_routes_from_neighbor(
        tgen, topo, dut="r1", peer="r2", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify the Default route Route in FIB in R2")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    }
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

    step("Change route-map RMv4 and RMv6 from deny to permit")
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    NOTE = """After changing  route-map to permit verify that IPv4 routes Sv41, Sv42, IPv6 routes Sv61 Sv62  present on R1 BGP and routing table , using "show ip route " "show ip bgp nbr xxx received route " "show ipv6 route " "show ipv6 bgp nbr xxx receied route """
    step(NOTE)
    expected_routes = {
        "ipv4": [{"network": NETWORK1_1["ipv4"], "nexthop": NEXT_HOP_IP["ipv4"]}],
        "ipv6": [{"network": NETWORK1_1["ipv6"], "nexthop": NEXT_HOP_IP["ipv4"]}],
    }
    result = verify_bgp_received_routes_from_neighbor(
        tgen, topo, dut="r1", peer="r0", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
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

    step("Configure default static route (IPv4 and IPv6) on R2 nexthop as R1 ")
    NEXT_HOP_IP_R1 = {}
    r1_r2_ipv4_neighbor = topo["routers"]["r1"]["links"]["r2"]["ipv4"].split("/")[0]
    r1_r2_ipv6_neighbor = topo["routers"]["r1"]["links"]["r2"]["ipv6"].split("/")[0]
    NEXT_HOP_IP_R1["ipv4"] = r1_r2_ipv4_neighbor
    NEXT_HOP_IP_R1["ipv6"] = r1_r2_ipv6_neighbor
    static_routes_input = {
        "r2": {
            "static_routes": [
                {
                    "network": "0.0.0.0/0",
                    "next_hop": NEXT_HOP_IP_R1["ipv4"],
                },
                {
                    "network": "0::0/0",
                    "next_hop": NEXT_HOP_IP_R1["ipv6"],
                },
            ]
        }
    }
    result = create_static_routes(tgen, static_routes_input)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify Static default route is taking preference over BGP default routes , BGP default route is inactive IN RIB and static is up and installed in RIB and FIB "
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv4"].split("/")[0]
    ipv6_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv6"].split("/")[0]
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_nxt_hop}

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP[addr_type],
                        "protocol": "static",
                    }
                ]
            }
        }
        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    write_test_footer(tc_name)


def test_verify_default_originate_after_removing_default_originate_p1(request):
    """Verify BGP default route after removing default-originate"""

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
    r0_local_as = topo["routers"]["r0"]["bgp"]["local_as"]
    r1_local_as = topo["routers"]["r1"]["bgp"]["local_as"]
    r2_local_as = topo["routers"]["r2"]["bgp"]["local_as"]
    r3_local_as = topo["routers"]["r3"]["bgp"]["local_as"]
    r4_local_as = topo["routers"]["r4"]["bgp"]["local_as"]
    input_dict = {
        "r0": {
            "bgp": {
                "local_as": r0_local_as,
            }
        },
        "r1": {
            "bgp": {
                "local_as": 2000,
            }
        },
        "r2": {
            "bgp": {
                "local_as": 2000,
            }
        },
        "r3": {
            "bgp": {
                "local_as": 5000,
            }
        },
        "r4": {
            "bgp": {
                "local_as": 5000,
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

    step("Configure IPv4 and IPv6 static route on R0 and R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            },
        }
        result = create_static_routes(tgen, static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify IPv4 and IPv6 static route are configured and up on R0 and R4")
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
        "Configure redistribute connected and static on R0 (R0-R1) on R4 ( R4-R3) IPv4 and IPv6 address family "
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
        "r3": {
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

    step("verify IPv4 and IPv6 static route are configured and up on R1 and R3")
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
                    {
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r1", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_bgp_rib(tgen, addr_type, "r1", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify IPv4 and IPv6 static route are configured and up on R1 and R3")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R3_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
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

        result = verify_fib_routes(tgen, addr_type, "r3", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes_input)
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
    step(
        "Verify  all the static , connected  and loopback routes from R0,R1,R3 and R4 is receieved on R2 "
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
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R3_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
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

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify the Default Originate on R2 nexthop as R1")

    interface = topo["routers"]["r1"]["links"]["r2"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv4"].split("/")[0]
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=True,
    )
    assert (
        result is True
    ), "Testcase {} : Failed \n Error: After Deactivating the BGP neighbor the default route is   expected but found in RIB -> {}".format(
        tc_name, result
    )

    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=True,
    )
    assert (
        result is True
    ), "Testcase {} : Failed \n Error:  After Deactivating the BGP neighbor the default route is   expected but found in FIB -> {}".format(
        tc_name, result
    )

    step(
        "Configure default-originate on R3 for R3 to R2 neighbor  for IPv4 and IPv6 peer "
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
        Both Default routes from R1 and R3 Should present in  R2 BGP RIB
        The Deafult Route from iBGP is prefferedover EBGP thus
        Default Route From R1->r2  should only present in R2 FIB  """
    step(STEP)

    interface = topo["routers"]["r3"]["links"]["r2"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r3", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r3"]["links"]["r2"]["ipv4"].split("/")[0]
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error: Only IBGP default originate is expected in FIB over EBGP {}".format(
        tc_name, result
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "No change on static and connected routes which got advertised from R0, R1, R3 and R4"
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
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R3_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
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

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        " Remove default-originate on R1 for R1 to R2 neighbor  for IPv4 and IPv6 peer "
    )
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {"default_originate": {"r2": {"delete": True}}}
                    },
                    "ipv6": {
                        "unicast": {"default_originate": {"r2": {"delete": True}}}
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify the Default Originate reoute from R1 to r2 is removed in R2 ")
    interface = topo["routers"]["r1"]["links"]["r2"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2"]["ipv4"].split("/")[0]
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n After removing the default originate the route should not be present in FIB \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n After removing the default originate the route should not be present in RIB \n Error: {}".format(
        tc_name, result
    )

    NOTE = """ after removing the Default originate from R1-->R2
     Verify the BGP Default route received from R3 is present in both BGP RIB and FIB on R2
     """
    interface = topo["routers"]["r3"]["links"]["r2"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r3", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r3"]["links"]["r2"]["ipv4"].split("/")[0]
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=True,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "No change on static and connected routes which got advertised from R0, R1, R3 and R4"
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
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R3_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
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

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Remove default-originate on R3 for R3 to R2 neighbor  for IPv4 and IPv6 peer "
    )
    local_as = get_dut_as_number(tgen, dut="r3")
    default_originate_config = {
        "r3": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {"default_originate": {"r2": {"delete": True}}}
                    },
                    "ipv6": {
                        "unicast": {"default_originate": {"r2": {"delete": True}}}
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After removing default originate , verify default IPv4 and IPv6 BGP routes removed on R2 from R1 ( next-hop as R3) "
    )
    interface = topo["routers"]["r3"]["links"]["r2"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r3", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r3"]["links"]["r2"]["ipv4"].split("/")[0]
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n After removing the default originate the route should not be present in FIB \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n After removing the default originate the route should not be present in RIB \n Error: {}".format(
        tc_name, result
    )
    step(
        "No change on static and connected routes which got advertised from R0, R1, R3 and R4"
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
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R3_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
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

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    write_test_footer(tc_name)


def test_verify_default_originate_route_with_GR_p1(request):
    """ "Verify default-originate route with GR " """
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

    step("Configure IPV4 and IPV6 IBGP between R1 and R2 ")
    step("Configure IPV4 and IPV6 EBGP between R2 to R3 ")
    r0_local_as = topo["routers"]["r0"]["bgp"]["local_as"]
    r1_local_as = topo["routers"]["r1"]["bgp"]["local_as"]
    r2_local_as = topo["routers"]["r2"]["bgp"]["local_as"]
    r3_local_as = topo["routers"]["r3"]["bgp"]["local_as"]
    r4_local_as = topo["routers"]["r4"]["bgp"]["local_as"]
    input_dict = {
        "r0": {
            "bgp": {
                "local_as": r0_local_as,
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
                "local_as": r3_local_as,
            }
        },
        "r4": {
            "bgp": {
                "local_as": r4_local_as,
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

    step(
        "Configure per peer Graceful restart on R2 ( restarting router) and  R3  helper router "
    )
    input_dict = {
        "r2": {
            "bgp": {
                "local_as": get_dut_as_number(tgen, "r2"),
                "graceful-restart": {
                    "graceful-restart": True,
                    "preserve-fw-state": True,
                },
            }
        },
        "r3": {
            "bgp": {
                "local_as": get_dut_as_number(tgen, "r3"),
                "graceful-restart": {"graceful-restart-helper": True},
            }
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r2", peer="r3")

    step("verify Graceful restart at R2")
    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r2", peer="r3"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step(
        "Configure default-originate on R1 for R1-R2 neighbor for IPv4 and IPv6 BGP peers "
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

    step(
        "R2 received default-originate routes and advertised it to R3 , verify on R2 and R3"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    step(
        "After configuring default-originate command , verify default  routes are advertised on R2 "
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    }
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

    step(" Kill BGPd session on R2")
    kill_router_daemons(tgen, "r2", ["bgpd"])
    start_router_daemons(tgen, "r2", ["bgpd"])

    step("verify default  route is relearned after clear bgp  on R2 on BGP RIB and")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    }
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
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
