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
1. Verify BGP default-originate route with IBGP peer
2. Verify BGP default-originate route with EBGP peer
3. Verify BGP default route when default-originate configured with route-map over IBGP peer
4. Verify BGP default route when default-originate configured with route-map over EBGP peer"

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
    create_router_bgp,
    modify_as_number,
    verify_bgp_rib,
    get_prefix_count_route,
    get_dut_as_number,
    verify_rib_default_route,
)
from lib.common_config import (
    verify_prefix_lists,
    verify_fib_routes,
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
    delete_route_maps,
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
#                      Testcases
#
#####################################################


def test_verify_bgp_default_originate_in_IBGP_p0(request):
    """
    Verify BGP default-originate route with IBGP peer
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

    step("Configure IPv4 and IPv6 , IBGP neighbor between R1 and R2")
    step("Configure IPv4 and IPv6 Loopback interface on R1, R0 and R2")
    step("Configure IPv4 and IPv6 EBGP neighbor between R0 and R1")

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
    assert (
        BGP_CONVERGENCE is True
    ), " Complete Convergence is expected after changing the ASN but failed to converge --> :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Configure IPv4 and IPv6 static route on R1 next-hop as NULL0")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
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
        ), "Testcase {} : Failed to configure the static routes {} on router R1 \n Error: {}".format(
            tc_name, static_routes_input, result
        )
    step("verify IPv4 and IPv6 static route are configured and up on R1")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r1", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed \n After configuring the static routes {} , the routes are not found in FIB   \n Error: {}".format(
            tc_name, static_routes_input, result
        )

    step(
        "Configure redistribute static and connected on R0 and R1,  for IPv4 and IPv6 address family "
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
        },
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert (
        result is True
    ), "Testcase {} : Failed to configure the redistribute static configuration \n Error: {}".format(
        tc_name, result
    )

    step(
        "After configuring redistribute command , verify static and connected routes ( loopback connected routes)  are advertised on R2"
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
        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : After redistributing static routes the routes {} expected in FIB but NOT FOUND ......! \n Error: {}".format(
            tc_name, static_routes_input, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : After redistributing static routes the routes {} expected in RIB but NOT FOUND ......!   \n Error: {}".format(
            tc_name, static_routes_input, result
        )

    step(
        "Taking the snapshot of the prefix count before configuring the default originate"
    )
    snapshot1 = get_prefix_count_route(tgen, topo, dut="r2", peer="r1")

    step(
        "Configure Default originate on R1 for R1 to R2, for  IPv4 and IPv6 BGP address family "
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
    assert (
        result is True
    ), "Testcase {} : Failed Configuring default originate configuration. \n Error: {}".format(
        tc_name, result
    )

    step(
        "After configuring default-originate command , verify default  routes are advertised on R2 "
        " R1 static and loopback routes received on R2 BGP and FIB"
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

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : post configuring the BGP Default originate configuration static and connected routes should not be effected but impacted on FIB .......! FAILED \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failedpost configuring the BGP Default originate configuration static and connected routes should not be effected but impacted on RIB......! FAILED \n Error: {}".format(
            tc_name, result
        )
    step(
        "Verify default route for IPv4 and IPv6  present with path=igp   metric =0 , local-preference= 100 "
    )
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        metric=0,
        locPrf=100,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step(
        "Taking the snapshot2 of the prefix count after configuring the default originate"
    )
    snapshot2 = get_prefix_count_route(tgen, topo, dut="r2", peer="r1")

    step("verifying the prefix count incrementing or not ")
    isIPv4prefix_incremented = False
    isIPv6prefix_incremented = False
    if snapshot1["ipv4_count"] < snapshot2["ipv4_count"]:
        isIPv4prefix_incremented = True
    if snapshot1["ipv6_count"] < snapshot2["ipv6_count"]:
        isIPv6prefix_incremented = True

    assert (
        isIPv4prefix_incremented is True
    ), "Testcase {} : Failed Error: IPV4 Prefix is not incremented on receiveing ".format(
        tc_name
    )

    assert (
        isIPv6prefix_incremented is True
    ), "Testcase {} : Failed Error: IPV6 Prefix is not incremented on receiveing ".format(
        tc_name
    )
    write_test_footer(tc_name)


def test_verify_bgp_default_originate_in_EBGP_p0(request):
    """
    Verify BGP default-originate route with EBGP peer
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
    step("Configure lPv4 and IPv6 Loopback interface on R3, R4  and R2")
    step("Configure IPv4 and IPv6 IBGP neighbor between R4 and R3")
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
    assert (
        BGP_CONVERGENCE is True
    ), "Complete convergence is expeceted after changing the ASN os the routes ..!  :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step(" Configure IPv4 and IPv6 static route on R3 next-hop on R4 interface")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
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
        ), "Testcase {} : Failed to configure the static routes ....! Failed \n Error: {}".format(
            tc_name, result
        )
    step("verify IPv4 and IPv6 static route are configured and up on R1")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r3", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Route is not found in {} in FIB ......! Failed \n Error: {}".format(
            tc_name, static_routes_input, result
        )

    step(
        "Configure redistribute static and connected on R3 and R4 for IPv4 and IPv6 address family  "
    )
    redistribute_static = {
        "r3": {
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
    ), "Testcase {} : Failed to configure redistribute configuratin \n Error: {}".format(
        tc_name, result
    )

    step(
        "After configuring redistribute command , verify static and connected routes ( loopback connected routes)  are advertised on R2"
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
        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert (
            result is True
        ), "Testcase {} :  static & and connected routes are expected but not found in FIB .... ! \n Error: {}".format(
            tc_name, result
        )
        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : static & and connected routes are expected but not found in RIB .... ! \n Error: {}".format(
            tc_name, result
        )
    snapshot1 = get_prefix_count_route(tgen, topo, dut="r2", peer="r3")
    step(
        "Configure Default originate on R3 for R3 to R2, on  IPv4 and IPv6 BGP address family"
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
    assert (
        result is True
    ), "Testcase {} : Failed to configure the default originate configuration \n Error: {}".format(
        tc_name, result
    )

    step(
        "After configuring default-originate command , verify default  routes are advertised on R2 on both BGP RIB and FIB"
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
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
                    },
                ]
            }
        }

        result = verify_fib_routes(tgen, addr_type, "r2", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : static route from R1 {} and default  route from R3 is expected in R2 FIB .....! NOT FOUND  \n Error: {}".format(
            tc_name, NETWORK1_1, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : static route from R1 {} and default  route from R3 is expected in R2 RIB .....! NOT FOUND \n Error: {}".format(
            tc_name, NETWORK1_1, result
        )

    step(
        "Verify default route for IPv4 and IPv6 present with path = ebgp as path, metric =0 "
    )
    # local preference will bgp not applicable for eBGP
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        metric=0,
        expected_aspath="4000",
    )
    assert (
        result is True
    ), "Testcase {} : Default route from R3 is expected with attributes in R2 RIB .....! NOT FOUND  Error: {}".format(
        tc_name, result
    )

    step(
        "Taking the snapshot2 of the prefix count after configuring the default originate"
    )
    snapshot2 = get_prefix_count_route(tgen, topo, dut="r2", peer="r3")
    step(
        "Verify out-prefix count is incremented default route on IPv4 and IPv6 neighbor"
    )
    isIPv4prefix_incremented = False
    isIPv6prefix_incremented = False
    if snapshot1["ipv4_count"] < snapshot2["ipv4_count"]:
        isIPv4prefix_incremented = True
    if snapshot1["ipv6_count"] < snapshot2["ipv6_count"]:
        isIPv6prefix_incremented = True

    assert (
        isIPv4prefix_incremented is True
    ), "Testcase {} : Failed Error: IPV4 Prefix is not incremented on receiveing ".format(
        tc_name
    )

    assert (
        isIPv6prefix_incremented is True
    ), "Testcase {} : Failed Error: IPV6 Prefix is not incremented on receiveing ".format(
        tc_name
    )
    write_test_footer(tc_name)


def test_verify_bgp_default_originate_in_IBGP_with_route_map_p0(request):
    """
    test_verify_bgp_default_originate_in_IBGP_with_route_map_p0
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

    step("Configure IPv4 and IPv6 , IBGP neighbor between R1 and R2")
    step("Configure IPv4 and IPv6 , EBGP neighbor between R1 and R0")
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
    assert (
        BGP_CONVERGENCE is True
    ), "Complete convergence is expected after changing ASN ....! ERROR :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Configure 2 IPv4 and 2 IPv6 Static route on R0 with next-hop as Null0")
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
        assert (
            result is True
        ), "Testcase {} : Static Configuration is Failed  \n Error: {}".format(
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
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r0", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : routes {} unable is not found in R0 FIB  \n Error: {}".format(
            tc_name, static_routes_input, result
        )

    step(
        "Configure  redistribute static on IPv4 and IPv6 address family on R0 for R0 to R1 neighbor "
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
    assert (
        result is True
    ), "Testcase {} : Failed to configure redistribute static configuration....! \n Error: {}".format(
        tc_name, result
    )

    step("verify IPv4 and IPv6 static route are configured and up on R1")
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
        result = verify_fib_routes(tgen, addr_type, "r1", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed... Routes {}  expected in r0 FIB after configuring the redistribute config \n Error: {}".format(
            tc_name, static_routes_input, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed... Routes {}  expected in r0 RIB after configuring the redistribute config \n Error: {}".format(
            tc_name, static_routes_input, result
        )

    step(
        "Configure IPv4 prefix-list Pv4 and and IPv6 prefix-list Pv6 on R1 to match BGP route Sv41, Sv42, IPv6 route Sv61 Sv62 permit "
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
    assert (
        result is True
    ), "Testcase {} : Failed  to configure the prefix list \n Error: {}".format(
        tc_name, result
    )

    step(
        "Configure IPV4 and IPv6 route-map (RMv4 and RMv6 ) matching prefix-list (Pv4 and Pv6) respectively on R1"
    )
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
    ), "Testcase {} : Failed to configure the route map  \n Error: {}".format(
        tc_name, result
    )

    step(
        "Configure default-originate with route-map (RMv4 and RMv6) on R1, on BGP IPv4 and IPv6 address family "
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
    ), "Testcase {} : Failed to configure the default originate \n Error: {}".format(
        tc_name, result
    )

    step("Verify the default route is received in BGP RIB and FIB")
    step(
        "After configuring default-originate command , verify default  routes are advertised on R2 "
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
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
        assert (
            result is True
        ), "Testcase {} : Failed...! Expected default route from R1 not found in FIB  \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert (
            result is True
        ), "Testcase {} : Failed...!   Expected default route from R1 not found in RIB  \n Error: {}".format(
            tc_name, result
        )
    step("Remove route-map RMv4 and RMv6 from default-originate command in R1")
    NOTE = """ Configuring the default-originate should remove the  previously applied default originate with condtional route-map"""
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
    assert (
        result is True
    ), "Testcase {} : Failed  to remove the  default originate conditional route-map \n Error: {}".format(
        tc_name, result
    )

    step(
        "Verify BGP RIB and FIB After removing route-map , default route still present on R2"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
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
        assert (
            result is True
        ), "Testcase {} : Failed Default route from R1 is not found in FIB \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert (
            result is True
        ), "Testcase {} :  Failed Default route from R1 is not found in RIB  \n Error: {}".format(
            tc_name, result
        )

    step("Configure default-originate with route-map (RMv4 and RMv6) on R1 ")
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {
                                "r2": {
                                    "route_map": "RMv4",
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {
                                "r2": {
                                    "route_map": "RMv6",
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert (
        result is True
    ), "Testcase {} : Failed to configure the Default originate route-map \n Error: {}".format(
        tc_name, result
    )

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
        assert (
            result is True
        ), "Testcase {} : Failed  Default Route from R1 is not found in FIB  \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert (
            result is True
        ), "Testcase {} : Failed  Default Route from R1 is not found in RIB  \n Error: {}".format(
            tc_name, result
        )

    step("Delete prefix list using no prefix-list")
    input_dict_3 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv4"],
                            "action": "permit",
                            "delete": True,
                        },
                        {
                            "seqid": "2",
                            "network": NETWORK2_1["ipv4"],
                            "action": "permit",
                            "delete": True,
                        },
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv6"],
                            "action": "permit",
                            "delete": True,
                        },
                        {
                            "seqid": "2",
                            "network": NETWORK2_1["ipv6"],
                            "action": "permit",
                            "delete": True,
                        },
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert (
        result is True
    ), "Testcase {} : Failed to delete the prefix list  Error: {}".format(
        tc_name, result
    )

    step(
        "Verify BGP RIB and FIB After deleting prefix-list , verify IPv4 and IPv6 default route got removed from DUT "
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
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
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed\n After deleteing prefix default route is not expected in FIB  \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n After deleteing prefix default route is not expected in RIB \n  Error: {}".format(
            tc_name, result
        )

    step("Configure prefix-list and delete route-map using no route-map")
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
    assert (
        result is True
    ), "Testcase {} : Failed to configure the prefix lists Error: {}".format(
        tc_name, result
    )

    step(
        "After configuring the Prefixlist cross checking the BGP Default route is configured again , before deleting the route map"
    )

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
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
            expected=True,
        )
        assert (
            result is True
        ), "Testcase {} : Failed Default route from R1 is expected in FIB but not found \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
            expected=True,
        )
        assert (
            result is True
        ), "Testcase {} :  Failed Default route from R1 is expected in RIB but not found \n Error: {}".format(
            tc_name, result
        )

    step("Deleting the routemap")
    input_dict = {"r1": {"route_maps": ["RMv4", "RMv6"]}}
    result = delete_route_maps(tgen, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed to delete the Route-map \n Error: {}".format(
        tc_name, result
    )

    step(
        "Verify BGP RIB and FIB ,After deleting route-map , verify IPv4 and IPv6 default route got removed from DUT"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
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
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n After deleteing  route-map default route is not expected in FIB \nError: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n After deleteing route-map default route is not expected in RIB \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_bgp_default_originate_in_EBGP_with_route_map_p0(request):
    """
    test_verify_bgp_default_originate_in_EBGP_with_route_map_p0
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
        assert (
            result is True
        ), "Testcase {} : Failed  to configure the static routes \n Error: {}".format(
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
        assert (
            result is True
        ), "Testcase {} : Failed Static route {}  is not found in R4 FIB  \n Error: {}".format(
            tc_name, static_routes_input, result
        )

    step(
        "Configure  redistribute static on IPv4 and IPv6 address family on R4 for R4 to R3 neighbo"
    )
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
    assert (
        result is True
    ), "Testcase {} : Failed to configure the redistribute  static \n Error: {}".format(
        tc_name, result
    )

    step("verify IPv4 and IPv6 static route are configured and up on R3")
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
        assert (
            result is True
        ), "Testcase {} : Failed static routes from R1 and R3 is not found in FIB  \n Error: {}".format(
            tc_name, result
        )
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed static routes from R1 and R3 is not found in RIB  \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure IPv4 prefix-list Pv4 and and IPv6 prefix-list Pv6 on R3 so new route which is not present on R3"
    )
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {
                            "seqid": "1",
                            "network": NETWORK3_1["ipv4"],
                            "action": "permit",
                        }
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {
                            "seqid": "1",
                            "network": NETWORK3_1["ipv6"],
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

    step("verify IPv4 and IPv6 Prefix list got configured on R3")
    input_dict = {"r3": {"prefix_lists": ["Pv4", "Pv6"]}}
    result = verify_prefix_lists(tgen, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed ..! configured  prefix lists {}  are not found  \n Error: {}".format(
        tc_name, input_dict, result
    )

    step(
        "Configure IPv4 and IPv6 route-map ( RMv4 and RMv6 ) matching prefix-list (Pv4 and Pv6 ) respectively on R3"
    )
    input_dict_3 = {
        "r3": {
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
        "Taking the snapshot of the prefix count before configuring the default originate"
    )
    snapshot1 = get_prefix_count_route(tgen, topo, dut="r2", peer="r3")
    step(
        "Configure default-originate with IPv4 and IPv6  route-map (RMv4 and RMv6) on R3"
    )
    local_as = get_dut_as_number(tgen, dut="r3")
    default_originate_config = {
        "r3": {
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
    ), "Testcase {} : Failed to configure default-originate \n Error: {}".format(
        tc_name, result
    )

    step("Verify the default route is NOT received in BGP RIB and FIB on R2 ")
    step(
        "After configuring default-originate command , verify default  routes are not Received on R2 "
    )
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
        ), "Testcase {} : Failed \n Default route is not expected due to deny in prefix list \nError: {}".format(
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
        ), "Testcase {} : Failed \nDefault route is not expected due to deny in prefix list\n Error: {}".format(
            tc_name, result
        )

    step("Add route Sv41, Sv42, IPv6 route Sv61 Sv62 on prefix list Pv4 and Pv6")
    input_dict_3 = {
        "r3": {
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
    assert (
        result is True
    ), "Testcase {} : Failed  to configure the prefix lists Error: {}".format(
        tc_name, result
    )

    step("Verify BGP default route for IPv4 and IPv6 is received on R2")

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
        assert (
            result is True
        ), "Testcase {} : Failed Default routes are expected in R2 FIB  from R3 but not found ....!  \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
        )
        assert (
            result is True
        ), "Testcase {} : Failed Default routes are expected in R2 RIB  from R3 but not found ....! \n Error: {}".format(
            tc_name, result
        )

    step("Remove route  Sv41, Sv42, IPv6 route Sv61 Sv62 on prefix list Pv4 and Pv6")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv4"],
                            "action": "permit",
                            "delete": True,
                        },
                        {
                            "seqid": "2",
                            "network": NETWORK2_1["ipv4"],
                            "action": "permit",
                            "delete": True,
                        },
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv6"],
                            "action": "permit",
                            "delete": True,
                        },
                        {
                            "seqid": "2",
                            "network": NETWORK2_1["ipv6"],
                            "action": "permit",
                            "delete": True,
                        },
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert (
        result is True
    ), "Testcase {} : Failed to remove prefix-lists from R3 Error: {}".format(
        tc_name, result
    )

    step(
        "After Removing route  BGP default route for IPv4 and IPv6 is NOT received on R2"
    )
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
        ), "Testcase {} : Failed \n After Removing route in prefix list the default route is not expected in FIB \n Error: {}".format(
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
        ), "Testcase {} : Failed \n After Removing route in prefix list the default route is not expected in RIB\n Error: {}".format(
            tc_name, result
        )

    step(" Add route Sv41, Sv42, IPv6 route Sv61 Sv62 on prefix list Pv4 and Pv6")
    input_dict_3 = {
        "r3": {
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
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify BGP default route for IPv4 and IPv6 is received on R2")

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

    step("Change IPv4 and IPv6 prefix-list permit and deny ")
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {"seqid": "1", "network": NETWORK1_1["ipv4"], "action": "deny"},
                        {"seqid": "2", "network": NETWORK2_1["ipv4"], "action": "deny"},
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {"seqid": "1", "network": NETWORK1_1["ipv6"], "action": "deny"},
                        {"seqid": "2", "network": NETWORK2_1["ipv6"], "action": "deny"},
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify BGP default route for IPv4 and IPv6 is not received on R2")

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
        ), "Testcase {} : Failed \n after denying the prefix list default route is not expected in FIB \n Error: {}".format(
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
        ), "Testcase {} : Failed \n after denying the prefix list default route is not expected in RIB \n Error: {}".format(
            tc_name, result
        )

    step("Change IPv4 and IPv6 prefix-list deny to permit ")
    input_dict_3 = {
        "r3": {
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
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify BGP default route for IPv4 and IPv6 is  received on R2")
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

    step(
        "Taking the snapshot2 of the prefix count after configuring the default originate"
    )
    snapshot2 = get_prefix_count_route(tgen, topo, dut="r2", peer="r3")

    step("verifying the prefix count incrementing or not ")
    isIPv4prefix_incremented = False
    isIPv6prefix_incremented = False
    if snapshot1["ipv4_count"] < snapshot2["ipv4_count"]:
        isIPv4prefix_incremented = True
    if snapshot1["ipv6_count"] < snapshot2["ipv6_count"]:
        isIPv6prefix_incremented = True

    assert (
        isIPv4prefix_incremented is True
    ), "Testcase {} : Failed Error: IPV4 Prefix is not incremented on receiveing ".format(
        tc_name
    )

    assert (
        isIPv6prefix_incremented is True
    ), "Testcase {} : Failed Error: IPV6 Prefix is not incremented on receiveing ".format(
        tc_name
    )

    step(
        "Configure another IPv4 and IPv6 route-map and match same prefix-list (Sv41, Sv42, IPv6 route Sv61 Sv62) with deny statement "
    )
    input_dict_3 = {
        "r3": {
            "route_maps": {
                "RMv41": [
                    {
                        "action": "deny",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                    },
                ],
                "RMv61": [
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

    step("Attach route-map on IPv4 and IP6 BGP neighbor on fly")
    local_as = get_dut_as_number(tgen, dut="r3")
    default_originate_config = {
        "r3": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {"default_originate": {"r2": {"route_map": "RMv41"}}}
                    },
                    "ipv6": {
                        "unicast": {"default_originate": {"r2": {"route_map": "RMv61"}}}
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After attaching route-map verify IPv4 and IPv6 default route is withdrawn from the R2"
    )
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
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
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
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Change the recently added Routemap from deny to permit")
    input_dict_3 = {
        "r3": {
            "route_maps": {
                "RMv41": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                    },
                ],
                "RMv61": [
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

    step("Verify IPv4 and IPv6 default route is advertised from the R2")
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

    step(
        "Delete default-originate route-map command while configuring ( neighbor x.x.x default-originate) for IPv4 and IPv6 BGP neighbor "
    )
    """ Configuring the Default originate on neighbor  must remove the previously assigned  deault-originate with routemap config  """
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

    step(
        "Verify in running config from BGP that default-originate with route-map command is removed and default-originate command is still present and default route for IPv4 and IPv6 present in RIB and FIB"
    )
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

    step(
        "Configure default-originate with conditional route-map command on IPv4 and IPv6 address family  "
    )
    local_as = get_dut_as_number(tgen, dut="r3")
    default_originate_config = {
        "r3": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {"default_originate": {"r2": {"route_map": "RMv41"}}}
                    },
                    "ipv6": {
                        "unicast": {"default_originate": {"r2": {"route_map": "RMv61"}}}
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify in running config from BGP that default-originate with route-map command is present and default route for IPv4 and IPv6 present"
    )
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

    step(
        "Delete default originate with 'no bgp default-originate' from IPV4 and IPV6 address family "
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
        " Verify in running config from BGP that default-originate complete CLI is removed for IPV4 and IPV6 address family and default originate routes got deleted"
    )
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
        ), "Testcase {} : Failed \n Default Route is not expected in FIB \nError: {}".format(
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
        ), "Testcase {} : Failed \n Default Route is not expected in RIB\nError: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
