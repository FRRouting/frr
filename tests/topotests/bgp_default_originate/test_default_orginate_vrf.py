#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
#                       Shreenidhi A R <rshreenidhi@vmware.com>
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#
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
)
from lib.common_config import (
    verify_prefix_lists,
    verify_rib,
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
NETWORK1_1 = {"ipv4": "198.51.1.1/32", "ipv6": "2001:DB8::1:1/128"}
NETWORK2_1 = {"ipv4": "198.51.1.2/32", "ipv6": "2001:DB8::1:2/128"}
NETWORK5_1 = {"ipv4": "198.51.1.3/32", "ipv6": "2001:DB8::1:3/128"}
NETWORK5_2 = {"ipv4": "198.51.1.4/32", "ipv6": "2001:DB8::1:4/128"}
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
    json_file = "{}/bgp_default_orginate_vrf.json".format(CWD)
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
    global R1_NETWORK_LOOPBACK, R1_NETWORK_LOOPBACK_NXTHOP
    global R0_NETWORK_CONNECTED_NXTHOP, R1_NETWORK_CONNECTED, R1_NETWORK_CONNECTED_NXTHOP
    global R3_NETWORK_LOOPBACK, R3_NETWORK_LOOPBACK_NXTHOP
    global R3_NETWORK_CONNECTED, R3_NETWORK_CONNECTED_NXTHOP

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

    R1_NETWORK_LOOPBACK = {
        "ipv4": r1_loopback_address_ipv4,
        "ipv6": r1_loopback_address_ipv6,
    }
    R1_NETWORK_LOOPBACK_NXTHOP = {
        "ipv4": r1_loopback_address_ipv4_nxt_hop,
        "ipv6": r1_loopback_address_ipv6_nxt_hop,
    }

    R1_NETWORK_CONNECTED = {
        "ipv4": r1_connected_address_ipv4,
        "ipv6": r1_connected_address_ipv6,
    }
    R1_NETWORK_CONNECTED_NXTHOP = {
        "ipv4": r1_loopback_address_ipv4_nxt_hop,
        "ipv6": r1_loopback_address_ipv6_nxt_hop,
    }

    R3_NETWORK_LOOPBACK = {
        "ipv4": r3_loopback_address_ipv4,
        "ipv6": r3_loopback_address_ipv6,
    }
    R3_NETWORK_LOOPBACK_NXTHOP = {
        "ipv4": r3_loopback_address_ipv4_nxt_hop,
        "ipv6": r3_loopback_address_ipv6_nxt_hop,
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
def test_verify_default_originate_route_with_non_default_VRF_p1(request):
    """
    "Verify default-originate route with non-default VRF"
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    # these steps are implemented as base toplopgy setup
    step("Configure IPV4 and IPV6 IBGP between R1 and R2 default VRF")
    step("Configure IPV4 and IPV6 EBGP between R2 to R3 non-default VRF (RED)")
    step(
        "Configure IPv4 and IP6 loopback address on R1 default  and R3 non-default (RED) VRF"
    )
    step("After changing the BGP AS Path Verify the BGP Convergence")

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )
    step(
        "Configure  IPv4 and IPv6 static route on R1 default and R3 non-default (RED) VRF with nexthop as Null ( different static route on each side)"
    )
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
        ), "Testcase {} : Failed to configure the static routes in router R1 default vrf \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed to configure static route in R3 non default vrf RED \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify IPv4 and IPv6 static route configured on R1 default vrf and R3 non-default (RED) vrf"
    )
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
        result = verify_rib(tgen, addr_type, "r1", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed: Routes configured on vrf is not seen in R1 default VRF FIB \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            }
        }
        result = verify_rib(tgen, addr_type, "r3", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed : Routes configured in non-defaul vrf in R3 FIB is \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure redistribute connected and static on R1 (R1-R2) and on R3 ( R2-R3 RED VRF) IPv4 and IPv6 address family "
    )
    redistribute_static = {
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
        "r3": {
            "bgp": {
                "local_as": 3000,
                "vrf": "RED",
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
                },
            }
        },
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert (
        result is True
    ), "Testcase {} : Failed to configure the redistribute on R1 and R3 \n Error: {}".format(
        tc_name, result
    )

    step(
        "Verify IPv4 and IPv6 static route configured on R1 received as BGP routes on R2 default VRF "
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
        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step(
        "Verify IPv4 and IPv6  static route configured on R3 received as BGP routes on R2 non-default VRF "
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
                        "vrf": "RED",
                    },
                ]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure default-originate on R1 for R1 to R2 neighbor for IPv4 and IPv6 peer"
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
    ), "Testcase {} : Failed to configure  the default originate \n Error: {}".format(
        tc_name, result
    )

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

        result = verify_rib(
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

        result = verify_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    snapshot1 = get_prefix_count_route(tgen, topo, dut="r2", peer="r3", vrf="RED")

    step(
        "Configure default-originate on R3 for R3 to R2 neighbor (RED VRF)   for IPv4 and IPv6 peer"
    )

    default_originate_config = {
        "r3": {
            "bgp": {
                "local_as": "3000",
                "vrf": "RED",
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
        "Verify IPv4 and IPv6 bgp default route and static route received on R2 VRF red nexthop as R3"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
                        "vrf": "RED",
                    },
                ]
            }
        }
        result = verify_rib(
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

    step("verify Out-prefix count incremented for IPv4/IPv6 default route on VRF red")
    snapshot2 = get_prefix_count_route(tgen, topo, dut="r2", peer="r3", vrf="RED")
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

    step("Configure import VRF red on R2 for IPV4 and IPV6 BGP peer")
    step("Importing the non-default vrf in default VRF ")
    local_as = get_dut_as_number(tgen, "r2")
    input_import_vrf = {
        "r2": {
            "bgp": [
                {
                    "local_as": local_as,
                    "address_family": {
                        "ipv4": {"unicast": {"import": {"vrf": "RED"}}},
                        "ipv6": {"unicast": {"import": {"vrf": "RED"}}},
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, input_import_vrf)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "Verify VRF RED IPv4 and IPv6,  default-originate, \n static and loopback route are imported to R2 default VRF table  ,\n default-originate route coming from VRF red should not active on R2 default VRF table"
    )
    step("verifying the static routes connected and loop back routes")
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
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK_NXTHOP[addr_type],
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    STEP = """ After importing non defualt VRF into default vrf .
    verify that the default originate from R1 --> R2(non -default) is preffered over R3 --> R2
    because the Default Route prefers iBGP over eBGP over
    Default Route  from R1 Should be present in BGP RIB and FIB
    Default Route  from R3 Should be present only in BGP RIB not in  FIB
    """
    step(STEP)
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

        result = verify_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
                    },
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step(
        "Configure import VRF default on R2 (R2-R3) RED VRF for IPV4 and IPV6 BGP peer"
    )
    step("Importing the default vrf in non-default VRF ")
    local_as = "2000"
    input_import_vrf = {
        "r2": {
            "bgp": [
                {
                    "local_as": local_as,
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {"unicast": {"import": {"vrf": "default"}}},
                        "ipv6": {"unicast": {"import": {"vrf": "default"}}},
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, input_import_vrf)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "Default VR, IPv4 and IPv6 , default-originate, \n static and loopback route are imported to R2  VRF RED table  \n, default-originate route coming from VRF red should not active on R2 default VRF table"
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK_NXTHOP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [R3_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R3_NETWORK_CONNECTED_NXTHOP[addr_type],
                        "vrf": "RED",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    STEP = """ After importing  defualt VRF into non default vrf .
    verify that the default originate from R1 --> R2(non -default) is preffered over R3 --> R2
    because the Default Route prefers iBGP over eBGP over
    Default Route  from R1 Should be present in BGP RIB and FIB
    Default Route  from R3 Should be present only in BGP RIB not in  FIB
    """
    step(STEP)
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                        "vrf": "RED",
                    }
                ]
            }
        }

        result = verify_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
                        "vrf": "RED",
                    }
                ]
            }
        }

        result = verify_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
            expected=False,
        )
        assert result is not True, "Testcase {} : Failed {} \n Error: {}".format(
            tc_name, STEP, result
        )

        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R3[addr_type],
                        "vrf": "RED",
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Remove import VRF configure in step 8 and then remove import VRF configured on step 9"
    )
    local_as = get_dut_as_number(tgen, "r2")
    input_import_vrf = {
        "r2": {
            "bgp": [
                {
                    "local_as": local_as,
                    "address_family": {
                        "ipv4": {"unicast": {"import": {"vrf": "RED", "delete": True}}},
                        "ipv6": {"unicast": {"import": {"vrf": "RED", "delete": True}}},
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, input_import_vrf)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that the routes imported from non default VRF  - RED is removed")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
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
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r2", static_routes_input, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n routes imported from non default VRF is not expected Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n routes imported from non default VRF is not expected \nError: {}".format(
            tc_name, result
        )

    step(
        "Remove import VRF configure in step 8 and then remove import VRF configured on step 9"
    )
    local_as = "2000"
    input_import_vrf = {
        "r2": {
            "bgp": [
                {
                    "local_as": local_as,
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"import": {"vrf": "default", "delete": True}}
                        },
                        "ipv6": {
                            "unicast": {"import": {"vrf": "default", "delete": True}}
                        },
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, input_import_vrf)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step("Verify that the routes impoted from  default VRF   is removed")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [R1_NETWORK_LOOPBACK[addr_type]],
                        "next_hop": R1_NETWORK_LOOPBACK_NXTHOP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [R1_NETWORK_CONNECTED[addr_type]],
                        "next_hop": R1_NETWORK_CONNECTED_NXTHOP[addr_type],
                        "vrf": "RED",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r2", static_routes_input, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n routes impoted from  default VRF is not expected \n  Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n routes impoted from  default VRF is not expected \n  Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_default_originate_route_with_non_default_VRF_with_route_map_p1(request):
    """
    "Verify default-originate route with non-default VRF with route-map import "
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Configure IPV4 and IPV6 static route on R0 with Null nexthop")
    STEP = """
    Configure IPV4 and IPV6 EBGP session between R0 and R1
    Configure IPV4 and IPV6 static route on R0 with Null nexthop """
    step(STEP)
    input_dict = {
        "r0": {"bgp": {"local_as": 222, "vrf": "default"}},
        "r1": {"bgp": {"local_as": 333, "vrf": "default"}},
    }
    result = modify_as_number(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
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

    step("Configuring static route at R0")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK5_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step(" Configure re-distribute static on R0 for R0 to R1  for IPV4 and IPV6 peer ")
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
        }
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure default-originate on R1 for R1 to R2 neighbor for IPv4 and IPv6 peer"
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

    snapshot1 = get_prefix_count_route(tgen, topo, dut="r2", peer="r3", vrf="RED")

    step("Verify IPv4 and IPv6  static  received on R2 default VRF as BGP routes")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK5_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step(
        " Configure IPv4 and IPv6 prefix-list of of route received from R1 on R2 and for 0.0.0.0/0 0::0/0 route"
    )
    input_dict_3 = {
        "r2": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {
                            "seqid": "1",
                            "network": NETWORK5_1["ipv4"],
                            "action": "permit",
                        },
                        {"seqid": "2", "network": "0.0.0.0/0", "action": "permit"},
                        {
                            "seqid": "3",
                            "network": NETWORK2_1["ipv4"],
                            "action": "permit",
                        },
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {
                            "seqid": "1",
                            "network": NETWORK5_1["ipv6"],
                            "action": "permit",
                        },
                        {"seqid": "2", "network": "0::0/0", "action": "permit"},
                        {
                            "seqid": "3",
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

    step("verify IPv4 and IPv6 Prefix list got configured on R3")
    input_dict = {"r2": {"prefix_lists": ["Pv4", "Pv6"]}}
    result = verify_prefix_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure IPv4/IPv6 route-map on R2 with deny sequence using above prefix-list"
    )
    input_dict_3 = {
        "r2": {
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

    STEP = """
    import Route-map anf non-default VRF into defailt vrf
    import vrf route-map RM1
    import vrf red
    """
    step(STEP)

    local_as = get_dut_as_number(tgen, "r2")
    input_import_vrf = {
        "r2": {
            "bgp": [
                {
                    "local_as": local_as,
                    "address_family": {
                        "ipv4": {"unicast": {"import": {"vrf": "RED"}}},
                        "ipv6": {"unicast": {"import": {"vrf": "RED"}}},
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, input_import_vrf)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(STEP)
    input_import_vrf = {
        "r2": {
            "bgp": [
                {
                    "local_as": local_as,
                    "address_family": {
                        "ipv4": {"unicast": {"import": {"vrf": "route-map RMv4"}}},
                        "ipv6": {"unicast": {"import": {"vrf": "route-map RMv6"}}},
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, input_import_vrf)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "Verify IPv4 and IPv6 routes present on VRF red ( static , default-originate) should not get advertised to default VRF "
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_R1[addr_type],
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r2", static_routes_input, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n VRF red ( static , default-originate) should not get advertised to default VRF  \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen, addr_type, "r2", static_routes_input, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n VRF red ( static , default-originate) should not get advertised to default VRF  \nError: {}".format(
            tc_name, result
        )

    step("Change route-map sequence deny to permit")
    input_dict_3 = {
        "r2": {
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

    step(
        "IPv4 and IPv6 routes present on VRF red ( static , default-originate) should get advertised to default VRF"
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

        result = verify_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify Out-prefix count incremented for IPv4/IPv6 default route on VRF red")
    snapshot2 = get_prefix_count_route(tgen, topo, dut="r2", peer="r3", vrf="RED")
    step("verifying the prefix count incrementing or not ")
    isIPv4prefix_incremented = False
    isIPv6prefix_incremented = False
    if snapshot1["ipv4_count"] <= snapshot2["ipv4_count"]:
        isIPv4prefix_incremented = True
    if snapshot1["ipv6_count"] <= snapshot2["ipv6_count"]:
        isIPv6prefix_incremented = True

    assert (
        isIPv4prefix_incremented is True
    ), "Testcase {} : Failed Error: IPV4 Prefix is not incremented on receiveing ".format(
        tc_name
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
