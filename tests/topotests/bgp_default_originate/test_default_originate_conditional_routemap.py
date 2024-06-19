#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
#                       Shreenidhi A R <rshreenidhi@vmware.com>
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#
"""
Following scenerios are covered.
1. When there is change in route-map policy associated with default-originate, changes does not reflect.
2. When route-map associated with default-originate is deleted, default route doesn't get withdrawn
3. Update message is not being sent when only route-map is removed from the default-originate config.
4. SNT counter gets incremented on change of every policy associated with default-originate
5. Route-map with multiple match clauses causes inconsistencies with default-originate.
6. BGP-Default originate behaviour with BGP attributes
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
    get_prefix_count_route,
    modify_as_number,
    verify_bgp_rib,
    get_dut_as_number,
    verify_rib_default_route,
    verify_fib_default_route,
)
from lib.common_config import (
    verify_fib_routes,
    step,
    required_linux_kernel_version,
    create_route_maps,
    interface_status,
    create_prefix_lists,
    get_frr_ipv6_linklocal,
    start_topology,
    write_test_header,
    verify_prefix_lists,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    create_static_routes,
    check_router_status,
    delete_route_maps,
)

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers

# Global variables
topo = None
NETWORK1_1 = {"ipv4": "198.51.1.1/32", "ipv6": "2001:DB8::1:1/128"}
DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}


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
    ADDR_TYPES = check_address_types()
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

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


def test_default_originate_delete_conditional_routemap(request):
    """
    "scenerio covered":
    1. When there is change in route-map policy associated with default-originate, changes does not reflect.
    2. When route-map associated with default-originate is deleted, default route doesn't get withdrawn
    3. Update message is not being sent when only route-map is removed from the default-originate config.
    4. SNT counter gets incremented on change of every policy associated with default-originate
    5. Route-map with multiple match clauses causes inconsistencies with default-originate.
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    global topo
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    step("Configure IPv4 and IPv6 , IBGP neighbor between R1 and R2")
    step("Configure IPv4 and IPv6 , EBGP neighbor between R1 and R0")
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
                "local_as": 2000,
            }
        },
        "r4": {
            "bgp": {
                "local_as": 3000,
            }
        },
    }
    result = modify_as_number(tgen, topo, input_dict)
    try:
        assert result is True
    except AssertionError:
        logger.info("Expected behaviour: {}".format(result))
        logger.info("BGP config is not created because of invalid ASNs")

    step("After changing the BGP remote as , Verify the BGP Convergence")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert (
        BGP_CONVERGENCE is True
    ), "Complete convergence is expected after changing ASN ....! ERROR :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Configure 1 IPv4 and 1 IPv6 Static route on R0 with next-hop as Null0")
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
        ), "Testcase {} : Failed to configure the static route  \n Error: {}".format(
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
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r0", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : routes {}  not found in R0 FIB  \n Error: {}".format(
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
    ), "Testcase {} : Failed to configure redistribute  configuration....! \n Error: {}".format(
        tc_name, result
    )

    step("verify IPv4 and IPv6 static route are received on R1")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r0": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r1", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed... Routes {}  expected in r1 FIB after configuring the redistribute config on R0 \n Error: {}".format(
            tc_name, static_routes_input, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", static_routes_input)
        assert (
            result is True
        ), "Testcase {} : Failed... Routes {}  expected in r1 RIB after configuring the redistribute config on R0\n Error: {}".format(
            tc_name, static_routes_input, result
        )

    step(
        "Configure IPv4 prefix-list 'Pv4' and and IPv6 prefix-list 'Pv6' on R1 to match BGP route Sv41, IPv6 route Sv61 permit "
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
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv6"],
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
        "Configure IPV4 and IPv6 route-map (RMv4 and RMv6) matching prefix-list (Pv4 and Pv6) respectively on R1"
    )
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                        "set": {
                            "path": {
                                "as_num": "5555",
                                "as_action": "prepend",
                            }
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "Pv6"}},
                        "set": {
                            "path": {
                                "as_num": "5555",
                                "as_action": "prepend",
                            }
                        },
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

    step(
        "After configuring default-originate command , verify default  routes are advertised on R2 "
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        metric=0,
        expected_aspath="5555",
    )
    assert (
        result is True
    ), "Testcase {} : Failed to configure the default originate \n Error: {}".format(
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
    assert (
        result is True
    ), "Testcase {} : Failed to configure the default originate \n Error: {}".format(
        tc_name, result
    )

    step("Changing the as-path  policy of the existing route-map")
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                        "set": {
                            "path": {
                                "as_num": "6666",
                                "as_action": "prepend",
                            }
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "Pv6"}},
                        "set": {
                            "path": {
                                "as_num": "6666",
                                "as_action": "prepend",
                            }
                        },
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
        "Verify prefix sent count on R1 towards R2 \n Send count shoud not be incremented on change of existing (AS-path) policy "
    )
    snapshot = get_prefix_count_route(
        tgen, topo, dut="r1", peer="r2", link="r1", sent=True, received=False
    )

    ipv4_prefix_count = False
    ipv6_prefix_count = False
    if snapshot["ipv4_count"] == 2:
        ipv4_prefix_count = True
    if snapshot["ipv6_count"] == 2:
        ipv6_prefix_count = True

    assert (
        ipv4_prefix_count is True
    ), "Testcase {} : Failed Error: Expected sent Prefix is 2 but obtained {} ".format(
        tc_name, ipv4_prefix_count
    )
    assert (
        ipv6_prefix_count is True
    ), "Testcase {} : Failed Error: Expected sent Prefix is 2 but obtained {} ".format(
        tc_name, ipv6_prefix_count
    )

    step(
        "After changing the as-path policy verify  the  new policy is advertised to router  R2"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        metric=0,
        expected_aspath="6666",
    )
    assert (
        result is True
    ), "Testcase {} : Default route with expected attributes is not found in BGP RIB  \n Error: {}".format(
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
    assert (
        result is True
    ), "Testcase {} : Default route with expected attributes is not found in BGP FIB  \n Error: {}".format(
        tc_name, result
    )

    step("Remove the as-path policy from the route-map")
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                        "set": {
                            "path": {
                                "as_num": "6666",
                                "as_action": "prepend",
                                "delete": True,
                            }
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "Pv6"}},
                        "set": {
                            "path": {
                                "as_num": "6666",
                                "as_action": "prepend",
                                "delete": True,
                            }
                        },
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
        "After removing the  route policy (AS-Path) verify that as-path is removed in r2 "
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
    )
    assert result is True, "Testcase {} : Failed ... !  \n Error: {}".format(
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
    assert result is True, "Testcase {} : Failed .... !\n Error: {}".format(
        tc_name, result
    )

    step("Delete the route-map ")

    delete_routemap = {"r1": {"route_maps": ["RMv4", "RMv6"]}}
    result = delete_route_maps(tgen, delete_routemap)
    assert (
        result is True
    ), "Testcase {} : Failed  to delete the route-map\n Error: {}".format(
        tc_name, result
    )

    step(
        "After deleting route-map , verify  the default route  in FIB and RIB are removed "
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        metric=0,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : After removing the route-map the default-route is not removed from R2 RIB\n Error: {}".format(
        tc_name, result
    )

    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} :  After removing the route-map the default-route is not removed from R2 FIB \n Error: {}".format(
        tc_name, result
    )

    step("Create route-map with with sequnce number 10 ")
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                        "set": {
                            "path": {
                                "as_num": "9999",
                                "as_action": "prepend",
                            }
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "match": {"ipv6": {"prefix_lists": "Pv6"}},
                        "set": {
                            "path": {
                                "as_num": "9999",
                                "as_action": "prepend",
                            }
                        },
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
        "After Configuring the route-map the dut is expected to receive the  route policy (as-path) as 99999"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        metric=0,
        expected_aspath="9999",
    )
    assert result is True, "Testcase {} : Failed...!   \n Error: {}".format(
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
    assert result is True, "Testcase {} : Failed ...!\n Error: {}".format(
        tc_name, result
    )

    step("Create another route-map with seq number less than the previous i. <10 ")
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "5",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                        "set": {
                            "path": {
                                "as_num": "7777",
                                "as_action": "prepend",
                            }
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "5",
                        "match": {"ipv6": {"prefix_lists": "Pv6"}},
                        "set": {
                            "path": {
                                "as_num": "7777",
                                "as_action": "prepend",
                            }
                        },
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
        "On creating new route-map  the route-map with lower seq id should be considered "
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R1,
        metric=0,
        expected_aspath="7777",
    )
    assert (
        result is True
    ), "Testcase {} : Route-map with lowest prefix is not considered  \n Error: {}".format(
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
    assert (
        result is True
    ), "Testcase {} :  Route-map with lowest prefix is not considered   \n Error: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)


def test_verify_default_originate_after_BGP_attributes_p1(request):
    """
    "Verify different BGP attributes with default-originate route "
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    global topo
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
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
        "Configure one IPv4 and one IPv6, Static route on R4 with next-hop as Null0 IPv4 route Sv41, IPv6 route Sv61 "
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
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
    step("Verify IPv4 and IPv6 static routes configured on R4 in FIB")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
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
        "Configure redistribute static knob on R4 , for R4 to R3 neighbor for IPv4 and IPv6 address family "
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify After configuring redistribute static , verify route received in BGP table of R3"
    )
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
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    NOTE = """Configure 2  IPv4 prefix-list Pv41 Pv42 and and 2 IPv6 prefix-list Pv61 Pv62 on R3 to match BGP IPv4 route Sv41, 200.1.1.1/24 , IPv6 route Sv61 and 200::1/64"""
    step(NOTE)
    input_dict_3 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "Pv41": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv4"],
                            "action": "permit",
                        }
                    ],
                    "Pv42": [
                        {"seqid": "1", "network": "200.1.1.1/24", "action": "permit"}
                    ],
                },
                "ipv6": {
                    "Pv61": [
                        {
                            "seqid": "1",
                            "network": NETWORK1_1["ipv6"],
                            "action": "permit",
                        }
                    ],
                    "Pv62": [
                        {"seqid": " 1", "network": "200::1/64", "action": "permit"}
                    ],
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify IPv4 and IPv6 Prefix list got configured on R3")
    input_dict = {"r3": {"prefix_lists": ["Pv41", "Pv61", "Pv42", "Pv62"]}}
    result = verify_prefix_lists(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure 2 sequence of route-map for IPv4 seq1 permit Pv41 and seq2 permit Pv42 and for IPv6 seq1 permit Pv61 , seq2 permit Pv62 on R3"
    )
    input_dict_3 = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv41"}},
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "match": {"ipv4": {"prefix_lists": "Pv42"}},
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "Pv61"}},
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "match": {"ipv6": {"prefix_lists": "Pv62"}},
                    },
                ],
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Apply on route-map seq1 set as-path prepend to 200 and route-map seq2 set  as-path prepend to 300 for IPv4 and IPv6 route-map "
    )
    route_map = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "path": {
                                "as_num": "200",
                                "as_action": "prepend",
                            }
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "path": {
                                "as_num": "300",
                                "as_action": "prepend",
                            }
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "path": {
                                "as_num": "200",
                                "as_action": "prepend",
                            }
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "path": {
                                "as_num": "300",
                                "as_action": "prepend",
                            }
                        },
                    },
                ],
            }
        }
    }

    result = create_route_maps(tgen, route_map)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        " Configure default-originate with IPv4 and IPv6 route-map on R3 for R3-R2 IPv4 and IPv6 BGP neighbor"
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify IPv4 and IPv6 default route received on R2 with both the AS path on R2"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        metric=0,
        expected_aspath="4000 200",
    )

    step(
        "Modify AS prepend path adding one more value 500 in route-map sequence 1 and 600 for route-map sequence 2 for IPv4 and IPv6 route-map"
    )
    route_map = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "path": {
                                "as_num": "500",
                                "as_action": "prepend",
                            }
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "path": {
                                "as_num": "600",
                                "as_action": "prepend",
                            }
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "path": {
                                "as_num": "500",
                                "as_action": "prepend",
                            }
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "path": {
                                "as_num": "600",
                                "as_action": "prepend",
                            }
                        },
                    },
                ],
            }
        }
    }

    result = create_route_maps(tgen, route_map)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("As path 500 added to IPv4 and IPv6 default -originate route received on R2")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        metric=0,
        expected_aspath="4000 500",
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Apply on route-map seq1 set metric value to  70 and route-map seq2 set  metric 80 IPv4 and IPv6 route-map"
    )
    route_map = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "metric": 70,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "metric": 80,
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "metric": 70,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "metric": 80,
                        },
                    },
                ],
            }
        }
    }

    result = create_route_maps(tgen, route_map)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify Configured metric value received on R2 along with as-path for IPv4 and IPv6 default routes "
    )

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        metric=70,
        expected_aspath="4000 500",
    )

    step(
        "Modify route-map seq1 configure metric 50 and route-map seq2 configure metric 100 IPv4 and IPv6 route-map "
    )
    route_map = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "metric": 50,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "metric": 100,
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "metric": 50,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "metric": 100,
                        },
                    },
                ],
            }
        }
    }

    result = create_route_maps(tgen, route_map)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify Configured metric value received on R2 along with as-path for IPv4 and IPv6 default routes "
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        metric=50,
        expected_aspath="4000 500",
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Delete AS-prepend  from IP4 and IPv6 route-map configured on R3 ")
    route_map = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "path": {
                                "as_num": "500",
                                "as_action": "prepend",
                                "delete": True,
                            },
                            "delete": True,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "path": {
                                "as_num": "600",
                                "as_action": "prepend",
                                "delete": True,
                            },
                            "delete": True,
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "path": {
                                "as_num": "500",
                                "as_action": "prepend",
                                "delete": True,
                            },
                            "delete": True,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "path": {
                                "as_num": "600",
                                "as_action": "prepend",
                                "delete": True,
                            },
                            "delete": True,
                        },
                    },
                ],
            }
        }
    }

    result = create_route_maps(tgen, route_map)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify AS-prepend is deleted from default originate route and metric value only present on R2 for IPv4 and IPv6 default routes "
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        metric=50,
        expected_aspath="4000",
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Delete metric value  from IP4 and IPv6 route-map configured on R3 ")
    route_map = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {"metric": 50, "delete": True},
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {"metric": 100, "delete": True},
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {"metric": 50, "delete": True},
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {"metric": 100, "delete": True},
                    },
                ],
            }
        }
    }

    result = create_route_maps(tgen, route_map)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify Metric value deleted from IPv4 and IPv6 default route on R2 ,verify  default routes "
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        metric=0,
        expected_aspath="4000",
    )

    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step("Change  IPv4 and IPv6 , EBGP to IBGP neighbor between R3 and R2")
    step("Change IPv4 and IPv6 IBGP to EBGP neighbor between R3 and R4")
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
                "local_as": 1111,
            }
        },
        "r3": {
            "bgp": {
                "local_as": 1111,
            }
        },
        "r4": {
            "bgp": {
                "local_as": 5555,
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
        "Configure one IPv4 and one IPv6, Static route on R4 with next-hop as Null0 IPv4 route Sv41, IPv6 route Sv61 "
    )
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
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
    step("Verify IPv4 and IPv6 static routes configured on R4 in FIB")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
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
        "Configure redistribute static knob on R4 , for R4 to R3 neighbor for IPv4 and IPv6 address family "
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify After configuring redistribute static , verify route received in BGP table of R3"
    )
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
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step(
        " Configure default-originate with IPv4 and IPv6 route-map on R3 for R3-R2 IPv4 and IPv6 BGP neighbor"
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify IPv4 and IPv6 default route received on R2 with both the AS path on R2"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Configure local -preference to 50 on IPv4 and IPv6 route map seq1 and 60 on seq2"
    )
    route_map = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "locPrf": 50,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "locPrf": 60,
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "locPrf": 50,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "locPrf": 60,
                        },
                    },
                ],
            }
        }
    }

    result = create_route_maps(tgen, route_map)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify Configured metric value received on R2 along with as-path for IPv4 and IPv6 default routes "
    )

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        locPrf=50,
    )

    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Modify local preference value to 150  on IPv4 and IPv6 route map seq1 and 160 on seq2"
    )
    route_map = {
        "r3": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "locPrf": 150,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "locPrf": 160,
                        },
                    },
                ],
                "RMv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {
                            "locPrf": 150,
                        },
                    },
                    {
                        "action": "permit",
                        "seq_id": "2",
                        "set": {
                            "locPrf": 160,
                        },
                    },
                ],
            }
        }
    }

    result = create_route_maps(tgen, route_map)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify Modified local-preference  value received on R2  for IPv4 and IPv6 default routes "
    )

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        locPrf=150,
    )

    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    # updating the topology with the updated AS-Number to avoid conflict in con configuring the AS
    updated_topo = topo
    updated_topo["routers"]["r0"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r0")
    updated_topo["routers"]["r1"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r1")
    updated_topo["routers"]["r2"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r2")
    updated_topo["routers"]["r3"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r3")
    updated_topo["routers"]["r4"]["bgp"]["local_as"] = get_dut_as_number(tgen, "r4")

    step(
        "Shut IPv4/IPv6 BGP neighbor from R4 ( R4-R3) using 'neighbor x.x.x.x shut' command "
    )
    local_as = get_dut_as_number(tgen, dut="r4")
    shut_neighbor = {
        "r4": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r4": {"shutdown": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r4": {"shutdown": True}}}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, updated_topo, shut_neighbor)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    interface = topo["routers"]["r3"]["links"]["r4"]["interface"]
    input_dict = {"r1": {"interface_list": [interface], "status": "down"}}

    result = interface_status(tgen, topo, input_dict)
    assert (
        result is True
    ), "Testcase {} : Shut down the interface failed ! \n Error: {}".format(
        tc_name, result
    )

    step("After shutting the interface verify the BGP convergence")
    result = verify_bgp_convergence(tgen, topo, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n After shutting Down BGP convergence should Fail and return False \n Error: {}".format(
        tc_name, result
    )

    step("verify default route deleted from R2 ")
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
    ), "Testcase {} : Failed \n Error: After Shut down interface the default route is NOT expected but found in RIB -> {}".format(
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
    ), "Testcase {} : Failed \n Error:  After Shut down interface the default route is NOT expected but found in FIB -> {}".format(
        tc_name, result
    )

    step(
        "no Shut IPv4/IPv6 BGP neighbor from R4 ( R4-R3) using 'neighbor x.x.x.x shut' command "
    )
    local_as = get_dut_as_number(tgen, dut="r4")
    shut_neighbor = {
        "r4": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r4": {"shutdown": False}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r4": {"shutdown": False}}}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, updated_topo, shut_neighbor)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    interface = topo["routers"]["r3"]["links"]["r4"]["interface"]
    input_dict = {"r1": {"interface_list": [interface], "status": "up"}}

    result = interface_status(tgen, topo, input_dict)
    assert (
        result is True
    ), "Testcase {} : Bring up interface failed ! \n Error: {}".format(tc_name, result)

    step("After no shutting the interface verify the BGP convergence")
    result = verify_bgp_convergence(tgen, topo, expected=True)
    assert (
        result is True
    ), "Testcase {} : Failed \n After shutting Down BGP convergence should Fail and return False \n Error: {}".format(
        tc_name, result
    )

    step("After no shut neighbor , verify default route relearn on R2")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=True,
    )
    assert (
        result is True
    ), "Testcase {} : Failed \n Error: After no Shut down interface the default route is  expected but found in RIB -> {}".format(
        tc_name, result
    )

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
    ), "Testcase {} : Failed \n Error:  After Shut down interface the default route is  expected but found in FIB -> {}".format(
        tc_name, result
    )

    step("Remove IPv4/IPv6 static route configure on R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "delete": True,
                    }
                ]
            }
        }
        result = create_static_routes(tgen, static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step("Verify IPv4 and IPv6 static routes removed on R4 in FIB")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = verify_fib_routes(
            tgen, addr_type, "r4", static_routes_input, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_bgp_rib(
            tgen, addr_type, "r4", static_routes_input, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("After removing static route  , verify default route removed on R2")
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
    ), "Testcase {} : Failed \n Error: After removing static  the default route is NOT expected but found in RIB -> {}".format(
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
    ), "Testcase {} : Failed \n Error:  After removing static the default route is NOT expected but found in FIB -> {}".format(
        tc_name, result
    )

    step("Configuring the static route back in r4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
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
    step("Verify IPv4 and IPv6 static routes configured on R4 in FIB")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r4": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }
        result = verify_fib_routes(
            tgen, addr_type, "r4", static_routes_input, expected=True
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_bgp_rib(
            tgen, addr_type, "r4", static_routes_input, expected=True
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("After adding static route back  , verify default route learned  on R2")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=True,
    )
    assert (
        result is True
    ), "Testcase {} : Failed \n Error: After removing static  the default route is  expected but found in RIB -> {}".format(
        tc_name, result
    )

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
    ), "Testcase {} : Failed \n Error:  After removing static  the default route is  expected but found in FIB -> {}".format(
        tc_name, result
    )

    step("Deactivate IPv4 and IPv6 neighbor configured from R4 ( R4-R3)")

    configure_bgp_on_r1 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r4": {"deactivate": "ipv4"}}}
                            }
                        },
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r4": {"deactivate": "ipv6"}}}
                            }
                        },
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, updated_topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("After deactivating the BGP neighbor   , verify default route removed on R2")
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
    ), "Testcase {} : Failed \n Error: After Deactivating the BGP neighbor the default route is NOT expected but found in RIB -> {}".format(
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
    ), "Testcase {} : Failed \n Error: After Deactivating the BGP neighbor  the default route is NOT expected but found in FIB -> {}".format(
        tc_name, result
    )

    step("Activate IPv4 and IPv6 neighbor configured from R4 ( R4-R3)")

    configure_bgp_on_r1 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r4": {"activate": "ipv4"}}}
                            }
                        },
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r4": {"activate": "ipv6"}}}
                            }
                        },
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, updated_topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp convergence.")
    bgp_convergence = verify_bgp_convergence(tgen, updated_topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )
    step("After Activating the BGP neighbor   , verify default route learned on R2")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
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
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_R3,
        expected=True,
    )
    assert (
        result is True
    ), "Testcase {} : Failed \n Error:  After Deactivating the BGP neighbor the default route is   expected but found in FIB -> {}".format(
        tc_name, result
    )
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
