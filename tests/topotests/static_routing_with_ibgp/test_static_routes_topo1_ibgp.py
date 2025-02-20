#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#
"""

    -Verify static route ECMP functionality with 2 next hop

    -Verify static route functionality with 2 next hop and different AD
    value

    -Verify RIB status when same route advertise via BGP and static route

"""
import sys
import time
import os
import pytest
import platform

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
    create_static_routes,
    check_address_types,
    step,
    shutdown_bringup_interface,
    stop_router,
    start_router,
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, create_router_bgp, verify_bgp_rib
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()
NETWORK = {"ipv4": ["11.0.20.1/32", "11.0.20.2/32"], "ipv6": ["2::1/128", "2::2/128"]}
NETWORK2 = {"ipv4": "11.0.20.1/32", "ipv6": "2::1/128"}

PREFIX1 = {"ipv4": "110.0.20.1/32", "ipv6": "20::1/128"}


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
    json_file = "{}/static_routes_topo1_ibgp.json".format(CWD)
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
    global BGP_CONVERGENCE
    global ADDR_TYPES

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # Api call verify whether BGP is converged
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Running setup_module() done")


def teardown_module():
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


def populate_nh():
    NEXT_HOP_IP = {
        "nh1": {
            "ipv4": topo["routers"]["r1"]["links"]["r2-link0"]["ipv4"].split("/")[0],
            "ipv6": topo["routers"]["r1"]["links"]["r2-link0"]["ipv6"].split("/")[0],
        },
        "nh2": {
            "ipv4": topo["routers"]["r1"]["links"]["r2-link1"]["ipv4"].split("/")[0],
            "ipv6": topo["routers"]["r1"]["links"]["r2-link1"]["ipv6"].split("/")[0],
        },
    }
    return NEXT_HOP_IP


#####################################################
#
#   Tests starting
#
#####################################################


def test_static_route_2nh_p0_tc_1_ibgp(request):
    """
    Verify static route ECMP functionality with 2 next hop

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    NEXT_HOP_IP = populate_nh()

    step(
        "Configure IPv4 static route (10.1.1.1) in R2 with next hop N1"
        "(28.1.1.2 ) and N2 (29.1.1.2) , Static route next-hop present on"
        "R1"
    )
    step("ex :- ip route 10.1.1.1/24 28.1.1.2 & ip route 10.1.1.1/24 29.1.1.1")
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                    },
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                    },
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "On R2, static route installed in RIB using show ip route"
            " with 2 ECMP next hop "
        )
        nh = [NEXT_HOP_IP["nh1"][addr_type], NEXT_HOP_IP["nh2"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        step("Configure IBGP IPv4 peering between R2 and R3 router.")
        step("Configure redistribute static in BGP on R2 router")

        input_dict_2 = {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Remove the static route configured with nexthop N1 from running config")
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "delete": True,
                    }
                ]
            }
        }
        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "On R2, after removing the static route with N1 , "
            "route become active with nexthop N2 and vice versa."
        )
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are  still present in RIB".format(
            tc_name
        )

        nh = [NEXT_HOP_IP["nh2"][addr_type]]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        step("Configure the static route with nexthop N1")

        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                    }
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Remove the static route configured with nexthop N2 from running config")

        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                        "delete": True,
                    }
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "On R2, after removing the static route with N2 , "
            "route become active with nexthop N1 and vice versa."
        )
        nh = NEXT_HOP_IP["nh2"][addr_type]
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are  still present in RIB".format(
            tc_name
        )

        nh = [NEXT_HOP_IP["nh1"][addr_type]]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        step("Configure the static route with nexthop N2")
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                    }
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Shut nexthop interface N1")
        intf = topo["routers"]["r2"]["links"]["r1-link0"]["interface"]

        shutdown_bringup_interface(tgen, dut, intf, False)

        step("Only one the nexthops should be active in RIB.")

        nh = NEXT_HOP_IP["nh2"][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are  still present in RIB".format(
            tc_name
        )

        dut = "r3"
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Route is  still present in RIB".format(
            tc_name
        )

        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            protocol=protocol,
            next_hop=nh,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Route is  still present in RIB".format(
            tc_name
        )

        dut = "r2"
        nh = [NEXT_HOP_IP["nh2"][addr_type]]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        dut = "r3"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_4)
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Route is  missing in RIB".format(tc_name)

        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, protocol=protocol, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Route is  still present in RIB".format(
            tc_name
        )

        dut = "r2"
        step("No shut the nexthop interface N1")
        shutdown_bringup_interface(tgen, dut, intf, True)

        step(
            "after shut of nexthop N1 , route become active "
            "with nexthop N2 and vice versa."
        )
        nh = [NEXT_HOP_IP["nh1"][addr_type], NEXT_HOP_IP["nh2"][addr_type]]

        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        step("Shut nexthop interface N2")
        intf = topo["routers"]["r2"]["links"]["r1-link1"]["interface"]
        dut = "r2"
        shutdown_bringup_interface(tgen, dut, intf, False)

        step(
            " after shut of nexthop N1 , route become active with "
            "nexthop N2 and vice versa."
        )
        nh = NEXT_HOP_IP["nh2"][addr_type]

        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are  still present in RIB".format(
            tc_name
        )

        nh = [NEXT_HOP_IP["nh1"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        dut = "r3"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_4)
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Route is  missing in RIB".format(tc_name)

        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, protocol=protocol, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Route is  still present in RIB".format(
            tc_name
        )

        step("No shut nexthop interface N2")
        dut = "r2"
        shutdown_bringup_interface(tgen, dut, intf, True)

        step(
            "after shut of nexthop N1 , route become active "
            "with nexthop N2 and vice versa."
        )
        nh = [NEXT_HOP_IP["nh1"][addr_type], NEXT_HOP_IP["nh2"][addr_type]]

        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        dut = "r3"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_4)
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Route is  missing in RIB".format(tc_name)

        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, protocol=protocol, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Route is  still present in RIB".format(
            tc_name
        )

        step("Reload the FRR router")
        # stop/start -> restart FRR router and verify
        stop_router(tgen, "r2")

        start_router(tgen, "r2")

        dut = "r2"
        step(
            "After reload of FRR router , static route installed"
            " in RIB and FIB properly ."
        )
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        dut = "r3"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_4)
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Route is  still present in RIB".format(
            tc_name
        )

        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, protocol=protocol, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Route is  still present in RIB".format(
            tc_name
        )

    write_test_footer(tc_name)


def test_static_route_2nh_admin_dist_p0_tc_2_ibgp(request):
    """
    Verify static route functionality with 2 next hop & different AD value

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    NEXT_HOP_IP = populate_nh()
    step(
        "Configure IPv4 static route (10.1.1.1) in R2 with next hop N1"
        "(28.1.1.2 ) AD 10 and N2 (29.1.1.2) AD 20 , Static route next-hop"
        "present on R1 \n ex :- ip route 10.1.1.1/24 28.1.1.2 10 & "
        "ip route 10.1.1.1/24 29.1.1.2 20"
    )

    reset_config_on_routers(tgen)
    NEXT_HOP_IP = populate_nh()
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    },
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                        "admin_distance": 20,
                    },
                ]
            }
        }
        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "On R2, static route installed in RIB using "
            "show ip route with 2 next hop , lowest AD nexthop is active "
        )
        rte1_nh1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        nh = [NEXT_HOP_IP["nh1"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen, addr_type, dut, rte1_nh1, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are missing in RIB".format(tc_name)

        rte2_nh2 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                        "admin_distance": 20,
                    }
                ]
            }
        }
        nh = [NEXT_HOP_IP["nh2"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte2_nh2,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are not active in RIB".format(tc_name)

        step("Configure IBGP IPv4 peering between R2 and R3 router.")
        step("Explicit route is added in R3 for R2 nexthop rechability")
        rt3_rtes = {
            "r3": {
                "static_routes": [
                    {
                        "network": NEXT_HOP_IP["nh1"][addr_type] + "/32",
                        "next_hop": topo["routers"]["r2"]["links"]["r3"][addr_type],
                    },
                    {
                        "network": NEXT_HOP_IP["nh2"][addr_type] + "/32",
                        "next_hop": topo["routers"]["r2"]["links"]["r3"][addr_type],
                    },
                ]
            }
        }
        logger.info("Configure static routes")
        result = create_static_routes(tgen, rt3_rtes)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        step("Configure redistribute static in BGP on R2 router")

        input_dict_2 = {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Remove the static route configured with nexthop N1 from running config")
        rt1_nh1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                        "delete": True,
                    }
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, rt1_nh1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "On R2, after removing the static route with N1 , "
            "route become active with nexthop N2 and vice versa."
        )
        rte1_nh1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        nh = [NEXT_HOP_IP["nh1"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte1_nh1,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are missing in RIB".format(tc_name)

        rte2_nh2 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                        "admin_distance": 20,
                    }
                ]
            }
        }
        nh = [NEXT_HOP_IP["nh2"][addr_type]]
        result = verify_rib(
            tgen, addr_type, dut, rte2_nh2, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are not active in RIB".format(tc_name)

        step("Configure the static route with nexthop N1")
        rte1_nh1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        logger.info("Configure static routes")
        result = create_static_routes(tgen, rte1_nh1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Remove the static route configured with nexthop N2 from running config")
        rte2_nh2 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                        "admin_distance": 20,
                        "delete": True,
                    }
                ]
            }
        }
        logger.info("Configure static routes")
        result = create_static_routes(tgen, rte2_nh2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "On R2, after removing the static route with N2 , "
            "route become active with nexthop N1 and vice versa."
        )
        nh = NEXT_HOP_IP["nh2"][addr_type]
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte2_nh2,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are  still present in RIB".format(
            tc_name
        )

        nh = [NEXT_HOP_IP["nh1"][addr_type]]
        result = verify_rib(
            tgen, addr_type, dut, rte1_nh1, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        step("Configure the static route with nexthop N2")
        rte2_nh2 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                        "admin_distance": 20,
                    }
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, rte2_nh2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Shut nexthop interface N1")
        intf = topo["routers"]["r2"]["links"]["r1-link0"]["interface"]

        shutdown_bringup_interface(tgen, dut, intf, False)

        step("after shut of nexthop N1 , route become active with nexthop N2")

        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte1_nh1,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are  still present in RIB".format(
            tc_name
        )

        nh = [NEXT_HOP_IP["nh2"][addr_type]]
        result = verify_rib(
            tgen, addr_type, dut, rte2_nh2, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        step("No shut the nexthop interface N1")
        shutdown_bringup_interface(tgen, dut, intf, True)

        step(
            "after shut of nexthop N1 , route become active "
            "with nexthop N2 and vice versa."
        )
        nh = [NEXT_HOP_IP["nh1"][addr_type]]

        result = verify_rib(
            tgen, addr_type, dut, rte1_nh1, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        step("Shut nexthop interface N2")
        intf = topo["routers"]["r2"]["links"]["r1-link1"]["interface"]

        shutdown_bringup_interface(tgen, dut, intf, False)

        step(
            " after shut of nexthop N1 , route become active with "
            "nexthop N2 and vice versa."
        )
        nh = NEXT_HOP_IP["nh2"][addr_type]

        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte2_nh2,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are  still present in RIB".format(
            tc_name
        )

        nh = [NEXT_HOP_IP["nh1"][addr_type]]
        result = verify_rib(
            tgen, addr_type, dut, rte1_nh1, next_hop=nh, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB".format(tc_name)

        step("No shut nexthop interface N2")
        shutdown_bringup_interface(tgen, dut, intf, True)

        step(
            "after shut of nexthop N1 , route become active "
            "with nexthop N2 and vice versa."
        )
        rte1_nh1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        nh = [NEXT_HOP_IP["nh1"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen, addr_type, dut, rte1_nh1, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are missing in RIB".format(tc_name)

        rte2_nh2 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                        "admin_distance": 20,
                    }
                ]
            }
        }
        nh = [NEXT_HOP_IP["nh2"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte2_nh2,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are not active in RIB".format(tc_name)

        dut = "r3"
        protocol = "bgp"

        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte2_nh2,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are not active in RIB".format(tc_name)

        dut = "r2"
        step("Reload the FRR router")
        # stop/start -> restart FRR router and verify
        stop_router(tgen, "r2")

        start_router(tgen, "r2")

        step(
            "After reload of FRR router , static route installed"
            " in RIB and FIB properly ."
        )
        rte1_nh1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        nh = [NEXT_HOP_IP["nh1"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen, addr_type, dut, rte1_nh1, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are missing in RIB".format(tc_name)

        dut = "r3"
        protocol = "bgp"
        result = verify_bgp_rib(tgen, addr_type, dut, rte1_nh1, next_hop=nh)
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are missing in RIB".format(tc_name)

        rte2_nh2 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2[addr_type],
                        "next_hop": NEXT_HOP_IP["nh2"][addr_type],
                        "admin_distance": 20,
                    }
                ]
            }
        }
        nh = [NEXT_HOP_IP["nh2"][addr_type]]
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte2_nh2,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are not active in RIB".format(tc_name)

        dut = "r3"
        protocol = "bgp"
        result = verify_bgp_rib(tgen, addr_type, dut, rte2_nh2, next_hop=nh)
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are not active in RIB".format(tc_name)

        result = verify_rib(
            tgen,
            addr_type,
            dut,
            rte2_nh2,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError:  routes are not active in RIB".format(tc_name)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
