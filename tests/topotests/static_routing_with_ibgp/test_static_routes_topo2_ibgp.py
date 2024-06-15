#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#


"""
    -Verify static route functionality with 8 next hop different AD value
    and BGP ECMP

    -Verify 8 static route functionality with 8 next hop different AD

    -Verify static route with 8 next hop with different AD value and 8
    EBGP neighbors

    -Verify static route with 8 next hop with different AD value and 8
    IBGP neighbors

    -Delete the static route and verify the RIB and FIB state

    -Verify 8 static route functionality with 8 ECMP next hop
"""
import sys
import time
import os
import pytest
import platform
import random

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))
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
    shutdown_bringup_interface,
    stop_router,
    start_router,
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, create_router_bgp, verify_bgp_rib
from lib.topojson import build_config_from_json
from lib.topotest import version_cmp

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()
NETWORK = {
    "ipv4": [
        "11.0.20.1/32",
        "11.0.20.2/32",
        "11.0.20.3/32",
        "11.0.20.4/32",
        "11.0.20.5/32",
        "11.0.20.6/32",
        "11.0.20.7/32",
        "11.0.20.8/32",
    ],
    "ipv6": [
        "2::1/128",
        "2::2/128",
        "2::3/128",
        "2::4/128",
        "2::5/128",
        "2::6/128",
        "2::7/128",
        "2::8/128",
    ],
}
PREFIX1 = {"ipv4": "110.0.20.1/32", "ipv6": "20::1/128"}
PREFIX2 = {"ipv4": "110.0.20.2/32", "ipv6": "20::2/128"}
NEXT_HOP_IP = []
topo_diag = """
          Please view in a fixed-width font such as Courier.
    +------+              +------+              +------+
    |      +--------------+      +--------------+      |
    |      |              |      |              |      |
    |  R1  +---8 links----+ R2   +---8 links----+ R3   |
    |      |              |      |              |      |
    |      +--------------+      +--------------+      |
    +------+              +------+              +------+

"""


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
    json_file = "{}/static_routes_topo2_ibgp.json".format(CWD)
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
        "nh3": {
            "ipv4": topo["routers"]["r1"]["links"]["r2-link2"]["ipv4"].split("/")[0],
            "ipv6": topo["routers"]["r1"]["links"]["r2-link2"]["ipv6"].split("/")[0],
        },
        "nh4": {
            "ipv4": topo["routers"]["r1"]["links"]["r2-link3"]["ipv4"].split("/")[0],
            "ipv6": topo["routers"]["r1"]["links"]["r2-link3"]["ipv6"].split("/")[0],
        },
        "nh5": {
            "ipv4": topo["routers"]["r1"]["links"]["r2-link4"]["ipv4"].split("/")[0],
            "ipv6": topo["routers"]["r1"]["links"]["r2-link4"]["ipv6"].split("/")[0],
        },
        "nh6": {
            "ipv4": topo["routers"]["r1"]["links"]["r2-link5"]["ipv4"].split("/")[0],
            "ipv6": topo["routers"]["r1"]["links"]["r2-link5"]["ipv6"].split("/")[0],
        },
        "nh7": {
            "ipv4": topo["routers"]["r1"]["links"]["r2-link6"]["ipv4"].split("/")[0],
            "ipv6": topo["routers"]["r1"]["links"]["r2-link6"]["ipv6"].split("/")[0],
        },
        "nh8": {
            "ipv4": topo["routers"]["r1"]["links"]["r2-link7"]["ipv4"].split("/")[0],
            "ipv6": topo["routers"]["r1"]["links"]["r2-link7"]["ipv6"].split("/")[0],
        },
    }
    return NEXT_HOP_IP


#####################################################
#
#   Tests starting
#
#####################################################


def test_static_rte_with_8ecmp_nh_p1_tc9_ibgp(request):
    """
    Verify 8 static route functionality with 8 ECMP next hop

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    NEXT_HOP_IP = populate_nh()
    step("Configure 8 interfaces / links between R1 and R2")
    step("Configure 8 interfaces / links between R2 and R3")
    step("Configure 8 IBGP IPv4 peering between R2 and R3 router.")
    reset_config_on_routers(tgen)

    step(
        "Configure 8 IPv4 static route in R2 with 8 next hop"
        "N1(21.1.1.2) , N2(22.1.1.2) , N3(23.1.1.2) , N4(24.1.1.2) ,"
        "N5(25.1.1.2) , N6(26.1.1.2) , N7(27.1.1.2) , N8(28.1.1.2) ,"
        "Static route next-hop present on R1"
    )
    nh_all = {}
    for addr_type in ADDR_TYPES:
        # Enable static routes
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, input_dict_4)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
        logger.info("Verifying %s routes on r2", addr_type)
        nh_all[addr_type] = [
            NEXT_HOP_IP["nh1"][addr_type],
            NEXT_HOP_IP["nh2"][addr_type],
            NEXT_HOP_IP["nh3"][addr_type],
            NEXT_HOP_IP["nh4"][addr_type],
            NEXT_HOP_IP["nh5"][addr_type],
            NEXT_HOP_IP["nh6"][addr_type],
            NEXT_HOP_IP["nh7"][addr_type],
            NEXT_HOP_IP["nh8"][addr_type],
        ]

        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh_all[addr_type],
            protocol=protocol,
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

    step("Configure redistribute static in BGP on R2 router")
    for addr_type in ADDR_TYPES:
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

        dut = "r3"
        protocol = "bgp"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_4)
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

    step(
        "Remove the static route configured with nexthop N1 to N8, one"
        "by one from running config"
    )
    dut = "r2"
    protocol = "static"
    step(
        "After removing the static route with N1 to N8 one by one , "
        "verify that entry is removed from RIB and FIB of R3 "
    )
    for addr_type in ADDR_TYPES:
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
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
                "After removing the static route with N1 to N8 one by one , "
                "verify that entry is removed from RIB and FIB of R3 "
            )
            nh = NEXT_HOP_IP["nh" + str(nhp)][addr_type]
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
            ), "Testcase {} : Failed\nError:  routes are  still present in RIB".format(
                tc_name
            )

    step("Configure the static route with nexthop N1 to N8, one by one")
    for addr_type in ADDR_TYPES:
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, input_dict_4)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

            nh = NEXT_HOP_IP["nh" + str(nhp)][addr_type]
            result = verify_rib(
                tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
            )
            assert (
                result is True
            ), "Testcase {} : Failed\nError: Routes are  missing in RIB".format(tc_name)

    protocol = "static"
    step("Random shut of the nexthop interfaces")
    randnum = random.randint(0, 7)
    # Shutdown interface
    dut = "r2"
    step(
        " interface which is about to be shut no shut between r1 and r2 is %s",
        topo["routers"]["r2"]["links"]["r1-link{}".format(randnum)]["interface"],
    )
    intf = topo["routers"]["r2"]["links"]["r1-link{}".format(randnum)]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("Random no shut of the nexthop interfaces")
    # Bringup interface
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "After random shut/no shut of nexthop , only that "
        "nexthop deleted/added from all the routes , other nexthop remain "
        "unchanged"
    )
    dut = "r2"
    protocol = "static"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                    }
                ]
            }
        }
    result = verify_rib(
        tgen,
        addr_type,
        dut,
        input_dict_4,
        next_hop=nh_all[addr_type],
        protocol=protocol,
    )
    assert (
        result is True
    ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

    step("Remove random static route with all the nexthop")
    dut = "r2"
    randnum = random.randint(1, 7)
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh" + str(randnum)][addr_type],
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
            "After delete of random route , that route only got deleted from"
            " RIB/FIB other route are showing properly"
        )
        nh = NEXT_HOP_IP["nh{}".format(randnum)][addr_type]
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
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh" + str(randnum)][addr_type],
                    }
                ]
            }
        }
        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Reload the FRR router")
    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r2")
    start_router(tgen, "r2")

    step(
        "After reload of FRR router , static route "
        "installed in RIB and FIB properly ."
    )
    for addr_type in ADDR_TYPES:
        # Enable static routes
        nhp = 1
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                    }
                ]
            }
        }
        logger.info("Verifying %s routes on r2", addr_type)
        dut = "r2"
        protocol = "static"
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh_all[addr_type],
            protocol=protocol,
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

    step("Remove the redistribute static knob")
    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static", "delete": True}
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
            "After removing the BGP neighbor or redistribute static knob , "
            "verify route got clear from RIB and FIB of R3 routes "
        )
        dut = "r3"
        protocol = "bgp"
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, protocol=protocol, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes are  still present in RIB".format(
            tc_name
        )

    write_test_footer(tc_name)


def test_static_route_8nh_diff_AD_bgp_ecmp_p1_tc6_ibgp(request):
    """
    Verify static route functionality with 8 next hop different AD
    value and BGP ECMP

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure 8 interfaces / links between R1 and R2 ,")
    step("Configure 8 interlaces/links between R2 and R3")
    step(
        "Configure IBGP IPv4 peering over loopback interface between"
        "R2 and R3 router."
    )
    step("Configure redistribute static in BGP on R2 router")
    reset_config_on_routers(tgen)
    NEXT_HOP_IP = populate_nh()
    nh_all = {}
    for addr_type in ADDR_TYPES:
        nh_all[addr_type] = []
        for nhp in range(1, 9):
            nh_all[addr_type].append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])
    step(
        "Configure IPv4 static route in R2 with 8 next hop"
        "N1(21.1.1.2) AD 10, N2(22.1.1.2) AD 20, N3(23.1.1.2) AD 30,"
        "N4(24.1.1.2) AD 40, N5(25.1.1.2) AD 50, N6(26.1.1.2) AD 60,"
        "N7(27.1.1.2) AD 70, N8(28.1.1.2) AD 80, Static route next-hop"
        "present on R1"
    )
    for addr_type in ADDR_TYPES:
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, input_dict_4)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
        logger.info("Verifying %s routes on r2", addr_type)

        step(
            "On R2, static route installed in RIB using "
            "show ip route with 8 next hop , lowest AD nexthop is active"
        )
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        dut = "r2"
        protocol = "static"
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

        nh = []
        for nhp in range(2, 9):
            nh.append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
            retry_timeout=6,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes   are present in RIB".format(tc_name)

    step(
        "Remove the static route configured with nexthop N1 to N8, one"
        "by one from running config"
    )

    for addr_type in ADDR_TYPES:
        # delete static routes
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
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
        "After removing the static route with N1 to N8 one by one , "
        "route become active with next preferred nexthop and nexthop which "
        "got removed is not shown in RIB and FIB"
    )
    result = verify_rib(
        tgen,
        addr_type,
        dut,
        input_dict_4,
        next_hop=nh_all[addr_type],
        protocol=protocol,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \nError: Routes are  still present in RIB".format(tc_name)

    step("Configure the static route with nexthop N1 to N8, one by one")

    for addr_type in ADDR_TYPES:
        # add static routes
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
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
        " After configuring them, route is always active with lowest AD"
        " value and all the nexthop populated in RIB and FIB again"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        dut = "r2"
        protocol = "static"
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)
        nh = []
        for nhp in range(2, 9):
            nh.append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
            retry_timeout=6,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes   are missing in RIB".format(tc_name)

    step("Random shut of the nexthop interfaces")
    randnum = random.randint(0, 7)
    for addr_type in ADDR_TYPES:
        intf = topo["routers"]["r2"]["links"]["r1-link" + str(randnum)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, False)
        nhip = NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type]
        input_dict_5 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type],
                    }
                ]
            }
        }
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_5,
            next_hop=nhip,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n Error: Routes are still present in RIB".format(
            tc_name
        )

    step("Random no shut of the nexthop interfaces")
    for addr_type in ADDR_TYPES:
        intf = topo["routers"]["r2"]["links"]["r1-link" + str(randnum)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, True)
        nhip = NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_5, next_hop=nhip, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \n Error: Routes are missing in RIB".format(tc_name)

    protocol = "bgp"
    # this is next hop reachability route  in r3 as we are using ibgp
    dut = "r3"
    for addr_type in ADDR_TYPES:
        nh_as_rte = NEXT_HOP_IP["nh1"][addr_type] + "/32"
        # add static routes
        nh_static_rte = {
            "r3": {"static_routes": [{"network": nh_as_rte, "next_hop": "Null0"}]}
        }
        logger.info("Configure static routes")
        result = create_static_routes(tgen, nh_static_rte)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "After each interface shut and no shut between R2 -R3 ,verify static"
        "route is present in the RIB & FIB of R3 & R2 RIB/FIB is remain"
        " unchanged"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Error: Routes are missing in RIB".format(tc_name)

    protocol = "static"
    dut = "r2"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {}: Failed \n Error: Routes are missing in RIB".format(tc_name)

    protocol = "bgp"
    dut = "r3"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {}: Failed \n Error: Routes are missing in RIB".format(tc_name)

    step("Reload the FRR router")
    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r2")

    start_router(tgen, "r2")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are still present in RIB".format(
            tc_name
        )

    step("BGP neighbor remove and add")
    for rtr in ["r2", "r3"]:
        if "bgp" in topo["routers"][rtr].keys():
            delete_bgp = {rtr: {"bgp": {"delete": True}}}
            result = create_router_bgp(tgen, topo, delete_bgp)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    create_router_bgp(tgen, topo["routers"])

    NEXT_HOP_IP = populate_nh()
    step("Verify routes are still present after delete and add bgp")
    dut = "r2"
    protocol = "static"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are still present in RIB".format(
            tc_name
        )

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are still present in RIB".format(
            tc_name
        )

    step("Remove the redistribute static knob")
    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static", "delete": True}
                                ]
                            }
                        }
                    }
                }
            }
        }

        logger.info("Remove redistribute static")
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        step("verify that routes are deleted from R3 routing table")

        dut = "r3"
        protocol = "bgp"
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \nError: Routes are"
            " strill present in RIB of R3".format(tc_name)
        )

    write_test_footer(tc_name)


def test_static_route_8nh_diff_AD_ibgp_ecmp_p1_tc7_ibgp(request):
    """
    Verify static route with 8 next hop with different AD value and 8
    IBGP neighbors
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure 8 interfaces / links between R1 and R2")
    step("Configure 8 interlaces/links between R2 and R3")
    step("Configure 8 IBGP IPv4 peering between R2 and R3")

    reset_config_on_routers(tgen)
    NEXT_HOP_IP = populate_nh()

    step("Configure redistribute static in BGP on R2 router")
    for addr_type in ADDR_TYPES:
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

    step(
        "Configure IPv4 static route in R2 with 8 next hop"
        "N1(21.1.1.2) AD 10, N2(22.1.1.2) AD 20, N3(23.1.1.2) AD 30,"
        "N4(24.1.1.2) AD 40, N5(25.1.1.2) AD 50, N6(26.1.1.2) AD 60,"
        "N7(27.1.1.2) AD 70, N8(28.1.1.2) AD 80, Static route next-hop"
        "present on R1"
    )
    nh_all = {}
    for addr_type in ADDR_TYPES:
        nh_all[addr_type] = []
        for nhp in range(1, 9):
            nh_all[addr_type].append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])
    for addr_type in ADDR_TYPES:
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, input_dict_4)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
        logger.info("Verifying %s routes on r2", addr_type)

        step(
            "On R2, static route installed in RIB using "
            "show ip route with 8 next hop , lowest AD nexthop is active"
        )
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        dut = "r2"
        protocol = "static"
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

        nh = []
        for nhp in range(2, 9):
            nh.append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes   are missing in RIB".format(tc_name)

    step(
        "Remove the static route configured with nexthop N1 to N8, one"
        "by one from running config"
    )

    for addr_type in ADDR_TYPES:
        # delete static routes
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
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
        "After removing the static route with N1 to N8 one by one , "
        "route become active with next preferred nexthop and nexthop which "
        "got removed is not shown in RIB and FIB"
    )
    result = verify_rib(
        tgen,
        addr_type,
        dut,
        input_dict_4,
        next_hop=nh_all[addr_type],
        protocol=protocol,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \nError: Routes are  still present in RIB".format(tc_name)

    step("Configure the static route with nexthop N1 to N8, one by one")

    for addr_type in ADDR_TYPES:
        # add static routes
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
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
        " After configuring them, route is always active with lowest AD"
        " value and all the nexthop populated in RIB and FIB again"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        dut = "r2"
        protocol = "static"
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)
        nh = []
        for nhp in range(2, 9):
            nh.append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes   are missing in RIB".format(tc_name)

    step("Random shut of the nexthop interfaces")
    randnum = random.randint(0, 7)
    for addr_type in ADDR_TYPES:
        intf = topo["routers"]["r2"]["links"]["r1-link" + str(randnum)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, False)
        nhip = NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type]
        input_dict_5 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type],
                    }
                ]
            }
        }
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_5,
            next_hop=nhip,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n Error: Routes are still present in RIB".format(
            tc_name
        )

    step("Random no shut of the nexthop interfaces")
    for addr_type in ADDR_TYPES:
        intf = topo["routers"]["r2"]["links"]["r1-link" + str(randnum)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, True)
        nhip = NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_5, next_hop=nhip, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \n Error: Routes are missing in RIB".format(tc_name)

    dut = "r2"
    protocol = "bgp"

    # this is next hop reachability route  in r3 as we are using ibgp
    dut = "r3"
    for addr_type in ADDR_TYPES:
        nh_as_rte = NEXT_HOP_IP["nh1"][addr_type] + "/32"
        # add static routes
        nh_static_rte = {
            "r3": {"static_routes": [{"network": nh_as_rte, "next_hop": "Null0"}]}
        }
        logger.info("Configure static routes")
        result = create_static_routes(tgen, nh_static_rte)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "After each interface shut and no shut between R2 -R3 ,verify static"
        "route is present in the RIB & FIB of R3 & R2 RIB/FIB is remain"
        " unchanged"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Error: Routes are missing in RIB".format(tc_name)

    protocol = "static"
    dut = "r2"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {}: Failed \n Error: Routes are missing in RIB".format(tc_name)

    protocol = "bgp"
    dut = "r3"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {}: Failed \n Error: Routes are missing in RIB".format(tc_name)

    step("Reload the FRR router")
    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r2")

    start_router(tgen, "r2")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Error: Routes are still present in RIB".format(
            tc_name
        )

    step("BGP neighbor remove and add")
    for rtr in ["r2", "r3"]:
        if "bgp" in topo["routers"][rtr].keys():
            delete_bgp = {rtr: {"bgp": {"delete": True}}}
            result = create_router_bgp(tgen, topo, delete_bgp)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    create_router_bgp(tgen, topo["routers"])

    NEXT_HOP_IP = populate_nh()
    step("Verify routes are still present after delete and add bgp")
    dut = "r2"
    protocol = "static"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Error: Routes are still present in RIB".format(
            tc_name
        )

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Error: Routes are still present in RIB".format(
            tc_name
        )

    step("Remove the redistribute static knob")
    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static", "delete": True}
                                ]
                            }
                        }
                    }
                }
            }
        }

        logger.info("Remove redistribute static")
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        step("verify that routes are deleted from R3 routing table")

        dut = "r3"
        protocol = "bgp"
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \nError: Routes are"
            " still present in RIB of R3".format(tc_name)
        )

    write_test_footer(tc_name)


def test_static_route_8nh_diff_AD_bgp_ecmp_p1_tc10_ibgp(request):
    """
    Verify 8 static route functionality with 8 next hop different AD'

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    NEXT_HOP_IP = populate_nh()

    step("Configure 8 interfaces / links between R1 and R2 ")
    step("Configure 8 IBGP IPv4 peering between R2 and R3 router.")
    reset_config_on_routers(tgen)

    step(
        "Configure IPv4 static route in R2 with 8 next hop"
        "N1(21.1.1.2) AD 10, N2(22.1.1.2) AD 20, N3(23.1.1.2) AD 30,"
        "N4(24.1.1.2) AD 40, N5(25.1.1.2) AD 50, N6(26.1.1.2) AD 60,"
        "N7(27.1.1.2) AD 70, N8(28.1.1.2) AD 80"
    )
    step(
        "Configure nexthop AD in such way for static route S1 , N1 is"
        "preferred and for S2 , N2 is preferred and so on .."
    )
    nh_all = {}
    for addr_type in ADDR_TYPES:
        nh_all[addr_type] = []
        for nhp in range(1, 9):
            nh_all[addr_type].append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])

    for addr_type in ADDR_TYPES:
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, input_dict_4)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
            second_rte = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX2[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, second_rte)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
        logger.info("Verifying %s routes on r2", addr_type)

        step(
            "On R2, static route installed in RIB using "
            "show ip route with 8 next hop , lowest AD nexthop is active"
        )
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        dut = "r2"
        protocol = "static"
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

        step("Verify that highest AD nexthop are inactive")
        nh = []
        for nhp in range(2, 9):
            nh.append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
            retry_timeout=6,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes   are missing in RIB".format(tc_name)

    step("Configure redistribute static in BGP on R2 router")
    for addr_type in ADDR_TYPES:
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

    step(
        "Remove the static route configured with nexthop N1 to N8, one"
        "by one from running config"
    )

    for addr_type in ADDR_TYPES:
        # delete static routes
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
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
            "After removing the static route with N1 to N8 one by one , "
            "route become active with next preferred nexthop and nexthop which"
            "got removed is not shown in RIB and FIB"
        )

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
        ), "Testcase {} : Failed \nError: Routes are  still present in RIB".format(
            tc_name
        )

    step("Configure the static route with nexthop N1 to N8, one by one")
    for addr_type in ADDR_TYPES:
        # add static routes
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
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
        " After configuring them, route is always active with lowest AD"
        " value and all the nexthop populated in RIB and FIB again"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {"r2": {"static_routes": [{"network": PREFIX1[addr_type]}]}}
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol, fib=True
        )
        assert result is True, (
            "Testcase {} : Failed \nError: Route with "
            "lowest AD  is missing in RIB".format(tc_name)
        )

    step("Random shut of the nexthop interfaces")
    randnum = random.randint(0, 7)
    for addr_type in ADDR_TYPES:
        intf = topo["routers"]["r2"]["links"]["r1-link" + str(randnum)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, False)
        nhip = NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type]
        input_dict_5 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type],
                    }
                ]
            }
        }
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_5,
            next_hop=nhip,
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n Error: Routes are still present in RIB".format(
            tc_name
        )

    step("Random no shut of the nexthop interfaces")
    for addr_type in ADDR_TYPES:
        intf = topo["routers"]["r2"]["links"]["r1-link" + str(randnum)]["interface"]
        shutdown_bringup_interface(tgen, dut, intf, True)
        nhip = NEXT_HOP_IP["nh" + str(randnum + 1)][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_5, next_hop=nhip, protocol=protocol
        )
        assert (
            result is True
        ), "Testcase {} : Failed \n Error: Routes are missing in RIB".format(tc_name)

    step("Remove random static route with all the nexthop")
    for addr_type in ADDR_TYPES:
        # delete static routes
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
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
                "After removing the static route with N1 to N8 one by one , "
                "route become active with next preferred nexthop and nexthop "
                "which got removed is not shown in RIB and FIB"
            )
            nh = NEXT_HOP_IP["nh" + str(nhp)][addr_type]
            result = verify_rib(
                tgen,
                addr_type,
                dut,
                input_dict_4,
                next_hop=nh,
                protocol=protocol,
                expected=False,
            )
            assert result is not True, (
                "Testcase {} : Failed \nError: Route "
                " is still present in RIB".format(tc_name)
            )

        step("Reconfigure the deleted routes and verify they are installed")
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, input_dict_4)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

            dut = "r2"
            protocol = "static"
            nh = NEXT_HOP_IP["nh1"][addr_type]
            result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
            assert result is True, (
                "Testcase {} : Failed \nError: Route "
                " is still present in RIB".format(tc_name)
            )

            step("Reload the FRR router")
            # stop/start -> restart FRR router and verify
            stop_router(tgen, "r2")

            start_router(tgen, "r2")

            step("After reloading, verify that routes are still present in R2.")
            result = verify_rib(
                tgen,
                addr_type,
                dut,
                second_rte,
                next_hop=nh,
                protocol=protocol,
                fib=True,
            )
            assert (
                result is True
            ), "Testcase {} : Failed \nError: Route is missing in RIB".format(tc_name)

    step("Remove the redistribute static knob")
    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static", "delete": True}
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
        "After removing the BGP neighbor or redistribute static knob , "
        "verify route got clear from RIB and FIB of R3 routes "
    )
    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                    }
                ]
            }
        }
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, protocol=protocol, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes are  still present in RIB".format(
            tc_name
        )

    write_test_footer(tc_name)


def test_static_route_delete_p0_tc11_ibgp(request):
    """
    Delete the static route and verify the RIB and FIB state
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    NEXT_HOP_IP = populate_nh()

    step("Configure 8 interfaces / links between R1 and R2 ")
    step("Configure 8 IBGP IPv4 peering between R2 and R3 router.")
    reset_config_on_routers(tgen)

    step(
        "Configure IPv4 static route in R2 with 8 next hop"
        "N1(21.1.1.2) AD 10, N2(22.1.1.2) AD 20, N3(23.1.1.2) AD 30,"
        "N4(24.1.1.2) AD 40, N5(25.1.1.2) AD 50, N6(26.1.1.2) AD 60,"
        "N7(27.1.1.2) AD 70, N8(28.1.1.2) AD 80"
    )
    step(
        "Configure nexthop AD in such way for static route S1 , N1 is"
        "preferred and for S2 , N2 is preferred and so on .."
    )
    nh_all = {}
    for addr_type in ADDR_TYPES:
        nh_all[addr_type] = []
        for nhp in range(1, 9):
            nh_all[addr_type].append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])

    for addr_type in ADDR_TYPES:
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, input_dict_4)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
            second_rte = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX2[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, second_rte)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
        logger.info("Verifying %s routes on r2", addr_type)

        step(
            "On R2, static route installed in RIB using "
            "show ip route with 8 next hop , lowest AD nexthop is active"
        )
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        dut = "r2"
        protocol = "static"
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol, fib=True
        )
        assert (
            result is True
        ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

        step("Verify that highest AD nexthop are inactive")
        nh = []
        for nhp in range(2, 9):
            nh.append(NEXT_HOP_IP["nh" + str(nhp)][addr_type])
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes   are missing in RIB".format(tc_name)

    step("Configure redistribute static in BGP on R2 router")
    for addr_type in ADDR_TYPES:
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

    step("Remove the redistribute static knob")
    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static", "delete": True}
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
            "Verify after removing the redistribute static from BGP all the"
            "routes got delete from RIB and FIB of R3 "
        )

        dut = "r3"
        protocol = "bgp"
        result = verify_rib(
            tgen, addr_type, dut, input_dict_4, protocol=protocol, expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes are  still present in RIB".format(
            tc_name
        )

    for addr_type in ADDR_TYPES:
        for nhp in range(1, 9):
            input_dict_4 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX1[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
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
            second_rte = {
                "r2": {
                    "static_routes": [
                        {
                            "network": PREFIX2[addr_type],
                            "next_hop": NEXT_HOP_IP["nh" + str(nhp)][addr_type],
                            "admin_distance": 10 * nhp,
                        }
                    ]
                }
            }
            logger.info("Configure static routes")
            result = create_static_routes(tgen, second_rte)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
        logger.info("Verifying %s routes on r2", addr_type)

        step(
            " After removing all the routes and nexthop from R2 , "
            " verify R2 RIB and FIB is cleared"
        )
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": PREFIX1[addr_type],
                        "next_hop": NEXT_HOP_IP["nh1"][addr_type],
                        "admin_distance": 10,
                    }
                ]
            }
        }
        dut = "r2"
        protocol = "static"
        nh = NEXT_HOP_IP["nh1"][addr_type]
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=nh,
            protocol=protocol,
            fib=True,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \nError: Routes are  still active in RIB".format(
            tc_name
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
