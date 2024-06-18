#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#
"""
    -Verify static route ECMP functionality with 8 next hop

    -Verify static route functionality with 8 next hop different AD value

    -Verify static route with tag option

    -Verify BGP did not install the static route when it receive route
    with local next hop

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
from lib.topotest import version_cmp

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
NETWORK2 = {"ipv4": ["11.0.20.1/32"], "ipv6": ["2::1/128"]}
NEXT_HOP_IP = []


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
    json_file = "{}/static_routes_topo3_ibgp.json".format(CWD)
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


def test_staticroute_with_ecmp_p0_tc3_ibgp(request):
    """
    Verify static route ECMP functionality with 8 next hop'

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)
    NEXT_HOP_IP = populate_nh()

    step("Configure 8 interfaces / links between R1 and R2,")
    step(
        "Configure IPv4 static route in R2 with 8 next hop"
        "N1(21.1.1.2), N2(22.1.1.2), N3(23.1.1.2), N4(24.1.1.2),"
        "N5(25.1.1.2), N6(26.1.1.2), N7(27.1.1.2),N8(28.1.1.2), Static"
        "route next-hop present on R1"
    )

    step("Configure IBGP IPv4 peering between R2 and R3 router.")

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
        nh = [
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
            tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
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
                        }
                    ]
                }
            }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    result = verify_rib(
        tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
    )
    assert (
        result is True
    ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

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

    step("Reload the FRR router")
    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r2")
    start_router(tgen, "r2")

    result = verify_rib(
        tgen, addr_type, dut, input_dict_4, next_hop=nh, protocol=protocol
    )
    assert (
        result is True
    ), "Testcase {} : Failed \nError: Routes are  missing in RIB".format(tc_name)

    write_test_footer(tc_name)


def test_staticroute_with_ecmp_with_diff_AD_p0_tc4_ibgp(request):
    """
    Verify static route ECMP functionality with 8 next hop

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)

    step("Configure 8 interfaces / links between R1 and R2,")
    step("Configure IBGP IPv4 peering between R2 and R3 router.")
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
            "show ip route with 8 next hop, lowest AD nexthop is active"
        )
        step("On R2, static route with lowest AD nexthop installed in FIB")
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
        assert result is True, (
            "Testcase {} : Failed \nError: Route with "
            " lowest AD is missing in RIB".format(tc_name)
        )

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
        assert result is not True, (
            "Testcase {} : Failed \nError: Routes "
            " with high AD are active in RIB".format(tc_name)
        )

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

        logger.info("Configuring redistribute static")
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "After configuring them, route is always active with lowest AD"
            "value and all the nexthop populated in RIB and FIB again "
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
        assert result is True, (
            "Testcase {} : Failed \nError: Route with "
            " lowest AD is missing in RIB".format(tc_name)
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
        "After removing the static route with N1 to N8 one by one, "
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

        step("On R2, static route with lowest AD nexthop installed in FIB")
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
        assert result is True, (
            "Testcase {} : Failed \nError: Route with "
            " lowest AD is missing in RIB".format(tc_name)
        )

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
        assert result is not True, (
            "Testcase {} : Failed \nError: Routes "
            " with high AD are active in RIB".format(tc_name)
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

    step("Reload the FRR router")
    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r2")
    start_router(tgen, "r2")

    step(
        "After reload of FRR router, static route installed "
        "in RIB and FIB properly ."
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
        assert result is True, (
            "Testcase {} : Failed \nError: Route with "
            " lowest AD is missing in RIB".format(tc_name)
        )

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
        assert result is not True, (
            "Testcase {} : Failed \nError: Routes "
            " with high AD are active in RIB".format(tc_name)
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


def test_bgp_local_nexthop_p1_tc14_ibgp(request):
    """
    Verify BGP did not install the static route when it receive route
    with local next hop

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    step("Configure BGP IPv4 session between R2 and R3")
    step("Configure IPv4 static route on R2")
    reset_config_on_routers(tgen)

    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": topo["routers"]["r3"]["links"]["r2-link0"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Configure redistribute static in the BGP")

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

        step("Verify R2 BGP table has IPv4 route")
        dut = "r2"
        result = verify_rib(tgen, addr_type, dut, input_dict_4)
        assert (
            result is True
        ), "Testcase {} : Failed \nError:  routes are  missing in RIB of R2".format(
            tc_name
        )

        step(" Verify route did not install in the R3 BGP table, RIB/FIB")
        dut = "r3"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_4, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \nError:  routes are"
            " still present in BGP RIB of R2".format(tc_name)
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_4, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \nError:  routes are"
            " still present in RIB of R2".format(tc_name)
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
