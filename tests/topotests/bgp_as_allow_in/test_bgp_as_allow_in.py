#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test bgp allowas-in functionality:

-   Verify that routes coming from same AS are accepted only when
    '"allowas-in" is configuerd.
-   Verify that "allowas-in" feature works per address-family/VRF
    'basis and doesn't impact the other AFIs.
-   Verify that the if number of occurrences of AS number in path is
    'more than the configured allowas-in value then we do not accept
    'the route.
-   Verify that when we advertise a network, learned from the same AS
    'via allowas-in command, to an iBGP neighbor we see multiple
    'occurrences.
-   Verify that when we advertise a network, learned from the same AS
    'via allowas-in command, to an eBGP neighbor we see multiple
    'occurrences of our own AS based on configured value+1.
"""

import os
import sys
import time
import pytest

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
    create_route_maps,
    check_address_types,
    step,
    required_linux_kernel_version,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
)
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()
NETWORK = {"ipv4": "2.2.2.2/32", "ipv6": "22:22::2/128"}
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
    json_file = "{}/bgp_as_allow_in.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Checking BGP convergence
    global BGP_CONVERGENCE
    global ADDR_TYPES

    # Api call verify whether BGP is converged
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error:" " {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Running setup_module() done")


def teardown_module(mod):
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


#####################################################
#
#   Tests starting
#
#####################################################


def test_bgp_allowas_in_p0(request):
    """
    Verify that routes coming from same AS are accepted only when
    "allowas-in" is configuerd.

    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    reset_config_on_routers(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Advertise prefix 2.2.2.2/32 from Router-1(AS-200).")
    step("Advertise an ipv6 prefix 22:22::2/128 from Router-1(AS-200).")
    # configure static routes
    dut = "r3"
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static in Router BGP in R1")

        input_dict_2 = {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        step(
            'Check BGP table of router R3 using "sh bgp ipv4" and "sh bgp '
            'ipv6" command.'
        )
        step(
            "We should not see prefix advertised from R1 in R3's BGP "
            "table without allowas-in."
        )
        logger.info("Verifying %s routes on r3, route should not be present", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=NEXT_HOP_IP[addr_type],
            protocol=protocol,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n".format(tc_name)
            + "Expected behavior: routes should not present in rib \n"
            + "Error: {}".format(result)
        )

        step("Configure allowas-in on R3 for R2.")
        step("We should see the prefix advertised from R1 in R3's BGP table.")
        # Api call to enable allowas-in in bgp process.
        input_dict_1 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3": {
                                                "allowas-in": {"number_occurences": 1}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_rib(tgen, addr_type, dut, input_dict_4, protocol=protocol)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_bgp_allowas_in_per_addr_family_p0(request):
    """
    Verify that "allowas-in" feature works per address-family/VRF
    basis and doesn't impact the other AFIs.

    """

    # This test is applicable only for dual stack.
    if "ipv4" not in ADDR_TYPES or "ipv6" not in ADDR_TYPES:
        pytest.skip("NOT APPLICABLE")

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    reset_config_on_routers(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Advertise prefix 2.2.2.2/32 from Router-1(AS-200).")
    step("Advertise an ipv6 prefix 22:22::2/128 from Router-1(AS-200).")
    # configure static routes routes
    dut = "r3"
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static in Router BGP in R1")

        input_dict_2 = {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure allowas-in on R3 for R2 under IPv4 addr-family only")
    # Api call to enable allowas-in in bgp process.
    input_dict_1 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3": {"allowas-in": {"number_occurences": 1}}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    static_route_ipv4 = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"], "next_hop": NEXT_HOP_IP["ipv4"]}
            ]
        }
    }

    static_route_ipv6 = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": NEXT_HOP_IP["ipv6"]}
            ]
        }
    }
    step("We should see R1 advertised prefix only in IPv4 AFI " "not in IPv6 AFI.")
    result = verify_rib(tgen, "ipv4", dut, static_route_ipv4, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(
        tgen, "ipv6", dut, static_route_ipv6, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n".format(tc_name)
        + "Expected behavior: routes are should not be present in ipv6 rib\n"
        + " Error: {}".format(result)
    )

    step("Repeat the same test for IPv6 AFI.")
    step("Configure allowas-in on R3 for R2 under IPv6 addr-family only")
    # Api call to enable allowas-in in bgp process.
    input_dict_1 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3": {
                                            "allowas-in": {
                                                "number_occurences": 2,
                                                "delete": True,
                                            }
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
                                        "r3": {"allowas-in": {"number_occurences": 2}}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step("We should see R1 advertised prefix only in IPv6 AFI " "not in IPv4 AFI.")
    result = verify_rib(
        tgen, "ipv4", dut, static_route_ipv4, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n".format(tc_name)
        + "Expected behavior: routes should not be present in ipv4 rib\n"
        + " Error: {}".format(result)
    )
    result = verify_rib(tgen, "ipv6", dut, static_route_ipv6, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_allowas_in_no_of_occurrences_p0(request):
    """
    Verify that the if number of occurrences of AS number in path is
    more than the configured allowas-in value then we do not accept
    the route.

    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    reset_config_on_routers(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut = "r3"
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        # Enable static routes
        static_routes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static in Router BGP in R1")

        input_dict_2 = {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure a route-map on R1 to prepend AS 4 times.")
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "route_maps": {
                    "ASP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {
                                "path": {
                                    "as_num": "200 200 200 200",
                                    "as_action": "prepend",
                                }
                            },
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure route map in out direction on R1")
        # Configure neighbor for route map
        input_dict_7 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1": {
                                                "route_maps": [
                                                    {
                                                        "name": "ASP_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step('Configure "allowas-in 4" on R3 for R2.')
        # Api call to enable allowas-in in bgp process.
        input_dict_1 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3": {
                                                "allowas-in": {"number_occurences": 4}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_rib(
            tgen, addr_type, dut, static_routes, protocol=protocol, expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n ".format(tc_name)
            + "Expected behavior: routes are should not be present in rib\n"
            + "Error: {}".format(result)
        )

    for addr_type in ADDR_TYPES:
        step('Configure "allowas-in 5" on R3 for R2.')
        input_dict_1 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3": {
                                                "allowas-in": {"number_occurences": 5}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        static_routes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }
        result = verify_rib(tgen, addr_type, dut, static_routes, protocol=protocol)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_bgp_allowas_in_sameastoibgp_p1(request):
    """
    Verify that when we advertise a network, learned from the same AS
    via allowas-in command, to an iBGP neighbor we see multiple
    occurrences.

    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    reset_config_on_routers(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut = "r3"
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        # Enable static routes
        static_routes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static in Router BGP in R1")

        input_dict_2 = {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure a route-map on R2 to prepend AS 2 times.")
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "route_maps": {
                    "ASP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {
                                "path": {"as_num": "200 200", "as_action": "prepend"}
                            },
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure route map in out direction on R2")
        # Configure neighbor for route map
        input_dict_7 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r2": {
                                                "route_maps": [
                                                    {
                                                        "name": "ASP_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step('Configure "allowas-in 3" on R3 for R1.')
        input_dict_1 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3": {
                                                "allowas-in": {"number_occurences": 3}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_1 = {
            "r4": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r4": {
                                                "allowas-in": {"number_occurences": 3}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        static_routes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }
        dut = "r4"
        path = "100 200 200 200"
        result = verify_bgp_rib(tgen, addr_type, dut, static_routes, aspath=path)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_bgp_allowas_in_sameastoebgp_p1(request):
    """
    Verify that when we advertise a network, learned from the same AS
    via allowas-in command, to an eBGP neighbor we see multiple
    occurrences of our own AS based on configured value+1.

    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    reset_config_on_routers(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut = "r3"
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        # Enable static routes
        static_routes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static in Router BGP in R1")

        input_dict_2 = {
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
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure a route-map on R2 to prepend AS 2 times.")
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "route_maps": {
                    "ASP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {
                                "path": {"as_num": "200 200", "as_action": "prepend"}
                            },
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure route map in out direction on R2")
        # Configure neighbor for route map
        input_dict_7 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r2": {
                                                "route_maps": [
                                                    {
                                                        "name": "ASP_{}".format(
                                                            addr_type
                                                        ),
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step('Configure "allowas-in 3" on R3 for R1.')
        input_dict_1 = {
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3": {
                                                "allowas-in": {"number_occurences": 3}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        static_routes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }
        dut = "r5"
        path = "200 100 200 200 200"
        result = verify_bgp_rib(tgen, addr_type, dut, static_routes, aspath=path)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
