#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#
#
##########################################################################################################################################
#
#   Testcases
#
###########################################################################################################################################
###########################################################################################################################################
#
# 1.10.1.7. Verify the BGP Local AS functionality with ECMP on 8 links by adding no-prepend and replace-as command in between eBGP Peers.
#
#################################################################################################################################################

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

from lib.common_config import (
    start_topology,
    write_test_header,
    create_static_routes,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    check_address_types,
    check_router_status,
    create_static_routes,
    verify_fib_routes,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    verify_bgp_rib,
    create_router_bgp,
)
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
BGP_CONVERGENCE = False
NETWORK = {"ipv4": "10.1.1.0/32", "ipv6": "10:1::1:0/128"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_local_asn_ecmp.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global BGP_CONVERGENCE
    global ADDR_TYPES
    ADDR_TYPES = check_address_types()

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

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


##########################################################################################################################################
#
#   Testcases
#
###########################################################################################################################################


def test_verify_bgp_local_as_in_ecmp_EBGP_p0(request):
    """
    Verify the BGP Local AS functionality with ECMP on 8 links by
    adding no-prepend and replace-as command in between eBGP Peers.
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

    step("Base config is done as part of JSON")
    dut = "r1"
    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_dict_static_route = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_dict_static_route)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static in Router BGP in R1")
        input_dict_static_route_redist = {
            "r1": {
                "bgp": [
                    {
                        "address_family": {
                            addr_type: {
                                "unicast": {"redistribute": [{"redist_type": "static"}]}
                            }
                        }
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_static_route_redist)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Verify IPv4 and IPv6 static routes received on R1")
        result = verify_rib(tgen, addr_type, "r1", input_dict_static_route)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_bgp_rib(tgen, addr_type, "r1", input_dict_static_route)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(tgen, addr_type, "r1", input_dict_static_route)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as at R3 towards R2.")
    for addr_type in ADDR_TYPES:
        input_dict_r3_to_r2 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r2": {
                                            "dest_link": {
                                                "r3-link1": {
                                                    "local_asn": {"local_as": "110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_r3_to_r2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as at R3 towards R4.")
    dest_link = {}
    for link_no in range(1, 9):
        link = "r3-link" + str(link_no)
        dest_link[link] = {"local_asn": {"local_as": "110"}}
    for addr_type in ADDR_TYPES:
        input_dict_r3_to_r4 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {"r4": {"dest_link": dest_link}}
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_r3_to_r4)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure remote-as at R2 towards R3.")
    for addr_type in ADDR_TYPES:
        input_dict_r2_to_r3 = {
            "r2": {
                "bgp": [
                    {
                        "local_as": "200",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r3": {
                                            "dest_link": {
                                                "r2-link1": {
                                                    "local_asn": {"remote_as": "110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_r2_to_r3)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure remote-as at R4 towards R3.")
    dest_link = {}
    for link_no in range(1, 9):
        link = "r4-link" + str(link_no)
        dest_link[link] = {"local_asn": {"remote_as": "110"}}
    for addr_type in ADDR_TYPES:
        input_dict_r4_to_r3 = {
            "r4": {
                "bgp": [
                    {
                        "local_as": "400",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {"r3": {"dest_link": dest_link}}
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_r4_to_r3)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Verify IPv4 and IPv6 static routes received on R3 & R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }
        for dut in ["r3", "r4"]:
            result = verify_fib_routes(tgen, addr_type, dut, static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

            result = verify_bgp_rib(tgen, addr_type, dut, static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that AS-110 is got added in the AS list 110 200 100 by following "
        " commands at R3 router."
    )
    dut = "r3"
    aspath = "110 200 100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend at R3 towards R2.")
    for addr_type in ADDR_TYPES:
        input_dict_no_prep_r3_to_r2 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r2": {
                                            "dest_link": {
                                                "r3-link1": {
                                                    "local_asn": {
                                                        "local_as": "110",
                                                        "no_prepend": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_no_prep_r3_to_r2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend at R3 towards R4.")
    dest_link = {}
    for link_no in range(1, 9):
        link = "r3-link" + str(link_no)
        dest_link[link] = {"local_asn": {"local_as": "110"}}
    for addr_type in ADDR_TYPES:
        input_dict_no_prep_r3_to_r4 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {"r4": {"dest_link": dest_link}}
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_no_prep_r3_to_r4)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    dut = "r3"
    aspath = "200 100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r2": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R2")
    for addr_type in ADDR_TYPES:
        input_dict_no_prep_rep_as_r3_to_r2 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r2": {
                                            "dest_link": {
                                                "r3-link1": {
                                                    "local_asn": {
                                                        "local_as": "110",
                                                        "no_prepend": True,
                                                        "replace_as": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_no_prep_rep_as_r3_to_r2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R4")
    dest_link = {}
    for link_no in range(1, 9):
        link = "r3-link" + str(link_no)
        dest_link[link] = {
            "local_asn": {"local_as": "110", "no_prepend": True, "replace_as": True}
        }
    for addr_type in ADDR_TYPES:
        input_dict_no_prep_rep_as_r3_to_r4 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {"r4": {"dest_link": dest_link}}
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_no_prep_rep_as_r3_to_r4)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    dut = "r4"
    aspath = "110 200 100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
