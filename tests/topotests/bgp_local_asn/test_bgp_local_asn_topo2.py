#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#
##########################################################################################################
#
#   Testcases
#
##########################################################################################################
##########################################################################################################
#
# 1.10.1.2. Verify the BGP Local AS functionality by configuring 4 Byte AS  in between eBGP Peers.
#
# 1.10.1.4. Verify the BGP Local AS functionality by configuring Old AS(local as) in 2 bytes and New AS in 4 bytes in between eBGP Peers.
#
###############################################################################################################

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
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    verify_bgp_rib,
    create_router_bgp,
    verify_bgp_advertised_routes_from_neighbor,
)
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()
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
    json_file = "{}/bgp_local_asn_topo2.json".format(CWD)
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


##########################################################################################################
#
#   Testcases
#
##########################################################################################################


def test_verify_bgp_local_as_in_4_Byte_AS_EBGP_p0(request):
    """
    Verify the BGP Local AS functionality by configuring 4 Byte AS  in between eBGP Peers.
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
    step("Configure local-as at R3 towards R4.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "12000300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "12000110"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    for addr_type in ADDR_TYPES:
        for dut, asn, neighbor in zip(
            ["r2", "r4"], ["12000200", "12000400"], ["r3", "r3"]
        ):
            input_dict_r2_r4 = {
                dut: {
                    "bgp": {
                        "local_as": asn,
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                dut: {
                                                    "local_asn": {
                                                        "remote_as": "12000110"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r2_r4)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    # configure static routes
    step(
        "Done in base config: Advertise prefix 10.1.1.0/32 from Router-1(AS-12000100)."
    )
    step(
        "Done in base config: Advertise an ipv6 prefix 10:1::1:0/128 from Router-1(AS-12000100)."
    )
    step("Verify that Static routes are redistributed in BGP process")

    dut = "r1"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_static_r1 = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static in Router BGP in R1")

        input_static_redist_r1 = {
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
        result = create_router_bgp(tgen, topo, input_static_redist_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that Static routes are redistributed in BGP process")
    for addr_type in ADDR_TYPES:
        input_static_verify_r1 = {
            "r1": {"static_routes": [{"network": NETWORK[addr_type]}]}
        }

        result = verify_rib(tgen, addr_type, "r1", input_static_verify_r1)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )

        for dut in ["r2", "r3", "r4"]:
            result = verify_rib(tgen, addr_type, dut, input_static_r1)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that AS-12000110 is got added in the AS list 12000110 12000200 12000100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "12000110 12000200 12000100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "12000300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "12000110",
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
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Verify advertised routes to R4 at R3")
    expected_routes = {
        "ipv4": [
            {"network": "10.1.1.0/32", "nexthop": ""},
        ],
        "ipv6": [
            {"network": "10:1::1:0/128", "nexthop": ""},
        ],
    }
    result = verify_bgp_advertised_routes_from_neighbor(
        tgen, topo, dut="r3", peer="r4", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    aspath = "12000200 12000100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "12000300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "12000110",
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
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    dut = "r4"
    aspath = "12000110 12000200 12000100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_bgp_local_as_in_old_AS2_new_AS4_EBGP_p0(request):
    """
    Verify the BGP Local AS functionality by configuring Old AS(local as) in
    2 bytes and New AS in 4 bytes in between eBGP Peers.
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
    step("Configure local-as at R3 towards R4.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "12000300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {"local_asn": {"local_as": "110"}}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    for addr_type in ADDR_TYPES:
        for dut, asn, neighbor in zip(
            ["r2", "r4"], ["12000200", "12000400"], ["r3", "r3"]
        ):
            input_dict_r2_r4 = {
                dut: {
                    "bgp": {
                        "local_as": asn,
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                dut: {"local_asn": {"remote_as": "110"}}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r2_r4)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    # configure static routes
    step(
        "Done in base config: Advertise prefix 10.1.1.0/32 from Router-1(AS-12000100)."
    )
    step(
        "Done in base config: Advertise an ipv6 prefix 10:1::1:0/128 from Router-1(AS-12000100)."
    )
    step("Verify that Static routes are redistributed in BGP process")

    dut = "r1"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_static_r1 = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Configure static routes")
        result = create_static_routes(tgen, input_static_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("configure redistribute static in Router BGP in R1")

        input_static_redist_r1 = {
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
        result = create_router_bgp(tgen, topo, input_static_redist_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that Static routes are redistributed in BGP process")
    for addr_type in ADDR_TYPES:
        input_static_verify_r1 = {
            "r1": {"static_routes": [{"network": NETWORK[addr_type]}]}
        }

        result = verify_rib(tgen, addr_type, "r1", input_static_verify_r1)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )

        for dut in ["r3", "r4"]:
            result = verify_rib(tgen, addr_type, dut, input_static_r1)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

        for dut, input_routes in zip(["r1"], [input_static_r1]):
            result = verify_rib(tgen, addr_type, dut, input_routes)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that AS-110 is got added in the AS list 110 12000200 12000100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "110 12000200 12000100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "12000300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
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
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Verify advertised routes to R4 at R3")
    expected_routes = {
        "ipv4": [
            {"network": "10.1.1.0/32", "nexthop": ""},
        ],
        "ipv6": [
            {"network": "10:1::1:0/128", "nexthop": ""},
        ],
    }
    result = verify_bgp_advertised_routes_from_neighbor(
        tgen, topo, dut="r3", peer="r4", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    aspath = "12000200 12000100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "12000300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
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
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    dut = "r4"
    aspath = "110 12000200 12000100"
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
