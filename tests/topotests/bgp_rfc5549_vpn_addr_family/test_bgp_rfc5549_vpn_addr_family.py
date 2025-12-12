#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test dynamic import/export vpn functionality:

TC1: Verify iBGP convergence with VPN address family..
"""

import os
import sys
import time
import pytest
from copy import deepcopy


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    step,
    check_router_status,
    stop_topology,
    check_router_status,
    apply_raw_config,
    required_linux_kernel_version
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_vpn_routes,
    clear_bgp,
)
from lib.topojson import build_config_from_json

# Reading the data from JSON File for topology creation
topo = None

# Global variables
NETWORK1_1 = {"ipv4": "172.16.10.1/32", "ipv6": "172:16:10::1/128"}
NETWORK1_2 = {"ipv4": "172.16.10.2/32", "ipv6": "172:16:10::2/128"}
NEXTHOP1_1 = {"ipv4": "12.0.0.1", "ipv6": "12::1"}

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global topo
    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_rfc5549_vpn_addr_family.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
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
    stop_topology(tgen)

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


########


def enable_import_vpn_under_bgp(
    tgen, tc_name, delete=False, rd="200:1", rt_import="200:3", rt_export="200:1"
):
    """This function is used to enable the vpn configuration on the dut"""

    if not delete:
        step("Configure VRFs and export & import VPN commands at R2 and R3 router. ")
        raw_config = {
            "r2": {
                "raw_config": [
                    "router bgp 200 vrf RED",
                    " address-family ipv4 unicast",
                    "  rd vpn export {}".format(rd),
                    "  rt vpn import {}".format(rt_import),
                    "  rt vpn export {}".format(rt_export),
                    "  export vpn",
                    "  import vpn",
                    " exit-address-family",
                    " address-family ipv6 unicast",
                    "  rd vpn export {}".format(rd),
                    "  rt vpn import {}".format(rt_import),
                    "  rt vpn export {}".format(rt_export),
                    "  export vpn",
                    "  import vpn",
                    " exit-address-family",
                    "router bgp 200",
                    " neighbor fd00:0:0:2::2 remote-as 200",
                    " neighbor fd00:0:0:2::2 timers 1 3",
                    " neighbor fd00:0:0:2::2 capability extended-nexthop",
                    " address-family ipv4 vpn",
                    "  neighbor fd00:0:0:2::2 activate",
                    " address-family ipv6 vpn",
                    "  neighbor fd00:0:0:2::2 activate",
                    " exit-address-family",
                ]
            }
        }

        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        raw_config = {
            "r3": {
                "raw_config": [
                    "router bgp 200 vrf RED",
                    " address-family ipv4 unicast",
                    "  rd vpn export {}".format(rd),
                    "  rt vpn import {}".format(rt_import),
                    "  rt vpn export {}".format(rt_export),
                    "  export vpn",
                    "  import vpn",
                    " exit-address-family",
                    " address-family ipv6 unicast",
                    "  rd vpn export {}".format(rd),
                    "  rt vpn import {}".format(rt_import),
                    "  rt vpn export {}".format(rt_export),
                    "  export vpn",
                    "  import vpn",
                    " exit-address-family",
                    "router bgp 200",
                    " address-family ipv4 vpn",
                    " neighbor fd00:0:0:2::1 activate",
                    "address-family ipv6 vpn",
                    " neighbor fd00:0:0:2::1 activate",
                ]
            }
        }

        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    else:
        step("Configure VRFs and export & import VPN commands at R2 and R3 router. ")
        raw_config = {
            "r2": {
                "raw_config": [
                    "router bgp 200 vrf RED",
                    " address-family ipv4 unicast",
                    "no  rd vpn export {}".format(rd),
                    "no  rt vpn import {}".format(rt_import),
                    "no  rt vpn export {}".format(rt_export),
                    "no  export vpn",
                    "no  import vpn",
                    " exit-address-family",
                    " address-family ipv6 unicast",
                    "no  rd vpn export {}".format(rd),
                    "no  rt vpn import {}".format(rt_import),
                    "no  rt vpn export {}".format(rt_export),
                    "no  export vpn",
                    "no  import vpn",
                    " exit-address-family",
                    "router bgp 200",
                    " neighbor fd00:0:0:2::2 remote-as 200",
                    " neighbor fd00:0:0:2::2 timers 1 3",
                    " neighbor fd00:0:0:2::2 capability extended-nexthop",
                    " address-family ipv4 vpn",
                    "  neighbor fd00:0:0:2::2 activate",
                    " address-family ipv6 vpn",
                    "  neighbor fd00:0:0:2::2 activate",
                    " exit-address-family",
                ]
            }
        }

        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        raw_config = {
            "r3": {
                "raw_config": [
                    "router bgp 200 vrf RED",
                    " address-family ipv4 unicast",
                    "no  rd vpn export {}".format(rd),
                    "no  rt vpn import {}".format(rt_import),
                    "no  rt vpn export {}".format(rt_export),
                    "no  export vpn",
                    "no  import vpn",
                    " exit-address-family",
                    " address-family ipv6 unicast",
                    "no  rd vpn export {}".format(rd),
                    "no  rt vpn import {}".format(rt_import),
                    "no  rt vpn export {}".format(rt_export),
                    "no  export vpn",
                    "no  import vpn",
                    " exit-address-family",
                    "router bgp 200",
                    " address-family ipv4 vpn",
                    " neighbor fd00:0:0:2::1 activate",
                    "address-family ipv6 vpn",
                    " neighbor fd00:0:0:2::1 activate",
                ]
            }
        }

        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    return


#####################################################
#
#   Testcases
#
#####################################################
def test_mpbgp_ibgp_funcationality_tc1_p0(request):
    """
    TC1: Verify iBGP convergence with VPN address family."
        Procedure: |
            1. Configure base configurations as per the topology
            2. Activate ibgp neighbor in the ipv4 vpn address family.
            3. Clear bgp process
            4. Delete ibgp neighbor in the ipv4 vpn address family.
            5. Activate ibgp neighbor in the ipv4 vpn address family. Redistribute the static routes into the bgp on RT1.
        ExpectedResult: |
            1. Base config should be up, verify using BGP convergence on all the routers for IPv4 and IPv6 nbrs.
            2. Verify that bgp neighbors are up In ipv4 as well as vpn address families.
            3. Verify that bgp neighbors are up In ipv4 as well as vpn address families.
            4. Verify that bgp neighbors are removed from vpnv4 address families.
            5. Verify that routes are learnt in the neighbor Vpn v4 table on RT3.
        ---
        TC1_FUNC_1:
        Verify iBGP convergence with VPN address family..
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base configurations as per the topology")
    reset_config_on_routers(tgen)
    step("Activate ibgp neighbor in the ipv4 vpn address family.")
    input_dict = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "address_family": {
                    "ipv4": {
                        "vpn": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "capability": "extended-nexthop",
                                            "activate": "ipv4",
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "vpn": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "capability": "extended-nexthop",
                                            "activate": "ipv4",
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r3": {
            "bgp": {
                "local_as": "200",
                "address_family": {
                    "ipv4": {
                        "vpn": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3-link1": {
                                            "capability": "extended-nexthop",
                                            "activate": "ipv4",
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "vpn": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3-link1": {
                                            "capability": "extended-nexthop",
                                            "activate": "ipv4",
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that bgp neighbors are up In ipv4 as well as vpn address families.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("clear bgp proces")
    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r2")

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Delete ibgp neighbor in the vpn address family.")

    raw_config = {
        "r2": {
            "raw_config": [
                "router bgp {}".format(topo["routers"]["r2"]["bgp"][2]["local_as"]),
                "no neighbor {} remote-as 200".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0]
                ),
                "address-family ipv4 vpn",
                "no neighbor {} activate".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv6"].split("/")[0]
                ),
                "address-family ipv6 vpn",
                "no neighbor {} activate".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv6"].split("/")[0]
                ),
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    topo1 = deepcopy(topo)

    topo1["routers"]["r2"]["bgp"][2]["address_family"]["ipv6"].pop("vpn")

    step("Verify that bgp neighbors are removed from vpnv4 address families.")
    result = verify_bgp_convergence(tgen, topo1, expected=False)
    assert (
        result is not True
    ), "Testcase {} :Failed, Vpnv4 Neighbors still found\n Error: {}".format(
        tc_name, result
    )

    step(
        "Activate ibgp neighbor in the ipv4 vpn address family. Redistribute the static routes into the bgp on RT1."
    )
    reset_config_on_routers(tgen)

    step("Verify that routes are learnt in the neighbor Vpn v4 table on RT3.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure VRFs and export & import VPN commands at R2 and R3 router. ")
    enable_import_vpn_under_bgp(tgen, tc_name)

    for addr_type in ["ipv4"]:
        input_routes_r2 = {
            "r3": {
                "routes": [
                    {
                        "routeDistinguishers": "200:1",
                        "network": [NETWORK1_1[addr_type], NETWORK1_2[addr_type]],
                        "vrf": "vpn",
                    }
                ]
            }
        }

        result = verify_bgp_vpn_routes(tgen, addr_type, "r3", input_routes_r2)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
