#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test BGP Multi-VRF Dynamic Route Leaking:
1. Verify recursive import among Tenant VRFs.
2. Verify that dynamic import works fine between two different Tenant VRFs.
    When next-hop IPs are same across all VRFs.
    When next-hop IPs are different across all VRFs.
3. Verify that with multiple tenant VRFs, dynamic import works fine between
    Tenant VRFs to default VRF.
    When next-hop IPs and prefixes are same across all VRFs.
    When next-hop IPs and prefixes are different across all VRFs.
"""

import os
import sys
import time
import pytest
import platform
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topotest import version_cmp

from lib.common_config import (
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    create_route_maps,
    create_static_routes,
    create_prefix_lists,
    create_bgp_community_lists,
    get_frr_ipv6_linklocal,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_community,
    verify_bgp_rib,
)
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
NETWORK1_1 = {"ipv4": "11.11.11.1/32", "ipv6": "11:11::1/128"}
NETWORK1_2 = {"ipv4": "11.11.11.11/32", "ipv6": "11:11::11/128"}
NETWORK1_3 = {"ipv4": "10.10.10.1/32", "ipv6": "10:10::1/128"}
NETWORK1_4 = {"ipv4": "10.10.10.100/32", "ipv6": "10:10::100/128"}
NETWORK1_5 = {"ipv4": "110.110.110.1/32", "ipv6": "110:110::1/128"}
NETWORK1_6 = {"ipv4": "110.110.110.100/32", "ipv6": "110:110::100/128"}

NETWORK2_1 = {"ipv4": "22.22.22.2/32", "ipv6": "22:22::2/128"}
NETWORK2_2 = {"ipv4": "22.22.22.22/32", "ipv6": "22:22::22/128"}
NETWORK2_3 = {"ipv4": "20.20.20.20/32", "ipv6": "20:20::20/128"}
NETWORK2_4 = {"ipv4": "20.20.20.200/32", "ipv6": "20:20::200/128"}
NETWORK2_5 = {"ipv4": "220.220.220.20/32", "ipv6": "220:220::20/128"}
NETWORK2_6 = {"ipv4": "220.220.220.200/32", "ipv6": "220:220::200/128"}

NETWORK3_1 = {"ipv4": "30.30.30.3/32", "ipv6": "30:30::3/128"}
NETWORK3_2 = {"ipv4": "30.30.30.30/32", "ipv6": "30:30::30/128"}

PREFIX_LIST = {
    "ipv4": ["11.11.11.1", "22.22.22.2", "22.22.22.22"],
    "ipv6": ["11:11::1", "22:22::2", "22:22::22"],
}
PREFERRED_NEXT_HOP = "global"
VRF_LIST = ["RED", "BLUE", "GREEN"]
COMM_VAL_1 = "100:100"
COMM_VAL_2 = "500:500"
COMM_VAL_3 = "600:600"


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
    json_file = "{}/bgp_vrf_dynamic_route_leak_topo4.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Run these tests for kernel version 4.19 or above
    if version_cmp(platform.release(), "4.19") < 0:
        error_msg = (
            "BGP vrf dynamic route leak tests will not run "
            '(have kernel "{}", but it requires >= 4.19)'.format(platform.release())
        )
        pytest.skip(error_msg)

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


#####################################################
#
#   Testcases
#
#####################################################


def test_dynamic_import_recursive_import_tenant_vrf_p1(request):
    """
    Verify recursive import among Tenant VRFs.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure static routes on R2 for vrf RED and redistribute in "
        "respective BGP instance"
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r2": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": "blackhole",
                        "vrf": "RED",
                    }
                ]
            }
        }

        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static route on BGP VRF RED")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update(
            {addr_type: {"unicast": {"redistribute": [{"redist_type": "static"}]}}}
        )

    redist_dict = {
        "r2": {"bgp": [{"vrf": "RED", "local_as": 2, "address_family": temp}]}
    }

    result = create_router_bgp(tgen, topo, redist_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that R2 has installed redistributed routes in vrf RED only")
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r2": {
                "static_routes": [{"network": [NETWORK2_1[addr_type]], "vrf": "RED"}]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r2", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Import vrf RED's routes into vrf GREEN on R2")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "RED"}}}})

    import_dict = {
        "r2": {"bgp": [{"vrf": "GREEN", "local_as": 2, "address_family": temp}]}
    }
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on R2, that it installs imported routes from vrf RED to vrf "
        "GREEN's RIB/FIB pointing next-hop to vrf RED"
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r2": {
                "static_routes": [{"network": [NETWORK2_1[addr_type]], "vrf": "GREEN"}]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r2", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r2", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("On R3 import routes from vrf GREEN to vrf default")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "GREEN"}}}})

    import_dict = {"r3": {"bgp": [{"local_as": 3, "address_family": temp}]}}
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on R3, that it installs imported routes from vrf GREEN to "
        "vrf default RIB/FIB pointing next-hop to vrf GREEN. "
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r2": {"static_routes": [{"network": [NETWORK2_1[addr_type]]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("On R4 import routes from vrf default to vrf BLUE")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "default"}}}})

    import_dict = {
        "r4": {"bgp": [{"vrf": "BLUE", "local_as": 4, "address_family": temp}]}
    }
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on R4, that it installs imported routes from vrf default to "
        "vrf BLUE RIB/FIB pointing next-hop to vrf default."
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r4": {
                "static_routes": [{"network": [NETWORK2_1[addr_type]], "vrf": "BLUE"}]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r4", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r4", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for dut, vrf_name, vrf_import, as_num in zip(
        ["r2", "r4"], ["GREEN", "BLUE"], ["RED", "default"], [2, 4]
    ):
        for action, value in zip(["Delete", "Re-add"], [True, False]):
            step("{} the import command on {} router".format(action, dut))
            temp = {}
            for addr_type in ADDR_TYPES:
                temp.update(
                    {
                        addr_type: {
                            "unicast": {"import": {"vrf": vrf_import, "delete": value}}
                        }
                    }
                )

            import_dict = {
                dut: {
                    "bgp": [
                        {"vrf": vrf_name, "local_as": as_num, "address_family": temp}
                    ]
                }
            }
            result = create_router_bgp(tgen, topo, import_dict)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

            for addr_type in ADDR_TYPES:
                static_routes = {
                    "r4": {
                        "static_routes": [
                            {"network": [NETWORK2_1[addr_type]], "vrf": "BLUE"}
                        ]
                    }
                }
                if value:
                    result = verify_bgp_rib(
                        tgen, addr_type, "r4", static_routes, expected=False
                    )
                    assert result is not True, (
                        "Testcase {} : Failed \nError {}\n"
                        "Routes {} still in BGP table".format(
                            tc_name,
                            result,
                            static_routes["r4"]["static_routes"][0]["network"],
                        )
                    )

                    result = verify_rib(
                        tgen, addr_type, "r4", static_routes, expected=False
                    )
                    assert result is not True, (
                        "Testcase {} : Failed Error {}"
                        "Routes {} still in Route table".format(
                            tc_name,
                            result,
                            static_routes["r4"]["static_routes"][0]["network"],
                        )
                    )
                else:
                    result = verify_bgp_rib(tgen, addr_type, "r4", static_routes)
                    assert result is True, "Testcase {} : Failed \n Error {}".format(
                        tc_name, result
                    )

                    result = verify_rib(tgen, addr_type, "r4", static_routes)
                    assert result is True, "Testcase {} : Failed \n Error {}".format(
                        tc_name, result
                    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
