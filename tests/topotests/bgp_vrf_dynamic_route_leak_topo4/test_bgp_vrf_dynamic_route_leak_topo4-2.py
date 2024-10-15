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


def test_dynamic_import_routes_between_two_tenant_vrf_p0(request):
    """
    Verify that dynamic import works fine between two different Tenant VRFs.

    When next-hop IPs are same across all VRFs.
    When next-hop IPs are different across all VRFs.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure static routes on R3 for each vrf and redistribute in "
        "respective BGP instance"
    )

    for vrf_name, network in zip(VRF_LIST, [NETWORK1_1, NETWORK2_1, NETWORK3_1]):
        step("Configure static route for VRF : {}".format(vrf_name))
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r3": {
                    "static_routes": [
                        {
                            "network": [network[addr_type]],
                            "next_hop": "blackhole",
                            "vrf": vrf_name,
                        }
                    ]
                }
            }

            result = create_static_routes(tgen, static_routes)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

        step("Redistribute static route on BGP VRF : {}".format(vrf_name))
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {addr_type: {"unicast": {"redistribute": [{"redist_type": "static"}]}}}
            )

        redist_dict = {
            "r3": {"bgp": [{"vrf": vrf_name, "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, redist_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for vrf_name, network in zip(VRF_LIST, [NETWORK1_1, NETWORK2_1, NETWORK3_1]):
        step(
            "Verify that R3 has installed redistributed routes in respective "
            "vrfs: {}".format(vrf_name)
        )
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r3": {
                    "static_routes": [
                        {
                            "network": [network[addr_type]],
                            "next_hop": "blackhole",
                            "vrf": vrf_name,
                        }
                    ]
                }
            }

            result = verify_rib(tgen, addr_type, "r3", static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    step("Import from vrf GREEN+BLUE into vrf RED on R3")

    for vrf_name in ["BLUE", "GREEN"]:
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update({addr_type: {"unicast": {"import": {"vrf": vrf_name}}}})

        import_dict = {
            "r3": {"bgp": [{"vrf": "RED", "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, import_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify on R1, that it installs all the routes(local+imported) in "
        "vrf RED's RIB/FIB and doesn't get confuse with next-hop attribute, "
        "as all vrfs on R1 are using same IP address for next-hop"
    )

    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK1_1[addr_type],
                            NETWORK2_1[addr_type],
                            NETWORK3_1[addr_type],
                        ],
                        "next_hop": "blackhole",
                        "vrf": "RED",
                    }
                ]
            }
        }

        next_hop_1 = topo["routers"]["r3"]["links"]["r1-link1"][addr_type].split("/")[0]
        result = verify_bgp_rib(
            tgen, addr_type, "r1", static_routes, next_hop=next_hop_1
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", static_routes, next_hop=next_hop_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Remove import vrf GREEN/BLUE/Both command from vrf RED's instance on" " R3")
    for vrf_name in ["BLUE", "GREEN"]:
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {addr_type: {"unicast": {"import": {"vrf": vrf_name, "delete": True}}}}
            )

        import_dict = {
            "r3": {"bgp": [{"vrf": "RED", "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, import_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that R1,R2 & R3 withdraw imported routes from vrf RED's RIB")
    for dut in ["r1", "r2", "r3"]:
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [NETWORK2_1[addr_type], NETWORK3_1[addr_type]],
                            "next_hop": "blackhole",
                            "vrf": "RED",
                        }
                    ]
                }
            }
            result = verify_bgp_rib(tgen, addr_type, dut, static_routes, expected=False)
            assert result is not True, (
                "Testcase {} : Failed \nError {}\n"
                "Routes {} still in BGP table".format(
                    tc_name, result, static_routes[dut]["static_routes"][0]["network"]
                )
            )

            result = verify_rib(tgen, addr_type, dut, static_routes, expected=False)
            assert result is not True, (
                "Testcase {} : Failed \nError {}\n"
                "Routes {} still in Route table".format(
                    tc_name, result, static_routes[dut]["static_routes"][0]["network"]
                )
            )

    step("Add import vrf GREEN/BLUE/Both command from vrf RED's instance on " "R3")
    for vrf_name in ["BLUE", "GREEN"]:
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update({addr_type: {"unicast": {"import": {"vrf": vrf_name}}}})

        import_dict = {
            "r3": {"bgp": [{"vrf": "RED", "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, import_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for dut in ["r1", "r2", "r3"]:
        step("Verify that {} reinstall imported routes from vrf RED's RIB".format(dut))
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [NETWORK2_1[addr_type], NETWORK3_1[addr_type]],
                            "next_hop": "blackhole",
                            "vrf": "RED",
                        }
                    ]
                }
            }
            result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

            result = verify_rib(tgen, addr_type, dut, static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    for action, value in zip(["Shut", "No shut"], [True, False]):
        step(
            "{} the neighborship between R1-R3 and R1-R2 for vrf GREEN, BLUE "
            "and default".format(action)
        )
        bgp_disable = {"r3": {"bgp": []}}
        for vrf_name in ["GREEN", "BLUE", "default"]:
            temp = {}
            for addr_type in ADDR_TYPES:
                temp.update(
                    {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {"r3-link1": {"shutdown": value}}
                                    },
                                    "r2": {
                                        "dest_link": {"r3-link1": {"shutdown": value}}
                                    },
                                }
                            }
                        }
                    }
                )

            bgp_disable["r3"]["bgp"].append(
                {"vrf": vrf_name, "local_as": 3, "address_family": temp}
            )
        result = create_router_bgp(tgen, topo, bgp_disable)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Verify RIB/FIB of vrf RED will be unchanged on all 3 routers")
        for dut in ["r1", "r2", "r3"]:
            step("Verify RIB/FIB for vrf RED on {}".format(dut))
            for addr_type in ADDR_TYPES:
                static_routes = {
                    dut: {
                        "static_routes": [
                            {
                                "network": [
                                    NETWORK2_1[addr_type],
                                    NETWORK3_1[addr_type],
                                ],
                                "next_hop": "blackhole",
                                "vrf": "RED",
                            }
                        ]
                    }
                }
                result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, dut, static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

    for action, value, status in zip(
        ["Shut", "No shut"], [True, False], ["Withdraw", "Reinstall"]
    ):
        step("{} the neighborship between R1-R3 and R1-R2 for vrf RED".format(action))
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {
                    addr_type: {
                        "unicast": {
                            "neighbor": {
                                "r1": {"dest_link": {"r3-link1": {"shutdown": value}}},
                                "r2": {"dest_link": {"r3-link1": {"shutdown": value}}},
                            }
                        }
                    }
                }
            )

        bgp_disable = {
            "r3": {"bgp": [{"vrf": "RED", "local_as": 3, "address_family": temp}]}
        }
        result = create_router_bgp(tgen, topo, bgp_disable)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Verify that R1 and R2 {} all the routes from RED vrf's RIB and"
            " FIB".format(status)
        )
        for dut in ["r1", "r2"]:
            step("Verify RIB/FIB for vrf RED on {}".format(dut))
            for addr_type in ADDR_TYPES:
                static_routes = {
                    dut: {
                        "static_routes": [
                            {
                                "network": [
                                    NETWORK2_1[addr_type],
                                    NETWORK3_1[addr_type],
                                ],
                                "next_hop": "blackhole",
                                "vrf": "RED",
                            }
                        ]
                    }
                }

                if value:
                    result = verify_bgp_rib(
                        tgen, addr_type, dut, static_routes, expected=False
                    )
                    assert result is not True, (
                        "Testcase {} : Failed \nError {}\n"
                        "Routes {} still in BGP table".format(
                            tc_name,
                            result,
                            static_routes[dut]["static_routes"][0]["network"],
                        )
                    )

                    result = verify_rib(
                        tgen, addr_type, dut, static_routes, expected=False
                    )
                    assert result is not True, (
                        "Testcase {} : Failed \nError {}\n"
                        "Routes {} still in Route table".format(
                            tc_name,
                            result,
                            static_routes[dut]["static_routes"][0]["network"],
                        )
                    )
                else:
                    result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
                    assert result is True, "Testcase {} : Failed \n Error {}".format(
                        tc_name, result
                    )

                    result = verify_rib(tgen, addr_type, dut, static_routes)
                    assert result is True, "Testcase {} : Failed \n Error {}".format(
                        tc_name, result
                    )

    step("Remove import command from router R3 and configure the same on R2")
    for vrf_name in ["BLUE", "GREEN"]:
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {addr_type: {"unicast": {"import": {"vrf": vrf_name, "delete": True}}}}
            )

        import_dict = {
            "r3": {"bgp": [{"vrf": "RED", "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, import_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that once import commands are removed from R3, all imported "
        "routes are withdrawn from RIB/FIB of vrf RED on R1/R2/R3"
    )

    for dut in ["r1", "r2", "r3"]:
        step("Verify RIB/FIB for vrf RED on {}".format(dut))
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [NETWORK2_1[addr_type], NETWORK3_1[addr_type]],
                            "next_hop": "blackhole",
                            "vrf": "RED",
                        }
                    ]
                }
            }
            result = verify_bgp_rib(tgen, addr_type, dut, static_routes, expected=False)
            assert result is not True, (
                "Testcase {} : Failed \nError {}\n"
                "Routes {} still in BGP table".format(
                    tc_name, result, static_routes[dut]["static_routes"][0]["network"]
                )
            )

            result = verify_rib(tgen, addr_type, dut, static_routes, expected=False)
            assert (
                result is not True
            ), "Testcase {} : Failed Error {}" "Routes {} still in Route table".format(
                tc_name, result, static_routes[dut]["static_routes"][0]["network"]
            )

    step(
        "Configure static routes on R2 for each vrf and redistribute in "
        "respective BGP instance"
    )
    for vrf_name, network in zip(VRF_LIST, [NETWORK1_1, NETWORK2_1, NETWORK3_1]):
        step("Configure static route for VRF : {}".format(vrf_name))
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r2": {
                    "static_routes": [
                        {
                            "network": [network[addr_type]],
                            "next_hop": "blackhole",
                            "vrf": vrf_name,
                        }
                    ]
                }
            }

            result = create_static_routes(tgen, static_routes)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

        step("Redistribute static route on BGP VRF : {}".format(vrf_name))
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {addr_type: {"unicast": {"redistribute": [{"redist_type": "static"}]}}}
            )

        redist_dict = {
            "r2": {"bgp": [{"vrf": vrf_name, "local_as": 2, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, redist_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Remove redistribute static route on BGP VRF : {} on r3".format(vrf_name))
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {
                    addr_type: {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}]
                        }
                    }
                }
            )

        redist_dict = {
            "r3": {"bgp": [{"vrf": vrf_name, "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, redist_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for vrf_name in ["BLUE", "GREEN"]:
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update({addr_type: {"unicast": {"import": {"vrf": vrf_name}}}})

        import_dict = {
            "r2": {"bgp": [{"vrf": "RED", "local_as": 2, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, import_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify after import commands are re-configured on R2's vrf RED, all "
        "those routes are installed again in vrf RED of R1,R2,R3"
    )
    for dut in ["r1", "r2", "r3"]:
        step("Verify RIB/FIB for vrf RED on {}".format(dut))
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [
                                NETWORK1_1[addr_type],
                                NETWORK2_1[addr_type],
                                NETWORK3_1[addr_type],
                            ],
                            "next_hop": "blackhole",
                            "vrf": "RED",
                        }
                    ]
                }
            }
            result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

            result = verify_rib(tgen, addr_type, dut, static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    step(
        "Remove/add import vrf GREEN/BLUE/both command from vrf RED's " "instance on R2"
    )
    for vrf_name in ["BLUE", "GREEN"]:
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {addr_type: {"unicast": {"import": {"vrf": vrf_name, "delete": True}}}}
            )

        redist_dict = {
            "r2": {"bgp": [{"vrf": "RED", "local_as": 2, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, redist_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that R1,R2 & R3 withdraw imported routes from vrf RED's RIB")
    for dut in ["r1", "r2", "r3"]:
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [NETWORK2_1[addr_type], NETWORK3_1[addr_type]],
                            "next_hop": "blackhole",
                            "vrf": "RED",
                        }
                    ]
                }
            }
            result = verify_bgp_rib(tgen, addr_type, dut, static_routes, expected=False)
            assert result is not True, (
                "Testcase {} : Failed \nError {}\n"
                "Routes {} still in BGP table".format(
                    tc_name, result, static_routes[dut]["static_routes"][0]["network"]
                )
            )

            result = verify_rib(tgen, addr_type, dut, static_routes, expected=False)
            assert (
                result is not True
            ), "Testcase {} : Failed Error {}" "Routes {} still in Route table".format(
                tc_name, result, static_routes[dut]["static_routes"][0]["network"]
            )

    step("Add import vrf GREEN/BLUE/Both command from vrf RED's instance on " "R2")
    for vrf_name in ["BLUE", "GREEN"]:
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update({addr_type: {"unicast": {"import": {"vrf": vrf_name}}}})

        redist_dict = {
            "r2": {"bgp": [{"vrf": "RED", "local_as": 2, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, redist_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for dut in ["r1", "r2", "r3"]:
        step("Verify that {} reinstall imported routes from vrf RED's RIB".format(dut))
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [NETWORK2_1[addr_type], NETWORK3_1[addr_type]],
                            "next_hop": "blackhole",
                            "vrf": "RED",
                        }
                    ]
                }
            }
            result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

            result = verify_rib(tgen, addr_type, dut, static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    for action, value in zip(["Shut", "No shut"], [True, False]):
        step(
            "{} the neighborship between R2-R3 for vrf GREEN, BLUE and default".format(
                action
            )
        )
        bgp_disable = {"r2": {"bgp": []}}
        for vrf_name in ["GREEN", "BLUE", "default"]:
            temp = {}
            for addr_type in ADDR_TYPES:
                temp.update(
                    {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {"r2-link1": {"shutdown": value}}
                                    }
                                }
                            }
                        }
                    }
                )

            bgp_disable["r2"]["bgp"].append(
                {"vrf": vrf_name, "local_as": 2, "address_family": temp}
            )
        result = create_router_bgp(tgen, topo, bgp_disable)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Verify RIB/FIB of vrf RED will be unchanged on all 3 routers")
        for dut in ["r1", "r2", "r3"]:
            step("Verify RIB/FIB for vrf RED on {}".format(dut))
            for addr_type in ADDR_TYPES:
                static_routes = {
                    dut: {
                        "static_routes": [
                            {
                                "network": [
                                    NETWORK2_1[addr_type],
                                    NETWORK3_1[addr_type],
                                ],
                                "next_hop": "blackhole",
                                "vrf": "RED",
                            }
                        ]
                    }
                }
                result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, dut, static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

    for action, value, status in zip(
        ["Shut", "No shut"], [True, False], ["Withdraw", "Reinstall"]
    ):
        step("{} the neighborship between R2-R3 for vrf RED".format(action))
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {
                    addr_type: {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r3-link1": {"shutdown": value}}}
                            }
                        }
                    }
                }
            )

        bgp_disable = {
            "r3": {"bgp": [{"vrf": "RED", "local_as": 3, "address_family": temp}]}
        }
        result = create_router_bgp(tgen, topo, bgp_disable)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Verify that R1 and R2 {} all the routes from RED vrf's RIB and"
            " FIB".format(status)
        )
        for dut in ["r1", "r3"]:
            step("Verify RIB/FIB for vrf RED on {}".format(dut))
            for addr_type in ADDR_TYPES:
                static_routes = {
                    dut: {
                        "static_routes": [
                            {
                                "network": [
                                    NETWORK2_1[addr_type],
                                    NETWORK3_1[addr_type],
                                ],
                                "next_hop": "blackhole",
                                "vrf": "RED",
                            }
                        ]
                    }
                }

                if value:
                    result = verify_bgp_rib(
                        tgen, addr_type, dut, static_routes, expected=False
                    )
                    assert result is not True, (
                        "Testcase {} : Failed \nError {}\n"
                        "Routes {} still in BGP table".format(
                            tc_name,
                            result,
                            static_routes[dut]["static_routes"][0]["network"],
                        )
                    )

                    result = verify_rib(
                        tgen, addr_type, dut, static_routes, expected=False
                    )
                    assert result is not True, (
                        "Testcase {} : Failed Error {}"
                        "Routes {} still in Route table".format(
                            tc_name,
                            result,
                            static_routes[dut]["static_routes"][0]["network"],
                        )
                    )
                else:
                    result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
                    assert result is True, "Testcase {} : Failed \n Error {}".format(
                        tc_name, result
                    )

                    result = verify_rib(tgen, addr_type, dut, static_routes)
                    assert result is True, "Testcase {} : Failed \n Error {}".format(
                        tc_name, result
                    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
