#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test BGP Multi-VRF Dynamic Route Leaking:
1. Verify that with multiple tenant VRFs, dynamically imported routes are
    further advertised to eBGP peers.
2. Verify the route-map operations along with dynamic import command
3. Verify that deleting static routes from originating VRF also deletes
    routes from other VRFs and peers.
4. Verify that deleting and adding "import" command multiple times shows
    consistent results.
"""

import os
import sys
import time
import pytest
import platform

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
    json_file = "{}/bgp_vrf_dynamic_route_leak_topo3.json".format(CWD)
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


def test_dynamic_import_routes_advertised_to_ebgp_peers_p0(request):
    """
    Verify that with multiple tenant VRFs, dynamically imported routes are
    further advertised to eBGP peers.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure static routes on R2 and R3 and redistribute in BGP for "
        "BLUE and RED vrf instances"
    )
    for dut, network in zip(
        ["r2", "r3"], [[NETWORK1_1, NETWORK1_2], [NETWORK2_1, NETWORK2_2]]
    ):
        for vrf_name, network_vrf in zip(["RED", "BLUE"], network):
            step("Configure static route for VRF : {} on {}".format(vrf_name, dut))
            for addr_type in ADDR_TYPES:
                static_routes = {
                    dut: {
                        "static_routes": [
                            {
                                "network": [network_vrf[addr_type]],
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

    for dut, as_num in zip(["r2", "r3"], ["2", "3"]):
        for vrf_name in ["RED", "BLUE"]:
            step("Redistribute static route on BGP VRF : {}".format(vrf_name))
            temp = {}
            for addr_type in ADDR_TYPES:
                temp.update(
                    {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    }
                )

            redist_dict = {
                dut: {
                    "bgp": [
                        {"vrf": vrf_name, "local_as": as_num, "address_family": temp}
                    ]
                }
            }

            result = create_router_bgp(tgen, topo, redist_dict)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that R2 and R3 has installed redistributed routes in BLUE "
        "and RED vrfs"
    )
    for dut, network in zip(
        ["r2", "r3"], [[NETWORK2_1, NETWORK2_2], [NETWORK1_1, NETWORK1_2]]
    ):
        for vrf_name, network_vrf in zip(["RED", "BLUE"], network):
            for addr_type in ADDR_TYPES:
                static_routes = {
                    dut: {
                        "static_routes": [
                            {
                                "network": [network_vrf[addr_type]],
                                "next_hop": "blackhole",
                                "vrf": vrf_name,
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
        "Import BLUE vrf's route in tenant vrf RED on R2 and then import "
        "vrf RED's routes into BLUE vrf on R3"
    )

    for dut, as_num, vrf_name, vrf_import in zip(
        ["r2", "r3"], ["2", "3"], ["RED", "BLUE"], ["BLUE", "RED"]
    ):
        step("Import vrf {} int vrf {}, on router {}".format(vrf_import, vrf_name, dut))
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update({addr_type: {"unicast": {"import": {"vrf": vrf_import}}}})

        import_dict = {
            dut: {
                "bgp": [{"vrf": vrf_name, "local_as": as_num, "address_family": temp}]
            }
        }

        result = create_router_bgp(tgen, topo, import_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that R2's vrf RED and R3's vrf BLUE has installed 4 set of "
        "prefixes. Routes imported from BLUE vrf (originated R2's & received "
        "from R3). Vrf RED's local routes (originated by R2's & received "
        "from R3)"
    )
    step(
        "Verify that R2 and R3 has installed redistributed routes in BLUE "
        "and RED vrfs"
    )

    for dut, vrf_name in zip(["r2", "r3"], ["RED", "BLUE"]):
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [
                                NETWORK1_1[addr_type],
                                NETWORK1_2[addr_type],
                                NETWORK2_1[addr_type],
                                NETWORK2_2[addr_type],
                            ],
                            "next_hop": "blackhole",
                            "vrf": vrf_name,
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
        "Additionally, R2 receives R3's BLUE vrf's prefixes and then import "
        "into vrf RED. These imported routes are advertised back to "
        "(originator)R3 but now in vrf RED, however R3 doesn't install these "
        "in vrf RED. Denied due to own AS"
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK1_1[addr_type],
                            NETWORK1_2[addr_type],
                            NETWORK2_1[addr_type],
                            NETWORK2_2[addr_type],
                        ],
                        "next_hop": "blackhole",
                        "vrf": "RED",
                    }
                ]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \nError {}\n" "Routes {} still in BGP table".format(
            tc_name, result, static_routes["r3"]["static_routes"][0]["network"]
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Remove import vrf BLUE from vrf RED's instance on R2.")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update(
            {addr_type: {"unicast": {"import": {"vrf": "BLUE", "delete": True}}}}
        )

    import_dict = {
        "r2": {"bgp": [{"vrf": "RED", "local_as": 2, "address_family": temp}]}
    }

    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    step(
        "Verify on R3 that, there is no change in FIB of vrf BLUE and R2's "
        "BLUE vrf originated routes are removed from vrf RED on R3."
    )
    for vrf_name in ["RED", "BLUE"]:
        for addr_type in ADDR_TYPES:
            if vrf_name == "RED":
                network_vrf = [NETWORK1_1[addr_type], NETWORK2_1[addr_type]]
            elif vrf_name == "BLUE":
                network_vrf = [
                    NETWORK1_1[addr_type],
                    NETWORK1_2[addr_type],
                    NETWORK2_1[addr_type],
                    NETWORK2_2[addr_type],
                ]
            static_routes = {
                "r3": {
                    "static_routes": [
                        {
                            "network": network_vrf,
                            "next_hop": "blackhole",
                            "vrf": vrf_name,
                        }
                    ]
                }
            }
            result = verify_bgp_rib(tgen, addr_type, "r3", static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

            result = verify_rib(tgen, addr_type, "r3", static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    step("Remove import vrf BLUE from vrf RED's instance on R2.")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "BLUE"}}}})

    import_dict = {
        "r2": {"bgp": [{"vrf": "RED", "local_as": 2, "address_family": temp}]}
    }

    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "All the routes described in earlier step should be added, once "
        "import command on R2 is re-added."
    )
    for dut, vrf_name in zip(["r2", "r3"], ["RED", "BLUE"]):
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [
                                NETWORK1_1[addr_type],
                                NETWORK1_2[addr_type],
                                NETWORK2_1[addr_type],
                                NETWORK2_2[addr_type],
                            ],
                            "next_hop": "blackhole",
                            "vrf": vrf_name,
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

    step("Remove import vrf RED from BLUE vrf on R3")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update(
            {addr_type: {"unicast": {"import": {"vrf": "RED", "delete": True}}}}
        )

    import_dict = {
        "r3": {"bgp": [{"vrf": "BLUE", "local_as": 3, "address_family": temp}]}
    }

    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on R2 that, there is no change in FIB of vrf RED and R3's "
        "vrf RED's originated routes are removed from vrf BLUE on R2."
    )
    for vrf_name in ["RED", "BLUE"]:
        for addr_type in ADDR_TYPES:
            if vrf_name == "BLUE":
                network_vrf = [NETWORK1_2[addr_type], NETWORK2_2[addr_type]]
            elif vrf_name == "RED":
                network_vrf = [
                    NETWORK1_1[addr_type],
                    NETWORK1_2[addr_type],
                    NETWORK2_1[addr_type],
                    NETWORK2_2[addr_type],
                ]
            static_routes = {
                "r2": {
                    "static_routes": [
                        {
                            "network": network_vrf,
                            "next_hop": "blackhole",
                            "vrf": vrf_name,
                        }
                    ]
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

    step("Add import vrf RED from BLUE vrf on R3")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "RED"}}}})

    import_dict = {
        "r3": {"bgp": [{"vrf": "BLUE", "local_as": 3, "address_family": temp}]}
    }

    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "All the routes described in earlier step should be added, once "
        "import command on R2 is re-added."
    )
    for dut, vrf_name in zip(["r2", "r3"], ["RED", "BLUE"]):
        for addr_type in ADDR_TYPES:
            static_routes = {
                dut: {
                    "static_routes": [
                        {
                            "network": [
                                NETWORK1_1[addr_type],
                                NETWORK1_2[addr_type],
                                NETWORK2_1[addr_type],
                                NETWORK2_2[addr_type],
                            ],
                            "next_hop": "blackhole",
                            "vrf": vrf_name,
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

    write_test_footer(tc_name)


def test_dynamic_imported_matching_prefix_based_on_community_list_p0(request):
    """
    Verify the route-map operations along with dynamic import command
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure static routes on R3 for vrf RED and redistribute in BGP " "instance"
    )
    for vrf_name, networks in zip(
        ["RED", "BLUE"], [[NETWORK1_1, NETWORK1_2], [NETWORK2_1, NETWORK2_2]]
    ):
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r3": {
                    "static_routes": [
                        {
                            "network": [networks[0][addr_type], networks[1][addr_type]],
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

    step(
        "Configure route-map to set community attribute for a specific " "prefix on R3"
    )
    for addr_type in ADDR_TYPES:
        input_dict_pf = {
            "r3": {
                "prefix_lists": {
                    addr_type: {
                        "pflist_ABC_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": NETWORK1_1[addr_type],
                                "action": "permit",
                            }
                        ]
                    }
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_pf)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    input_dict_cl = {
        "r3": {
            "bgp_community_lists": [
                {
                    "community_type": "expanded",
                    "action": "permit",
                    "name": "COMM",
                    "value": COMM_VAL_1,
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_cl)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_dict_rm = {
            "r3": {
                "route_maps": {
                    "rmap_XYZ_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pflist_ABC_{}".format(addr_type)
                                }
                            },
                            "set": {"community": {"num": COMM_VAL_1}},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Apply this route-map on R3 to set community under vrf RED/BLUE "
        "while redistributing the prefixes into BGP"
    )
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update(
            {
                addr_type: {
                    "unicast": {
                        "redistribute": [
                            {
                                "redist_type": "static",
                                "attribute": {
                                    "route-map": "rmap_XYZ_{}".format(addr_type)
                                },
                            }
                        ]
                    }
                }
            }
        )

    for vrf_name in ["RED", "BLUE"]:
        redist_dict = {
            "r3": {"bgp": [{"vrf": vrf_name, "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, redist_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that specific prefixes matched in route-map have community "
        "attribute value 100:100 tagged"
    )
    input_dict_comm = {"community": COMM_VAL_1}
    for addr_type in ADDR_TYPES:
        result = verify_bgp_community(
            tgen, addr_type, "r3", [NETWORK1_1[addr_type]], input_dict_comm, vrf="RED"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Configure a route-map for filtering the prefixes based on community "
        "attribute while importing into default vrf"
    )
    for addr_type in ADDR_TYPES:
        input_dict_rm = {
            "r3": {
                "route_maps": {
                    "rmap_IMP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 10,
                            "match": {"community_list": {"id": "COMM"}},
                            "set": {"community": {"num": COMM_VAL_2}},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Apply the route-map while Importing vrf RED/BLUE's prefixes into "
        "GREEN vrf on router R3"
    )
    temp = {}
    for vrf_name in ["RED", "BLUE"]:
        for addr_type in ADDR_TYPES:
            temp.update({addr_type: {"unicast": {"import": {"vrf": vrf_name}}}})

        inport_dict = {
            "r3": {"bgp": [{"vrf": "GREEN", "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, inport_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update(
            {
                addr_type: {
                    "unicast": {
                        "import": {"vrf": "route-map rmap_IMP_{}".format(addr_type)}
                    }
                }
            }
        )

    inport_dict = {
        "r3": {"bgp": [{"vrf": "GREEN", "local_as": 3, "address_family": temp}]}
    }

    result = create_router_bgp(tgen, topo, inport_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_comm = {"community": COMM_VAL_2}
    step(
        "Verify on R3 that only prefixes with community value {} in vrf RED "
        "are imported to vrf GREEN. While importing, the community value "
        "has been changed to {}".format(COMM_VAL_1, COMM_VAL_2)
    )

    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {
                "static_routes": [{"network": [NETWORK1_1[addr_type]], "vrf": "GREEN"}]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK2_1[addr_type],
                            NETWORK2_2[addr_type],
                            NETWORK1_2[addr_type],
                        ],
                        "vrf": "GREEN",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \nError {}\n" "Routes {} still in BGP table".format(
            tc_name, result, static_routes["r3"]["static_routes"][0]["network"]
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed Error {}" "Routes {} still in Route table".format(
            tc_name, result, static_routes["r3"]["static_routes"][0]["network"]
        )

        result = verify_bgp_community(
            tgen, addr_type, "r3", [NETWORK1_1[addr_type]], input_dict_comm, vrf="GREEN"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for action, value in zip(["Delete", "Add"], [True, False]):
        step("{} import vrf RED/BLUE command one by one from vrf GREEN".format(action))
        temp = {}
        for vrf_name in ["RED", "BLUE"]:
            for addr_type in ADDR_TYPES:
                temp.update(
                    {
                        addr_type: {
                            "unicast": {"import": {"vrf": vrf_name, "delete": value}}
                        }
                    }
                )

            inport_dict = {
                "r3": {"bgp": [{"vrf": "GREEN", "local_as": 3, "address_family": temp}]}
            }

            result = create_router_bgp(tgen, topo, inport_dict)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "Verify that when import vrf RED/BLUE is {} one by one, all "
            "routes of respective vrf disappear from vrf GREEN without "
            "affecting (BLUE/RED) routes".format(action.lower())
        )
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r3": {
                    "static_routes": [
                        {"network": [NETWORK1_1[addr_type]], "vrf": "GREEN"}
                    ]
                }
            }

            if value:
                result = verify_bgp_rib(
                    tgen, addr_type, "r3", static_routes, expected=False
                )
                assert result is not True, (
                    "Testcase {} : Failed \nError {}\n"
                    "Routes {} still in BGP table".format(
                        tc_name,
                        result,
                        static_routes["r3"]["static_routes"][0]["network"],
                    )
                )

                result = verify_rib(
                    tgen, addr_type, "r3", static_routes, expected=False
                )
                assert result is not True, (
                    "Testcase {} : Failed Error {}"
                    "Routes {} still in Route table".format(
                        tc_name,
                        result,
                        static_routes["r3"]["static_routes"][0]["network"],
                    )
                )
            else:
                result = verify_bgp_rib(tgen, addr_type, "r3", static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, "r3", static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

    for action, value in zip(["Delete", "Re-add"], [True, False]):
        step(
            "{} route-map IMP from global config when import and route-maps "
            "are applied in vrf GREEN".format(action)
        )
        for addr_type in ADDR_TYPES:
            input_dict_rm = {
                "r3": {
                    "route_maps": {
                        "rmap_IMP_{}".format(addr_type): [
                            {
                                "action": "permit",
                                "seq_id": 10,
                                "match": {"community_list": {"id": "COMM"}},
                                "set": {"community": {"num": COMM_VAL_2}},
                                "delete": value,
                            }
                        ]
                    }
                }
            }
            result = create_route_maps(tgen, input_dict_rm)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "Verify that when import vrf RED/BLUE is {} one by one, all "
            "routes of respective vrf disappear from vrf GREEN without "
            "affecting (BLUE/RED) routes".format(action.lower())
        )
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r3": {
                    "static_routes": [
                        {"network": [NETWORK1_1[addr_type]], "vrf": "GREEN"}
                    ]
                }
            }

            if value:
                result = verify_bgp_rib(
                    tgen, addr_type, "r3", static_routes, expected=False
                )
                assert result is not True, (
                    "Testcase {} : Failed \nError {}\n"
                    "Routes {} still in BGP table".format(
                        tc_name,
                        result,
                        static_routes["r3"]["static_routes"][0]["network"],
                    )
                )

                result = verify_rib(
                    tgen, addr_type, "r3", static_routes, expected=False
                )
                assert result is not True, (
                    "Testcase {} : Failed Error {}"
                    "Routes {} still in Route table".format(
                        tc_name,
                        result,
                        static_routes["r3"]["static_routes"][0]["network"],
                    )
                )
            else:
                result = verify_bgp_rib(tgen, addr_type, "r3", static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, "r3", static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

    write_test_footer(tc_name)


def test_dynamic_import_routes_delete_static_route_p1(request):
    """
    Verify that deleting static routes from originating VRF also deletes
    routes from other VRFs and peers.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure static routes on R3 for each tenant vrf and redistribute "
        "in respective BGP instance"
    )
    vrf_list = VRF_LIST + ["default"]
    for vrf_name, network in zip(
        vrf_list, [NETWORK1_1, NETWORK2_1, NETWORK3_1, NETWORK1_2]
    ):
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

    for vrf_name, network in zip(vrf_list, [NETWORK1_1, NETWORK2_1, NETWORK3_1]):
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

    step("Import routes among vrfs as mentioned below on router R3")

    for vrf_name, vrf_import in zip(
        ["GREEN", "BLUE", "default"], ["RED", "GREEN", "BLUE"]
    ):
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update({addr_type: {"unicast": {"import": {"vrf": vrf_import}}}})

        import_dict = {
            "r3": {"bgp": [{"vrf": vrf_name, "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, import_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for vrf_name, vrf_import, installed, not_installed in zip(
        ["BLUE", "default"],
        ["GREEN", "BLUE"],
        [NETWORK3_1, NETWORK2_1],
        [NETWORK1_1, NETWORK3_1],
    ):
        step(
            "Verify that only locally originated routes of vrf {} are "
            "advertised to vrf {}".format(vrf_import, vrf_name)
        )

        for addr_type in ADDR_TYPES:
            static_routes = {
                "r3": {
                    "static_routes": [
                        {"network": [installed[addr_type]], "vrf": vrf_name}
                    ]
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

            step(
                "Verify that non local originated routes {} of vrf {} are "
                "not advertised to vrf {}".format(
                    not_installed[addr_type], vrf_import, vrf_name
                )
            )

            static_routes = {
                "r3": {
                    "static_routes": [
                        {"network": [not_installed[addr_type]], "vrf": vrf_name}
                    ]
                }
            }
            result = verify_bgp_rib(
                tgen, addr_type, "r2", static_routes, expected=False
            )
            assert result is not True, (
                "Testcase {} : Failed \nError {}\n"
                "Routes {} still in BGP table".format(
                    tc_name, result, static_routes["r2"]["static_routes"][0]["network"]
                )
            )

            result = verify_rib(tgen, addr_type, "r2", static_routes, expected=False)
            assert (
                result is not True
            ), "Testcase {} : Failed Error {}" "Routes {} still in Route table".format(
                tc_name, result, static_routes["r2"]["static_routes"][0]["network"]
            )

    step("Delete static routes from vrf RED")
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": "blackhole",
                        "vrf": "RED",
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )
    step(
        "Verify on R2 and R3, that only vrf RED and GREEN's RIB/FIB withdraw "
        "deleted routes"
    )
    for dut in ["r2", "r3"]:
        step(
            "Verify on {}, that only vrf RED and GREEN's RIB/FIB withdraw "
            "deleted routes".format(dut)
        )
        for vrf_name in ["RED", "GREEN"]:
            for addr_type in ADDR_TYPES:
                static_routes = {
                    "r3": {
                        "static_routes": [
                            {"network": [NETWORK1_1[addr_type]], "vrf": vrf_name}
                        ]
                    }
                }
                result = verify_bgp_rib(
                    tgen, addr_type, "r2", static_routes, expected=False
                )
                assert result is not True, (
                    "Testcase {} : Failed \nError {}\n"
                    "Routes {} still in BGP table".format(
                        tc_name,
                        result,
                        static_routes["r2"]["static_routes"][0]["network"],
                    )
                )

                result = verify_rib(
                    tgen, addr_type, "r2", static_routes, expected=False
                )
                assert result is not True, (
                    "Testcase {} : Failed Error {}"
                    "Routes {} still in Route table".format(
                        tc_name,
                        result,
                        static_routes[dut]["static_routes"][0]["network"],
                    )
                )

    step("Delete static routes from vrf BLUE")
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]],
                        "next_hop": "blackhole",
                        "vrf": "BLUE",
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for dut in ["r2", "r3"]:
        step(
            "Verify on {}, that only default and BLUE vrf's RIB/FIB "
            "withdraw deleted routes".format(dut)
        )
        for vrf_name in ["BLUE", "default"]:
            for addr_type in ADDR_TYPES:
                static_routes = {
                    "r3": {
                        "static_routes": [
                            {"network": [NETWORK2_1[addr_type]], "vrf": vrf_name}
                        ]
                    }
                }
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

                result = verify_rib(tgen, addr_type, dut, static_routes, expected=False)
                assert result is not True, (
                    "Testcase {} : Failed Error {}"
                    "Routes {} still in Route table".format(
                        tc_name,
                        result,
                        static_routes[dut]["static_routes"][0]["network"],
                    )
                )

    step("Delete static routes from vrf default")
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_2[addr_type]],
                        "next_hop": "blackhole",
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for dut in ["r2", "r3"]:
        step(
            "Verify on {}, that only default vrf RIB/FIB withdraw deleted "
            "routes".format(dut)
        )
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r3": {
                    "static_routes": [
                        {"network": [NETWORK1_2[addr_type]], "vrf": vrf_name}
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
            assert result is not True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    step("Add back all the routes that were deleted")
    for vrf_name, network in zip(
        vrf_list, [NETWORK1_1, NETWORK2_1, NETWORK3_1, NETWORK1_2]
    ):
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

    for vrf_name, network in zip(vrf_list, [NETWORK1_1, NETWORK2_1, NETWORK3_1]):
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

    write_test_footer(tc_name)


def test_dynamic_import_routes_add_delete_import_command_p1(request):
    """
    Verify that deleting and adding "import" command multiple times shows
    consistent results.
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

    step("Verify that R2 has installed redistributed routes in respective " "vrfs only")
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
        "GREEN's RIB/FIB"
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

    step("On R3 import routes from vrfs GREEN to default")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "GREEN"}}}})

    import_dict = {"r3": {"bgp": [{"local_as": 3, "address_family": temp}]}}
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that R2's vrf RED routes are now imported into vrf default "
        "of R3, next-hop pointing to vrf GREEN"
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {"static_routes": [{"network": [NETWORK2_1[addr_type]]}]}
        }

        next_hop_1 = topo["routers"]["r2"]["links"]["r3-link3"][addr_type].split("/")[0]
        result = verify_bgp_rib(
            tgen, addr_type, "r3", static_routes, next_hop=next_hop_1
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, next_hop=next_hop_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Delete import command from R3's default vrf instance for both "
        "address-families 1 by 1 (ipv4/ipv6)"
    )
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update(
            {addr_type: {"unicast": {"import": {"vrf": "GREEN", "delete": True}}}}
        )

    import_dict = {"r3": {"bgp": [{"local_as": 3, "address_family": temp}]}}
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that R2's vrf RED routes are now removed from vrf "
        "default on R3, however vrf GREEN still retains those"
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {"static_routes": [{"network": [NETWORK2_1[addr_type]]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \nError {}\n" "Routes {} still in BGP table".format(
            tc_name, result, static_routes["r3"]["static_routes"][0]["network"]
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Delete import command from R2's vrf GREEN instance for both "
        "address-families 1 by 1 (ipv4/ipv6)"
    )
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update(
            {addr_type: {"unicast": {"import": {"vrf": "RED", "delete": True}}}}
        )

    import_dict = {
        "r2": {"bgp": [{"vrf": "GREEN", "local_as": 2, "address_family": temp}]}
    }
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    step(
        "Verify that R2's vrf RED routes are now removed from vrf GREEN "
        "on R2 & R3 as well"
    )
    for dut in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r2": {
                    "static_routes": [
                        {"network": [NETWORK2_1[addr_type]], "vrf": "GREEN"}
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
        "Add import command from R3's default vrf instance for both "
        "address-families 1 by 1 (ipv4/ipv6)"
    )
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "GREEN"}}}})

    import_dict = {"r3": {"bgp": [{"local_as": 3, "address_family": temp}]}}
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that there are no routes installed on R3's vrf default " "RIB/FIB.")
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {"static_routes": [{"network": [NETWORK2_1[addr_type]]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \nError {}\n" "Routes {} still in BGP table".format(
            tc_name, result, static_routes["r3"]["static_routes"][0]["network"]
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Add import command from R2's vrf GREEN instance for both "
        "address-families 1 by 1 (ipv4/ipv6)."
    )
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "RED"}}}})

    import_dict = {
        "r2": {"bgp": [{"vrf": "GREEN", "local_as": 2, "address_family": temp}]}
    }
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that R2's vrf RED routes are now imported into vrf "
        "default of R3, next-hop pointing to vrf GREEN"
    )
    for dut in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r2": {
                    "static_routes": [
                        {"network": [NETWORK2_1[addr_type]], "vrf": "GREEN"}
                    ]
                }
            }
            if dut == "r3":
                next_hop_1 = topo["routers"]["r2"]["links"]["r3-link3"][
                    addr_type
                ].split("/")[0]
                result = verify_bgp_rib(
                    tgen, addr_type, dut, static_routes, next_hop=next_hop_1
                )
            else:
                result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

            if dut == "r3":
                result = verify_rib(
                    tgen, addr_type, dut, static_routes, next_hop=next_hop_1
                )
            else:
                result = verify_rib(tgen, addr_type, dut, static_routes)

            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    step(
        "Delete import command from R3's default vrf instance for both "
        "address-families 1 by 1 (ipv4/ipv6)."
    )
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update(
            {addr_type: {"unicast": {"import": {"vrf": "GREEN", "delete": True}}}}
        )

    import_dict = {"r3": {"bgp": [{"local_as": 3, "address_family": temp}]}}
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that R2's vrf RED routes are now removed from vrf "
        "default on R3, however vrf GREEN still retains those."
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r2": {
                "static_routes": [{"network": [NETWORK2_1[addr_type]], "vrf": "GREEN"}]
            }
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        static_routes = {
            "r2": {"static_routes": [{"network": [NETWORK2_1[addr_type]]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \nError {}\n" "Routes {} still in BGP table".format(
            tc_name, result, static_routes["r3"]["static_routes"][0]["network"]
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Delete redistribute static from R2 for vrf RED")
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
        "r2": {"bgp": [{"vrf": "RED", "local_as": 2, "address_family": temp}]}
    }

    result = create_router_bgp(tgen, topo, redist_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that R2's vrf RED routes are now removed from vrf GREEN "
        "on R2 & R3 as well."
    )
    for dut in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            static_routes = {
                "r2": {
                    "static_routes": [
                        {"network": [NETWORK2_1[addr_type]], "vrf": "GREEN"}
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
        "Add import command from R3's default vrf instance for both "
        "address-families 1 by 1 (ipv4/ipv6)."
    )
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "GREEN"}}}})

    import_dict = {"r3": {"bgp": [{"local_as": 3, "address_family": temp}]}}
    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that there are no routes installed on R3's vrf default " "RIB/FIB")
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {"static_routes": [{"network": [NETWORK2_1[addr_type]]}]}
        }
        result = verify_bgp_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \nError {}\n" "Routes {} still in BGP table".format(
            tc_name, result, static_routes["r3"]["static_routes"][0]["network"]
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Add redistribute static from R2 for vrf RED")
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

    step(
        "Verify that R2's vrf RED routes are now imported into vrf "
        "default of R3, next-hop pointing to vrf GREEN"
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {"static_routes": [{"network": [NETWORK2_1[addr_type]]}]}
        }
        next_hop_1 = topo["routers"]["r2"]["links"]["r3-link3"][addr_type].split("/")[0]
        result = verify_bgp_rib(
            tgen, addr_type, "r3", static_routes, next_hop=next_hop_1
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, next_hop=next_hop_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
