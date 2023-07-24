#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test BGP Multi-VRF Dynamic Route Leaking:

1. Verify that Changing route-map configurations(match/set clauses) on
    the fly it takes immediate effect.
2. Verify BGP best path selection algorithm works fine when
    routes are imported from ISR to default vrf and vice versa.
"""

import os
import sys
import json
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
    step,
    create_route_maps,
    create_prefix_lists,
    create_bgp_community_lists,
    check_router_status,
    get_frr_ipv6_linklocal,
    shutdown_bringup_interface,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_community,
    verify_bgp_attributes,
    verify_best_path_as_per_bgp_attribute,
    verify_bgp_rib,
)
from lib.topojson import build_topo_from_json, build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
NETWORK1_1 = {"ipv4": "11.11.11.1/32", "ipv6": "11:11::1/128"}
NETWORK3_3 = {"ipv4": "50.50.50.5/32", "ipv6": "50:50::5/128"}
NETWORK3_4 = {"ipv4": "50.50.50.50/32", "ipv6": "50:50::50/128"}

PREFERRED_NEXT_HOP = "global"


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global topo
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_vrf_dynamic_route_leak_topo2.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
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


def test_bgp_best_path_with_dynamic_import_p0(request):
    """
    TC6_FUNC_6:
    1.5.6. Verify BGP best path selection algorithm works fine when
    routes are imported from ISR to default vrf and vice versa.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    build_config_from_json(tgen, topo)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    for addr_type in ADDR_TYPES:
        step(
            "Redistribute configured static routes into BGP process" " on R1/R2 and R3"
        )

        input_dict_1 = {}
        DUT = ["r1", "r2", "r3", "r4"]
        VRFS = ["ISR", "ISR", "default", "default"]
        AS_NUM = [100, 100, 300, 400]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_1.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Import from default vrf into vrf ISR on R1 and R2 as below")

        input_dict_vrf = {}
        DUT = ["r1", "r2"]
        VRFS = ["ISR", "ISR"]
        AS_NUM = [100, 100]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_vrf.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {"unicast": {"import": {"vrf": "default"}}}
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_vrf)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_default = {}
        DUT = ["r1", "r2"]
        VRFS = ["default", "default"]
        AS_NUM = [100, 100]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_default.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {"unicast": {"import": {"vrf": "ISR"}}}
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_default)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify ECMP/Next-hop/Imported routes Vs Locally originated "
        "routes/eBGP routes vs iBGP routes --already covered in almost"
        " all tests"
    )

    for addr_type in ADDR_TYPES:
        step("Verify Pre-emption")

        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_3[addr_type]]}]}
        }

        intf_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"]["interface"]
        intf_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"]["interface"]

        if addr_type == "ipv6" and "link_local" in PREFERRED_NEXT_HOP:
            nh_r3_r1 = get_frr_ipv6_linklocal(tgen, "r3", intf=intf_r3_r1)
            nh_r4_r1 = get_frr_ipv6_linklocal(tgen, "r4", intf=intf_r4_r1)
        else:
            nh_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]
            nh_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]

        result = verify_bgp_rib(
            tgen, addr_type, "r1", input_routes_r3, next_hop=[nh_r4_r1]
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Shutdown interface connected to r1 from r4:")
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, False)

    for addr_type in ADDR_TYPES:
        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_3[addr_type]]}]}
        }

        intf_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"]["interface"]
        intf_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"]["interface"]

        if addr_type == "ipv6" and "link_local" in PREFERRED_NEXT_HOP:
            nh_r3_r1 = get_frr_ipv6_linklocal(tgen, "r3", intf=intf_r3_r1)
            nh_r4_r1 = get_frr_ipv6_linklocal(tgen, "r4", intf=intf_r4_r1)
        else:
            nh_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]
            nh_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]

        step("Verify next-hop is changed")
        result = verify_bgp_rib(
            tgen, addr_type, "r1", input_routes_r3, next_hop=[nh_r3_r1]
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Bringup interface connected to r1 from r4:")
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, True)

    for addr_type in ADDR_TYPES:
        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_3[addr_type]]}]}
        }

        intf_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"]["interface"]
        intf_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"]["interface"]

        if addr_type == "ipv6" and "link_local" in PREFERRED_NEXT_HOP:
            nh_r3_r1 = get_frr_ipv6_linklocal(tgen, "r3", intf=intf_r3_r1)
            nh_r4_r1 = get_frr_ipv6_linklocal(tgen, "r4", intf=intf_r4_r1)
        else:
            nh_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]
            nh_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]

        step("Verify next-hop is not chnaged aftr shutdown:")
        result = verify_bgp_rib(
            tgen, addr_type, "r1", input_routes_r3, next_hop=[nh_r3_r1]
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Active-Standby scenario(as-path prepend and Local pref)")

    for addr_type in ADDR_TYPES:
        step("Create prefix-list")

        input_dict_pf = {
            "r1": {
                "prefix_lists": {
                    addr_type: {
                        "pf_ls_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": NETWORK3_4[addr_type],
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

    for addr_type in ADDR_TYPES:
        step("Create route-map to match prefix-list and set localpref 500")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_PATH1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 10,
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_{}".format(addr_type)
                                }
                            },
                            "set": {"locPrf": 500},
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Create route-map to match prefix-list and set localpref 600")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_PATH2_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 20,
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_{}".format(addr_type)
                                }
                            },
                            "set": {"locPrf": 600},
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_rma = {
            "r1": {
                "bgp": [
                    {
                        "local_as": "100",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r3": {
                                            "dest_link": {
                                                "r1-link1": {
                                                    "route_maps": [
                                                        {
                                                            "name": "rmap_PATH1_{}".format(
                                                                addr_type
                                                            ),
                                                            "direction": "in",
                                                        }
                                                    ]
                                                }
                                            }
                                        },
                                        "r4": {
                                            "dest_link": {
                                                "r1-link1": {
                                                    "route_maps": [
                                                        {
                                                            "name": "rmap_PATH2_{}".format(
                                                                addr_type
                                                            ),
                                                            "direction": "in",
                                                        }
                                                    ]
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_rma)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r1"
    attribute = "locPrf"

    for addr_type in ADDR_TYPES:
        step("Verify bestpath is installed as per highest localpref")

        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_4[addr_type]]}]}
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_routes_r3, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Create route-map to match prefix-list and set localpref 700")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_PATH1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 10,
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_{}".format(addr_type)
                                }
                            },
                            "set": {"locPrf": 700},
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Verify bestpath is changed as per highest localpref")

        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_4[addr_type]]}]}
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_routes_r3, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Create route-map to match prefix-list and set as-path prepend")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_PATH2_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 20,
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_{}".format(addr_type)
                                }
                            },
                            "set": {
                                "localpref": 700,
                                "path": {"as_num": "111", "as_action": "prepend"},
                            },
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    attribute = "path"

    for addr_type in ADDR_TYPES:
        step("Verify bestpath is changed as per shortest as-path")

        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_4[addr_type]]}]}
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_routes_r3, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_modify_route_map_match_set_clauses_p1(request):
    """
    TC13_CHAOS_4:
    1.5.13. Verify that Changing route-map configurations(match/set clauses) on
    the fly it takes immediate effect.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    build_config_from_json(tgen, topo)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    for addr_type in ADDR_TYPES:
        step(
            "Configure route-map to set community attribute for a specific"
            "prefix on R1 in vrf ISR"
        )

        input_dict_pf = {
            "r1": {
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
        "r1": {
            "bgp_community_lists": [
                {
                    "community_type": "expanded",
                    "action": "permit",
                    "name": "COMM",
                    "value": "100:100",
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_cl)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_XYZ_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pflist_ABC_{}".format(addr_type)
                                }
                            },
                            "set": {"community": {"num": "100:100"}},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step(
            "Apply this route-map on R1 to vrf ISR while redistributing the"
            " prefixes into BGP"
        )

        input_dict_1 = {}
        DUT = ["r1"]
        VRFS = ["ISR"]
        AS_NUM = [100]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_1.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
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
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step(
            "Configure another route-map for filtering the prefixes based on"
            " community attribute while importing into default vrf"
        )

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_IMP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 10,
                            "match": {"community_list": {"id": "COMM"}},
                            "set": {"community": {"num": "none"}},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step(
            "Apply the route-map while Importing vrf ISR's prefixes into "
            "default vrf on router R1:"
        )

        input_dict_isr = {}
        DUT = ["r1"]
        VRFS = ["default"]
        AS_NUM = [100]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_isr.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {"unicast": {"import": {"vrf": "ISR"}}}
                    },
                }
            )

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "import": {
                                    "vrf": "route-map rmap_IMP_{}".format(addr_type)
                                }
                            }
                        }
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_isr)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step(
            "Verify on R1 that only prefixes with community value 100:100"
            "in vrf ISR are imported to vrf default. While importing, the"
            " community value has been stripped off:"
        )

        input_routes_r1 = {
            "r1": {
                "static_routes": [
                    {"network": [NETWORK1_1[addr_type]], "vrf": "default"}
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Add set clause in route-map IMP:")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_IMP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 10,
                            "match": {"community_list": {"id": "COMM"}},
                            "set": {
                                "large_community": {"num": "100:100:100"},
                                "locPrf": 500,
                                "path": {"as_num": "100 100", "as_action": "prepend"},
                            },
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step(
            "Verify that as we continue adding different attributes "
            "step-by-step in route-map IMP those attributes gets "
            "attached to prefixes:"
        )

        input_routes_r1 = {
            "r1": {
                "static_routes": [
                    {"network": [NETWORK1_1[addr_type]], "vrf": "default"}
                ]
            }
        }

        input_dict_comm = {"largeCommunity": "100:100:100"}

        result = verify_bgp_community(
            tgen, addr_type, dut, [NETWORK1_1[addr_type]], input_dict_comm
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        input_rmap = {
            "r1": {
                "route_maps": {
                    "rmap_IMP_{}".format(addr_type): [{"set": {"locPrf": 500}}]
                }
            }
        }

        result = verify_bgp_attributes(
            tgen,
            addr_type,
            "r1",
            [NETWORK1_1[addr_type]],
            rmap_name="rmap_IMP_{}".format(addr_type),
            input_dict=input_rmap,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Change community-list to match a different value then " "100:100.")

    input_dict_cl = {
        "r1": {
            "bgp_community_lists": [
                {
                    "community_type": "expanded",
                    "action": "permit",
                    "name": "COMM",
                    "value": "100:100",
                    "delete": True,
                }
            ]
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_cl)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_routes_r1 = {
            "r1": {
                "static_routes": [
                    {"network": [NETWORK1_1[addr_type]], "vrf": "default"}
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Error : Routes are still " "present {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
