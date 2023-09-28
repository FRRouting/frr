#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test BGP Multi-VRF Dynamic Route Leaking:

1. Verify that dynamically imported routes are further advertised
    to iBGP peers(peer in cluster).
2. Verify matching a prefix based on community attribute and
    importing it by stripping off this value
3. Verify the route-map operation along with dynamic import command.
4. Verifying the JSON outputs for all supported commands
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
    step,
    create_route_maps,
    create_static_routes,
    create_prefix_lists,
    create_bgp_community_lists,
    create_interface_in_kernel,
    check_router_status,
    verify_cli_json,
    verify_fib_routes,
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
NETWORK1_3 = {"ipv4": "10.10.10.10/32", "ipv6": "10:10::10/128"}
NETWORK1_4 = {"ipv4": "10.10.10.100/32", "ipv6": "10:10::100/128"}

NETWORK2_1 = {"ipv4": "22.22.22.2/32", "ipv6": "22:22::2/128"}
NETWORK2_2 = {"ipv4": "22.22.22.22/32", "ipv6": "22:22::22/128"}
NETWORK2_3 = {"ipv4": "20.20.20.20/32", "ipv6": "20:20::20/128"}
NETWORK2_4 = {"ipv4": "20.20.20.200/32", "ipv6": "20:20::200/128"}

NETWORK3_1 = {"ipv4": "30.30.30.3/32", "ipv6": "30:30::3/128"}
NETWORK3_2 = {"ipv4": "30.30.30.30/32", "ipv6": "30:30::30/128"}
NETWORK3_3 = {"ipv4": "50.50.50.5/32", "ipv6": "50:50::5/128"}
NETWORK3_4 = {"ipv4": "50.50.50.50/32", "ipv6": "50:50::50/128"}

NETWORK4_1 = {"ipv4": "40.40.40.4/32", "ipv6": "40:40::4/128"}
NETWORK4_2 = {"ipv4": "40.40.40.40/32", "ipv6": "40:40::40/128"}
NETWORK4_3 = {"ipv4": "50.50.50.5/32", "ipv6": "50:50::5/128"}
NETWORK4_4 = {"ipv4": "50.50.50.50/32", "ipv6": "50:50::50/128"}

NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}
LOOPBACK_1 = {
    "ipv4": "10.0.0.7/24",
    "ipv6": "fd00:0:0:1::7/64",
}
LOOPBACK_2 = {
    "ipv4": "10.0.0.16/24",
    "ipv6": "fd00:0:0:3::5/64",
}
PREFERRED_NEXT_HOP = "global"


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
    json_file = "{}/bgp_vrf_dynamic_route_leak_topo1.json".format(CWD)
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
#   Local APIs
#
#####################################################


def disable_route_map_to_prefer_global_next_hop(tgen, topo):
    """
    This API is to remove prefer global route-map applied on neighbors

    Parameter:
    ----------
    * `tgen` : Topogen object
    * `topo` : Input JSON data

    Returns:
    --------
    True/errormsg

    """

    logger.info("Remove prefer-global rmap applied on neighbors")
    input_dict = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "ISR",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "100",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "100",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r4": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
        "r2": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "ISR",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "100",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "100",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r4": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
        "r3": {
            "bgp": [
                {
                    "local_as": "300",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "300",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
        "r4": {
            "bgp": [
                {
                    "local_as": "400",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r4-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "400",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r4-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase :Failed \n Error: {}".format(result)

    return True


#####################################################
#
#   Testcases
#
#####################################################


def test_dynamic_imported_routes_advertised_to_iBGP_peer_p0(request):
    """
    TC5_FUNC_5:
    1.5.5. Verify that dynamically imported routes are further advertised
    to iBGP peers(peer in cluster).
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    build_config_from_json(tgen, topo)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    for addr_type in ADDR_TYPES:

        step(
            "Redistribute configured static routes into BGP process" " on R1 and R3/R4"
        )

        input_dict_1 = {}
        DUT = ["r1", "r3", "r4"]
        VRFS = ["default", "default", "default"]
        AS_NUM = [100, 300, 400]

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

        step("Verify that R1 receives BGP routes from R3 and R4 in " "vrf default.")

        input_routes_r3 = {
            "r3": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK3_1[addr_type],
                            NETWORK3_2[addr_type],
                            NETWORK3_3[addr_type],
                            NETWORK3_4[addr_type],
                        ]
                    }
                ]
            }
        }

        input_routes_r4 = {
            "r4": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK4_1[addr_type],
                            NETWORK4_2[addr_type],
                            NETWORK4_3[addr_type],
                            NETWORK4_4[addr_type],
                        ]
                    }
                ]
            }
        }

        DUT = ["r1", "r2"]
        INPUT_DICT = [input_routes_r3, input_routes_r4]

        for dut, routes in zip(DUT, INPUT_DICT):
            result = verify_bgp_rib(tgen, addr_type, dut, routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

            result = verify_fib_routes(tgen, addr_type, dut, routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    for addr_type in ADDR_TYPES:

        step("Import from default vrf into vrf ISR on R1")

        input_dict_isr = {}
        DUT = ["r1", "r2"]
        VRFS = ["ISR", "ISR"]
        AS_NUM = [100, 100]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_isr.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {"unicast": {"import": {"vrf": "default"}}}
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_isr)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:

        step(
            "Verify that default vrf's imported routes are installed "
            "in RIB/FIB of vrf ISR on R1:"
        )

        input_routes_r3 = {
            "r3": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK3_1[addr_type],
                            NETWORK3_2[addr_type],
                            NETWORK3_3[addr_type],
                            NETWORK3_4[addr_type],
                        ],
                        "vrf": "ISR",
                    }
                ]
            }
        }

        input_routes_r4 = {
            "r4": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK4_1[addr_type],
                            NETWORK4_2[addr_type],
                            NETWORK4_3[addr_type],
                            NETWORK4_4[addr_type],
                        ],
                        "vrf": "ISR",
                    }
                ]
            }
        }

        INPUT_DICT_VRF = [input_routes_r3, input_routes_r4]

        for routes in INPUT_DICT_VRF:
            result = verify_bgp_rib(tgen, addr_type, "r1", routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

            result = verify_fib_routes(tgen, addr_type, "r1", routes)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    intf_r2_r1 = topo["routers"]["r2"]["links"]["r1-link1"]
    for addr_type in ADDR_TYPES:

        step(
            "Create a loopback10 interface on R1 with below IP address and "
            "associate with vrf ISR:"
        )

        create_interface_in_kernel(
            tgen,
            "r1",
            "loopback2",
            LOOPBACK_2[addr_type],
            "ISR",
        )

    for addr_type in ADDR_TYPES:

        step(
            "On router R1 Change the next-hop of static routes in vrf "
            "ISR to LOOPBACK_2"
        )

        input_routes_r1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_3[addr_type], NETWORK1_4[addr_type]],
                        "next_hop": "Null0",
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_routes_r1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        input_routes_r1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_3[addr_type], NETWORK1_4[addr_type]],
                        "next_hop": (intf_r2_r1[addr_type]).split("/")[0],
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_routes_r1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:

        step(
            "Verify that, though R1 originating BGP routes with next-hop"
            " 24.1.1.2/24::1:2, which is local to R2(but in default vrf)"
            ", R2 must receives and install all routes from R1 in vrf ISR."
        )
        step(
            "Verify on R2, that it now rejects 10.10.10.x routes originated "
            "from R1. As next-hop IP is local to R2's vrf ISR."
        )

        input_routes_r1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_3[addr_type], NETWORK1_4[addr_type]],
                        "vrf": "ISR",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Routes are still present \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:

        step("On router R1 delete static routes in vrf ISR to LOOPBACK_1")

        input_routes_r1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_3[addr_type], NETWORK1_4[addr_type]],
                        "next_hop": (intf_r2_r1[addr_type]).split("/")[0],
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_routes_r1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_dynamic_imported_matching_prefix_based_on_community_list_p0(request):
    """
    TC7_FUNC_7:
    1.5.7. Verify matching a prefix based on community attribute and
    importing it by stripping off this value
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

        input_dict_comm = {"community": "100:100"}

        result = verify_bgp_community(
            tgen,
            addr_type,
            dut,
            [NETWORK1_1[addr_type]],
            input_dict_comm,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n Error: Commnunity is not stipped off, {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:

        step("Remove/re-add route-map XYZ from redistribution.")

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
                                        "delete": True,
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
            "Verify that all the routes disappear from vrf default when "
            "route-map is removed from redistribution, and appear again "
            "when route-map is re-added to redistribution in vrf ISR."
        )

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
        ), "Testcase {} : Failed \n Error : Routes are still present \n {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:

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

        step("Remove/re-add route-map IMP form import statement.")

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
                                    "vrf": "route-map rmap_IMP_{}".format(addr_type),
                                    "delete": True,
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
            "Verify that when route-map IMP is removed all the prefixes of"
            " vrf ISR are imported to vrf default. However when route-map "
            "IMP is re-added only 11.11.11.1 and 11:11::1 (with community "
            "value) are imported."
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

        step("Delete/Re-add prefix-list ABC.")

        input_dict_pf = {
            "r1": {
                "prefix_lists": {
                    addr_type: {
                        "pflist_ABC_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": NETWORK1_1[addr_type],
                                "action": "permit",
                                "delete": True,
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
        ), "Testcase {} : Failed \n Error : Routes are still present \n {}".format(
            tc_name, result
        )

        input_dict_pf["r1"]["prefix_lists"][addr_type][
            "pflist_ABC_{}".format(addr_type)
        ][0]["delete"] = False

        result = create_prefix_lists(tgen, input_dict_pf)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        step("Delete/Re-add community-list COMM.")

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
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Error : Routes are still present \n {}".format(
            tc_name, result
        )

        input_dict_cl["r1"]["bgp_community_lists"][0]["delete"] = False

        result = create_bgp_community_lists(tgen, input_dict_cl)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        step("Delete/Re-add route-map XYZ.")

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
                            "delete": True,
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Error : Routes are still present \n {}".format(
            tc_name, result
        )

        input_dict_rm["r1"]["route_maps"]["rmap_XYZ_{}".format(addr_type)][0][
            "delete"
        ] = False

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        step("Delete/Re-add route-map IMP.")

        input_dict_rm2 = {
            "r1": {
                "route_maps": {
                    "rmap_IMP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "match": {"community_list": {"id": "COMM"}},
                            "set": {"community": {"num": "none"}},
                            "delete": True,
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_rm2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Error : Routes are still present \n {}".format(
            tc_name, result
        )

        input_dict_rm2["r1"]["route_maps"]["rmap_IMP_{}".format(addr_type)][0][
            "delete"
        ] = False

        result = create_route_maps(tgen, input_dict_rm2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_routemap_operatons_with_dynamic_import_p0(request):
    """
    TC8_FUNC_8:
    1.5.8. Verify the route-map operation along with dynamic import command.
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
                            "match": {"community_list": {"id": "COMM"}},
                            "set": {"community": {"num": "500:500"}},
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

        step("Applying route-map first followed by import VRF command.")
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
                        addr_type: {
                            "unicast": {"import": {"vrf": "ISR", "delete": True}}
                        }
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
            "Verify that until 'import VRF command' is not configured, "
            "routes are not imported. After configuring 'import VRF command'"
            " repeat step-4 for verification"
        )

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
        ), "Testcase {} : Failed \n Error : Routes are still present \n {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:

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

        step("Delete/re-add import vrf ISR command multiple times in default" "vrf.")

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
                        addr_type: {
                            "unicast": {"import": {"vrf": "ISR", "delete": True}}
                        }
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_isr)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Verify that when import vrf ISR command is deleted, "
            "all routes of vrf ISR disappear from default vrf and "
            "when it's re-configured, repeat step-4 for verification."
        )

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
        ), "Testcase {} : Failed \n Routes are still present, Error {}".format(
            tc_name, result
        )

        input_dict_isr["r1"]["bgp"][0]["address_family"][addr_type]["unicast"][
            "import"
        ]["delete"] = False

        result = create_router_bgp(tgen, topo, input_dict_isr)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, "r1", input_routes_r1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:

        step(
            "Delete and re-configure route-map IMP from global config when "
            "import and route-maps are applied in a ISR vrf."
        )

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_IMP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "match": {"community_list": {"id": "COMM"}},
                            "set": {"community": {"num": "500:500"}},
                            "delete": True,
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

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
        ), "Testcase {} : Failed \n Routes are still present, Error {}".format(
            tc_name, result
        )

        input_dict_rm["r1"]["route_maps"]["rmap_IMP_{}".format(addr_type)][0][
            "delete"
        ] = False

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_comm = {"community": "500:500"}

        result = verify_bgp_community(
            tgen, addr_type, dut, [NETWORK1_1[addr_type]], input_dict_comm
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_cli_json_p1(request):
    """
    TC8_FUNC_9:
    1.5.9. Verifying the JSON outputs for all supported commands:
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    build_config_from_json(tgen, topo)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    input_dict = {
        "r1": {
            "cli": [
                "show bgp vrf default ipv4 summary",
                "show bgp vrf all ipv6 summary",
                "show bgp neighbors",
            ]
        }
    }

    result = verify_cli_json(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
