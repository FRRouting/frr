#!/usr/bin/env python

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Following tests are covered to test BGP Multi-VRF:

FUNC_1:
    Within each VRF, each address must be unambiguous on DUT.
FUNC_2:
    Different VRFs can have ambiguous/overlapping
    addresses on DUT.
FUNC_3:
    Create static routes(IPv4+IPv6) associated to specific VRFs
    and verify on DUT that same prefixes are present in corresponding
    routing table.
FUNC_4_&_5:
    Each VRF should be mapped with a unique VLAN on DUT
    for traffic segregation, when using a single physical interface.
FUNC_6:
    Advertise same set of prefixes from different VRFs
    and verify on remote router that these prefixes are not
    leaking to each other
FUNC_7:
    Redistribute Static routes and verify on remote routers
    that routes are advertised within specific VRF instance, which
    those static routes belong to.
FUNC_8:
    Test end to end traffic isolation based on VRF tables.
FUNC_9:
    Use static routes for inter-vrf communication
    (route-leaking) on DUT.
FUNC_10:
    Verify intra-vrf and inter-vrf communication between
    iBGP peers.
FUNC_11:
    Verify intra-vrf and inter-vrf communication
    between eBGP peers.
FUNC_12_a:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
FUNC_12_b:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
FUNC_12_c:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
FUNC_12_d:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
FUNC_12_e:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
FUNC_12_f:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
FUNC_13:
    Configure a route-map on DUT to match traffic based
    on a VRF interfaces.
FUNC_14:
    Test VRF-lite with Static+BGP originated routes.
FUNC_15:
    Configure prefix-lists on DUT and apply to BGP peers to
    permit/deny prefixes.
FUNC_16_1:
    Configure a route-map on DUT to match traffic based various
    match/set causes.
FUNC_16_2:
    Configure a route-map on DUT to match traffic based various
    match/set causes.
FUNC_16_3:
    Configure a route-map on DUT to match traffic based various
    match/set causes.
"""

import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topotest import iproute2_is_vrf_capable
from lib.common_config import (
    step,
    verify_rib,
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    create_route_maps,
    create_static_routes,
    create_prefix_lists,
    create_interface_in_kernel,
    create_bgp_community_lists,
    check_router_status,
    apply_raw_config,
    required_linux_kernel_version,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_rib,
    create_router_bgp,
    verify_bgp_community,
    verify_bgp_convergence,
    verify_best_path_as_per_bgp_attribute,
)
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


# Global variables
NETWORK1_1 = {"ipv4": "1.1.1.1/32", "ipv6": "1::1/128"}
NETWORK1_2 = {"ipv4": "1.1.1.2/32", "ipv6": "1::2/128"}
NETWORK2_1 = {"ipv4": "2.1.1.1/32", "ipv6": "2::1/128"}
NETWORK2_2 = {"ipv4": "2.1.1.2/32", "ipv6": "2::2/128"}
NETWORK3_1 = {"ipv4": "3.1.1.1/32", "ipv6": "3::1/128"}
NETWORK3_2 = {"ipv4": "3.1.1.2/32", "ipv6": "3::2/128"}
NETWORK4_1 = {"ipv4": "4.1.1.1/32", "ipv6": "4::1/128"}
NETWORK4_2 = {"ipv4": "4.1.1.2/32", "ipv6": "4::2/128"}
NETWORK5_1 = {"ipv4": "5.1.1.1/32", "ipv6": "5::1/128"}
NETWORK5_2 = {"ipv4": "5.1.1.2/32", "ipv6": "5::2/128"}
NETWORK6_1 = {"ipv4": "6.1.1.1/32", "ipv6": "6::1/128"}
NETWORK6_2 = {"ipv4": "6.1.1.2/32", "ipv6": "6::2/128"}
NETWORK7_1 = {"ipv4": "7.1.1.1/32", "ipv6": "7::1/128"}
NETWORK7_2 = {"ipv4": "7.1.1.2/32", "ipv6": "7::2/128"}
NETWORK8_1 = {"ipv4": "8.1.1.1/32", "ipv6": "8::1/128"}
NETWORK8_2 = {"ipv4": "8.1.1.2/32", "ipv6": "8::2/128"}

NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}

LOOPBACK_1 = {
    "ipv4": "10.10.10.10/32",
    "ipv6": "10::10:10/128",
}
LOOPBACK_2 = {
    "ipv4": "20.20.20.20/32",
    "ipv6": "20::20:20/128",
}


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # iproute2 needs to support VRFs for this suite to run.
    if not iproute2_is_vrf_capable():
        pytest.skip("Installed iproute2 version does not support VRFs")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_multi_vrf_topo1.json".format(CWD)
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


#####################################################
#
#   Testcases
#
#####################################################


def test_address_unambiguous_within_each_vrf_p0(request):
    """
    FUNC_1:
    Within each VRF, each address must be unambiguous on DUT.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure a set of static routes(IPv4+IPv6) in " "RED_A on router RED-1")

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure the same static routes(IPv4+IPv6) with a TAG value"
        "of 500 in RED_A on router RED-1"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "tag": 500,
                        "vrf": "RED_A",
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {
        "red1": {
            "bgp": {
                "local_as": "500",
                "vrf": "RED_A",
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that static routes(IPv4+IPv6) is overridden and doesn't"
        " have duplicate entries within VRF RED_A on router RED-1"
    )

    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "tag": 500,
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, tag=500)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Make sure routes are not present in global routing table")

    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n Expected Behaviour: Routes are not "
            "present on Global Routing table \n Error {}".format(tc_name, result)
        )

    write_test_footer(tc_name)


def test_ambiguous_overlapping_addresses_in_different_vrfs_p0(request):
    """
    FUNC_2:
    Different VRFs can have ambiguous/overlapping
    addresses on DUT.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure a set of static routes(IPv4+IPv6) in vrf RED_A" "on router RED-1")

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure the same static routes(IPv4+IPv6) with a"
        " TAG value of 500 in vrf RED_B on router RED-1"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "tag": 500,
                        "vrf": "RED_B",
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that RED_A has the static routes without any" " TAG value")

    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_1, tag=500, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Routes are present with tag value 500 \n Error: {}".format(tc_name, result)
        )
        logger.info("Expected Behavior: {}".format(result))

    step(
        "Verify that RED_B has the same routes with TAG value "
        "500 on same device RED-1"
    )

    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "tag": 500,
                        "vrf": "RED_B",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, tag=500)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Make sure routes are not present in global routing table")

    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n Expected Behaviour: Routes are not "
            "present on Global Routing table \n Error {}".format(tc_name, result)
        )

    write_test_footer(tc_name)


def test_static_routes_associated_to_specific_vrfs_p0(request):
    """
    FUNC_3:
    Create static routes(IPv4+IPv6) associated to specific VRFs
    and verify on DUT that same prefixes are present in corresponding
    routing table.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Configure a set of unique static(IPv4+IPv6) routes in vrf"
        " RED_A on router RED-1"
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure set of unique static routes(IPv4+IPv6) in vrf "
        "RED_B on router RED-1"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that static routes 1.x.x.x/32 and 1::x/128 appear " "in VRF RED_A table"
    )
    step(
        "Verify that static routes 2.x.x.x/32 and 2::x/128 appear " "in VRF RED_B table"
    )

    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Verify that static routes 1.x.x.x/32 and 1::x/128 appear "
        "in VRF BLUE_A table"
    )
    step(
        "Verify that static routes 2.x.x.x/32 and 2::x/128 appear "
        "in VRF BLUE_B table"
    )

    for addr_type in ADDR_TYPES:
        dut = "blue1"
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Make sure routes are not present in global routing table")

    for addr_type in ADDR_TYPES:
        dut = "blue1"
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n Expected Behaviour: Routes are not "
            "present on Global Routing table \n Error {}".format(tc_name, result)
        )

    write_test_footer(tc_name)


def test_vrf_with_unique_physical_interface_p0(request):
    """
    FUNC_4_&_5:
    Each VRF should be mapped with a unique VLAN on DUT
    for traffic segregation, when using a single physical interface.

    Each VRF should be mapped to a unique physical
    interface(without VLAN tagging) on DUT for traffic segregation.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "R1 is receiving routes in 4 VRFs instances "
        "(RED_A, RED_B, BLUE_A, BLUE_B) from RED_1 and BLUE_1."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise a set of unique BGP prefixes(IPv4+IPv6) from "
        "routers RED_1 & BLUE_1 in each VRF using static redistribution"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Each VRF table on R2 should maintain it's associated "
        "routes and and accordingly install in zebra"
    )

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_prefixes_leaking_p0(request):
    """
    FUNC_6:
    Advertise same set of prefixes from different VRFs
    and verify on remote router that these prefixes are not
    leaking to each other
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure a set of static routes(IPv4+IPv6) in vrf " "RED_A on router RED-1")

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            },
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    }
                ]
            },
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure a set of static routes(IPv4+IPv6) in vrf " "BLUE_A on router BLUE-1"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    }
                ]
            },
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    }
                ]
            },
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure the same set of static routes with a "
        "metric value of 123 in vrf RED_B on router RED-1"
    )
    step(
        "Configure the same set of static routes with a "
        "metric value of 123 in vrf BLUE_B on router BLUE-1"
    )

    input_dict_3 = {
        "red1": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"metric": 123},
                                    }
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"metric": 123},
                                    }
                                ]
                            }
                        },
                    },
                },
            ]
        },
        "blue1": {
            "bgp": [
                {
                    "local_as": "800",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                },
                {
                    "local_as": "800",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"metric": 123},
                                    }
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"metric": 123},
                                    }
                                ]
                            }
                        },
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on R1 that RED_A doesn't receive any static "
        "route with metric value 123"
    )

    for addr_type in ADDR_TYPES:
        dut = "r1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            },
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    }
                ]
            },
        }

        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    }
                ]
            },
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    }
                ]
            },
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(
            tgen, addr_type, dut, input_dict_1, metric=123, expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Routes are present with metric value 123 \n Error: {}".format(
                tc_name, result
            )
        )
        logger.info("Expected Behavior: {}".format(result))

        result = verify_rib(tgen, addr_type, dut, input_dict_2, metric=123)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(
            tgen, addr_type, dut, input_dict_2, metric=0, expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Routes are present with metric value 0 \n Error: {}".format(
                tc_name, result
            )
        )
        logger.info("Expected Behavior: {}".format(result))

    write_test_footer(tc_name)


def test_static_routes_advertised_within_specific_vrf_p0(request):
    """
    FUNC_7:
    Redistribute Static routes and verify on remote routers
    that routes are advertised within specific VRF instance, which
    those static routes belong to.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise a set of unique BGP prefixes(IPv4+IPv6) "
        "through static redistribution into VRF RED_A and RED_B"
        " from router RED-1."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise same as above set of BGP prefixes(IPv4+IPv6) "
        "through static redistribution into VRF BLUE_A and BLUE_B"
        " from router BLUE-1."
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that static routes are installed into vrfs RED_A"
        "and RED_B tables only, not in global routing table of RED_1"
    )

    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1, protocol="static")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Verify that static routes are installed into vrfs BLUE_A and"
        "BLUE_B tables only, not in global routing table of BLUE_1."
    )

    for addr_type in ADDR_TYPES:
        dut = "blue1"
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, protocol="static")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Verify on router R1, that each set of prefixes is received"
        " into associated vrf tables only."
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        dut = "r1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_end_to_end_traffic_isolation_p0(request):
    """
    FUNC_8:
    Test end to end traffic isolation based on VRF tables.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from RED_1 "
        "in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from from BLUE_1 in"
        " vrf instances(BLUE_A and BLUE_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Use below commands to send prefixes with as-path prepend"
        "VRF BLUE_A and BLUE_B from router BLUE-1."
    )

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "blue1": {
                "route_maps": {
                    "ASP_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {"path": {"as_num": 123, "as_action": "prepend"}},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Apply route-map to neighbours")

    input_dict_5 = {
        "blue1": {
            "bgp": [
                {
                    "local_as": "800",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "blue1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "ASP_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "blue1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "ASP_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "800",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "blue1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "ASP_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "blue1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "ASP_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on R1 that BLUE_A and BLUE_B VRFs are receiving the"
        " prefixes with as-path 123 prepended."
    )

    for addr_type in ADDR_TYPES:
        dut = "r1"
        input_dict_6 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_6)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_6)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        dut = "r1"
        input_dict_7 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Use below commands to send prefixes with as-path prepend VRF"
        " BLUE_A and BLUE_B from router BLUE-1."
    )

    input_dict_6 = {
        "red2": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link1": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link1": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link2": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link2": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
        "blue2": {
            "bgp": [
                {
                    "local_as": "800",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link1": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link1": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "800",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link2": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link2": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_6)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that router RED-2 receives the prefixes in respective" " VRF tables.")

    for addr_type in ADDR_TYPES:
        dut = "red2"
        input_dict_6 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_6)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_6)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        dut = "blue2"
        input_dict_7 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_static_routes_for_inter_vrf_route_leaking_p0(request):
    """
    FUNC_9:
    Use static routes for inter-vrf communication
    (route-leaking) on DUT.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Configure unique loopback interfaces in VRFs RED_A "
        "and RED_B on router RED_1."
    )

    for addr_type in ADDR_TYPES:
        create_interface_in_kernel(
            tgen,
            "red1",
            "loopback1",
            LOOPBACK_1[addr_type],
            "RED_A",
        )
        create_interface_in_kernel(
            tgen,
            "red1",
            "loopback2",
            LOOPBACK_2[addr_type],
            "RED_B",
        )

    step(
        "Create a static routes in vrf RED_B on router RED_1 pointing"
        " next-hop as interface's IP in vrf RED_A"
    )

    intf_red1_r11 = topo["routers"]["red1"]["links"]["r1-link1"]["interface"]
    intf_red1_r10 = topo["routers"]["red1"]["links"]["r1-link2"]["interface"]
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": LOOPBACK_1[addr_type],
                        "interface": intf_red1_r10,
                        "nexthop_vrf": "RED_B",
                        "vrf": "RED_A",
                    },
                    {
                        "network": LOOPBACK_2[addr_type],
                        "interface": intf_red1_r11,
                        "nexthop_vrf": "RED_A",
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that static routes are installed into vrfs RED_A"
        "and RED_B tables only, not in global routing table of RED_1"
    )
    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": LOOPBACK_1[addr_type],
                        "interface": intf_red1_r10,
                        "nexthop_vrf": "RED_B",
                        "vrf": "RED_A",
                    },
                    {
                        "network": LOOPBACK_2[addr_type],
                        "interface": intf_red1_r11,
                        "nexthop_vrf": "RED_A",
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1, protocol="static")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_inter_vrf_and_intra_vrf_communication_iBGP_p0(request):
    """
    FUNC_10:
    Verify intra-vrf and inter-vrf communication between
    iBGP peers.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Configure unique loopback IP(IPv4+IPv6) in vrf RED_A on router"
        " R1 and advertise it in BGP process using redistribute "
        "connected command."
    )

    for addr_type in ADDR_TYPES:
        create_interface_in_kernel(
            tgen,
            "r1",
            "loopback1",
            LOOPBACK_1[addr_type],
            "RED_A",
        )

        create_interface_in_kernel(
            tgen,
            "r1",
            "loopback2",
            LOOPBACK_2[addr_type],
            "BLUE_A",
        )

    step(
        "Create a static routes in vrf RED_B on router RED_1 pointing"
        " next-hop as interface's IP in vrf RED_A"
    )

    intf_r2_r12 = topo["routers"]["r2"]["links"]["r1-link1"]["interface"]
    intf_r2_r10 = topo["routers"]["r2"]["links"]["r1-link3"]["interface"]
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": LOOPBACK_2[addr_type],
                        "interface": intf_r2_r10,
                        "nexthop_vrf": "BLUE_A",
                        "vrf": "RED_A",
                    },
                    {
                        "network": LOOPBACK_1[addr_type],
                        "interface": intf_r2_r12,
                        "nexthop_vrf": "RED_A",
                        "vrf": "BLUE_A",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute connected..")

    input_dict_3 = {}
    for dut in ["r1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        VRFS = ["RED_A", "BLUE_A"]
        AS_NUM = [100, 100]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "connected"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "connected"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["r2"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        VRFS = ["RED_A", "BLUE_A"]
        AS_NUM = [100, 100]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that static routes are installed into vrfs RED_A"
        "and RED_B tables only, not in global routing table of RED_1"
    )

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict = {
            "r2": {
                "static_routes": [
                    {
                        "network": LOOPBACK_2[addr_type],
                        "interface": intf_r2_r10,
                        "nexthop_vrf": "BLUE_A",
                        "vrf": "RED_A",
                    },
                    {
                        "network": LOOPBACK_1[addr_type],
                        "interface": intf_r2_r12,
                        "nexthop_vrf": "RED_A",
                        "vrf": "BLUE_A",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_inter_vrf_and_intra_vrf_communication_eBGP_p0(request):
    """
    FUNC_11:
    Verify intra-vrf and inter-vrf communication
    between eBGP peers.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Configure unique loopback IP(IPv4+IPv6) in vrf RED_A on router"
        " R2 and advertise it in BGP process using redistribute "
        "connected command."
    )

    step(
        "Configure unique loopback IP(IPv4+IPv6) in vrf BLUE_A on router"
        " R2 and advertise it in BGP process using redistribute "
        "connected command."
    )

    for addr_type in ADDR_TYPES:
        create_interface_in_kernel(
            tgen,
            "r2",
            "loopback1",
            LOOPBACK_1[addr_type],
            "RED_A",
        )
        create_interface_in_kernel(
            tgen,
            "r2",
            "loopback2",
            LOOPBACK_2[addr_type],
            "BLUE_A",
        )

    step(
        "Create a static routes in vrf RED_B on router RED_1 pointing"
        " next-hop as interface's IP in vrf RED_A"
    )

    intf_r3_r21 = topo["routers"]["r3"]["links"]["r2-link1"]["interface"]
    intf_r3_r23 = topo["routers"]["r3"]["links"]["r2-link3"]["interface"]
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r3": {
                "static_routes": [
                    {
                        "network": LOOPBACK_2[addr_type],
                        "interface": intf_r3_r23,
                        "nexthop_vrf": "BLUE_A",
                        "vrf": "RED_A",
                    },
                    {
                        "network": LOOPBACK_1[addr_type],
                        "interface": intf_r3_r21,
                        "nexthop_vrf": "RED_A",
                        "vrf": "BLUE_A",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["r3"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        VRFS = ["RED_A", "BLUE_A"]
        AS_NUM = [200, 200]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Redistribute connected..")

    input_dict_3 = {}
    for dut in ["r2"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        VRFS = ["RED_A", "BLUE_A"]
        AS_NUM = [100, 100]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "connected"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "connected"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that static routes are installed into vrfs RED_A"
        "and RED_B tables only, not in global routing table of RED_1"
    )

    for addr_type in ADDR_TYPES:
        dut = "r3"
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": LOOPBACK_2[addr_type],
                        "interface": intf_r3_r23,
                        "nexthop_vrf": "BLUE_A",
                        "vrf": "RED_A",
                    },
                    {
                        "network": LOOPBACK_1[addr_type],
                        "interface": intf_r3_r21,
                        "nexthop_vrf": "RED_A",
                        "vrf": "BLUE_A",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_route_map_within_vrf_to_alter_bgp_attribute_nexthop_p0(request):
    """
    FUNC_12_a:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise a set of BGP prefixes(IPv4+IPv6) from RED_1 and"
        " RED_2 in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise same set of BGP prefixes(IPv4+IPv6) from BLUE_1 and"
        "BLUE_2 in vrf instances(BLUE_A and BLUE_B)"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that within vrf instances, BGP best path selection"
        " algorithm remains intact and doesn't affect any other VRFs"
        " routing decision."
    )

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Delete nexthop-self configure from r1")

    input_dict_4 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link1": {"next_hop_self": False}
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
                                            "r1-link1": {"next_hop_self": False}
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link2": {"next_hop_self": False}
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
                                            "r1-link2": {"next_hop_self": False}
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link3": {"next_hop_self": False}
                                        }
                                    },
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link3": {"next_hop_self": False}
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link4": {"next_hop_self": False}
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
                                            "r1-link4": {"next_hop_self": False}
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that within vrf instances, BGP best path selection"
        " algorithm remains intact and doesn't affect any other VRFs"
        " routing decision."
    )

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Expected Behaviour: Routes are rejected because nexthop-self config is deleted \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Expected Behaviour: Routes are rejected because nexthop-self config is deleted \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


@pytest.mark.parametrize("attribute", ["locPrf", "weight", "metric"])
def test_route_map_within_vrf_to_alter_bgp_attribute_p0(request, attribute):
    """
    FUNC_12_b/c/d:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise a set of BGP prefixes(IPv4+IPv6) from RED_1 and"
        " RED_2 in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            },
            "red2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            },
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise same set of BGP prefixes(IPv4+IPv6) from BLUE_1 and"
        "BLUE_2 in vrf instances(BLUE_A and BLUE_B)"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            },
            "blue2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            },
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "red2", "blue1", "blue2"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure a route-maps to influence BGP parameters - " " Local Preference")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "route_maps": {
                    "rmap_r1_{}".format(addr_type): [
                        {"action": "permit", "set": {attribute: 120}}
                    ],
                    "rmap_r3_{}".format(addr_type): [
                        {"action": "permit", "set": {attribute: 150}}
                    ],
                }
            }
        }

        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure neighbor for route map")
    input_dict_4 = {
        "r2": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r3_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r3_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r3_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r3_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r3_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r3_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link4": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link4": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r3_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link4": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {
                                        "dest_link": {
                                            "r2-link4": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r3_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that within vrf instances, BGP best path selection"
        " algorithm remains intact and doesn't affect any other VRFs"
        " routing decision."
    )

    dut = "r2"
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_dict_1, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_dict_2, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_route_map_within_vrf_to_alter_bgp_attribute_aspath_p0(request):
    """
    FUNC_12_e:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise a set of BGP prefixes(IPv4+IPv6) from RED_1 and"
        " RED_2 in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            },
            "red2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            },
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise same set of BGP prefixes(IPv4+IPv6) from BLUE_1 and"
        "BLUE_2 in vrf instances(BLUE_A and BLUE_B)"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            },
            "blue2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            },
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "red2", "blue1", "blue2"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure a route-maps to influence BGP parameters - " " Local Preference")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r2": {
                "route_maps": {
                    "rmap_r1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {
                                "path": {"as_num": "111 222", "as_action": "prepend"}
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

    step("Configure neighbor for route map")
    input_dict_4 = {
        "r2": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {"dest_link": {"r2-link1": {}}},
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {"dest_link": {"r2-link1": {}}},
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {"dest_link": {"r2-link2": {}}},
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {"dest_link": {"r2-link2": {}}},
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {"dest_link": {"r2-link3": {}}},
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {"dest_link": {"r2-link3": {}}},
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link4": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {"dest_link": {"r2-link4": {}}},
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link4": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "r3": {"dest_link": {"r2-link4": {}}},
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that within vrf instances, BGP best path selection"
        " algorithm remains intact and doesn't affect any other VRFs"
        " routing decision."
    )

    dut = "r2"
    attribute = "path"
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_dict_1, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_dict_2, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_route_map_within_vrf_to_alter_bgp_attribute_lcomm_p0(request):
    """
    FUNC_12_f:
    Configure route-maps within a VRF, to alter BGP attributes.
    Verify that route-map doesn't affect any other VRF instances'
    routing on DUT.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise a set of BGP prefixes(IPv4+IPv6) from RED_1 and"
        " RED_2 in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            },
            "red2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            },
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise same set of BGP prefixes(IPv4+IPv6) from BLUE_1 and"
        "BLUE_2 in vrf instances(BLUE_A and BLUE_B)"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            },
            "blue2": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            },
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "red2", "blue1", "blue2"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure a route-maps to influence BGP parameters - " " Large-community")

    step("Create standard large commumity-list in r2")

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r2": {
                "bgp_community_lists": [
                    {
                        "community_type": "standard",
                        "action": "permit",
                        "name": "rmap_lcomm_{}".format(addr_type),
                        "value": "1:1:1 1:2:3 2:1:1 2:2:2",
                        "large": True,
                    }
                ]
            }
        }
        result = create_bgp_community_lists(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Create route-maps in red1 and r1")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "red1": {
                "route_maps": {
                    "rmap_red1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {
                                "large_community": {"num": "1:1:1 1:2:3 2:1:1 2:2:2"}
                            },
                        }
                    ]
                }
            },
            "r2": {
                "route_maps": {
                    "rmap_r1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "match": {
                                "large_community_list": {
                                    "id": "rmap_lcomm_" + addr_type
                                }
                            },
                        }
                    ]
                }
            },
        }
        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure neighbor for route map in red1")

    input_dict_4 = {
        "red1": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_red1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_red1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_red1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_red1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure neighbor for route map in r2")

    input_dict_4 = {
        "r2": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link3": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link4": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r2-link4": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "All the prefixes advertised from RED_1 and BLUE_1 should carry"
        " attributes set by outbound route-maps within specific vrfs. "
        "Router R1 should be able to match and permit/deny those "
        "prefixes based on received attributes. Please use below "
        "commands to verify."
    )

    input_dict = {
        "largeCommunity": "1:1:1 1:2:3 2:1:1 2:2:2",
    }

    for addr_type in ADDR_TYPES:
        vrf = "RED_A"
        routes = [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]]
        result = verify_bgp_community(tgen, addr_type, "r2", routes, input_dict, vrf)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        vrf = "RED_B"
        routes = [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]]
        result = verify_bgp_community(tgen, addr_type, "r2", routes, input_dict, vrf)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_route_map_match_traffic_based_on_vrf_p0(request):
    """
    FUNC_13:
    Configure a route-map on DUT to match traffic based
    on a VRF interfaces.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from RED_1 "
        "in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from from BLUE_1 in"
        " vrf instances(BLUE_A and BLUE_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure a route-map on R1 to match the prefixes "
        "coming from vrf RED_A and set as-prepend to these routes."
    )

    input_dict_4 = {
        "r1": {
            "route_maps": {
                "ABC": [
                    {
                        "action": "permit",
                        "match": {"source-vrf": "RED_A"},
                        "set": {"path": {"as_num": 1, "as_action": "prepend"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "On R1, import the routes form vrf RED_A and RED_B to BLUE_A and"
        " apply the route-map under vrf BLUE_A while importing"
    )

    raw_config = {
        "r1": {
            "raw_config": [
                "router bgp 100 vrf BLUE_A",
                "address-family ipv4 unicast",
                "import vrf RED_A",
                "import vrf RED_B",
                "import vrf route-map ABC",
                "address-family ipv6 unicast",
                "import vrf RED_A",
                "import vrf RED_B",
                "import vrf route-map ABC",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "All the prefixes advertised from RED_1 and BLUE_1 in vrfs "
        "RED_B and BLUE_B must prepend the AS number in as-path on R2."
    )

    for addr_type in ADDR_TYPES:
        input_dict_7 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, "r1", input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_vrf_lite_with_static_bgp_originated_routes_p0(request):
    """
    FUNC_14:
    Test VRF-lite with Static+BGP originated routes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from from RED_1"
        " in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from from BLUE_1 in"
        " vrf instances(BLUE_A and BLUE_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    input_dict_3 = {
        "red1": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK5_1["ipv4"]]
                                        + [NETWORK5_2["ipv4"]]
                                    }
                                ],
                                "redistribute": [{"redist_type": "static"}],
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK5_1["ipv6"]]
                                        + [NETWORK5_2["ipv6"]]
                                    }
                                ],
                                "redistribute": [{"redist_type": "static"}],
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK6_1["ipv4"]]
                                        + [NETWORK6_2["ipv4"]]
                                    }
                                ],
                                "redistribute": [{"redist_type": "static"}],
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK6_1["ipv6"]]
                                        + [NETWORK6_2["ipv6"]]
                                    }
                                ],
                                "redistribute": [{"redist_type": "static"}],
                            }
                        },
                    },
                },
            ]
        },
        "blue1": {
            "bgp": [
                {
                    "local_as": "800",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK7_1["ipv4"]]
                                        + [NETWORK7_2["ipv4"]]
                                    }
                                ],
                                "redistribute": [{"redist_type": "static"}],
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK7_1["ipv6"]]
                                        + [NETWORK7_2["ipv6"]]
                                    }
                                ],
                                "redistribute": [{"redist_type": "static"}],
                            }
                        },
                    },
                },
                {
                    "local_as": "800",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK8_1["ipv4"]]
                                        + [NETWORK8_2["ipv4"]]
                                    }
                                ],
                                "redistribute": [{"redist_type": "static"}],
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK8_1["ipv6"]]
                                        + [NETWORK8_2["ipv6"]]
                                    }
                                ],
                                "redistribute": [{"redist_type": "static"}],
                            }
                        },
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Static routes must be installed in associated VRF" " table only.")

    for addr_type in ADDR_TYPES:
        dut = "r1"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_3)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "All the routers must receive advertised as well as "
        "redistributed(static) prefixes in associated VRF tables."
    )

    for addr_type in ADDR_TYPES:
        dut = "r1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_prefix_list_to_permit_deny_prefixes_p0(request):
    """
    FUNC_15:
    Configure prefix-lists on DUT and apply to BGP peers to
    permit/deny prefixes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from from RED_1"
        " in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from from BLUE_1 in"
        " vrf instances(BLUE_A and BLUE_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify routes are present before applying prefix-list")
    for addr_type in ADDR_TYPES:
        dut = "r1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "On routers RED_1 and BLUE_1, configure prefix-lists to permit"
        " 4 prefixes and deny 1 prefix x.x.x.5. Apply these in outbound"
        "direction for each neighbour."
    )

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "red1": {
                "prefix_lists": {
                    addr_type: {
                        "pflist_red1_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": NETWORK1_1[addr_type],
                                "action": "permit",
                            },
                            {
                                "seqid": 11,
                                "network": NETWORK2_1[addr_type],
                                "action": "permit",
                            },
                            {
                                "seqid": 12,
                                "network": NETWORK1_2[addr_type],
                                "action": "deny",
                            },
                            {
                                "seqid": 13,
                                "network": NETWORK2_2[addr_type],
                                "action": "deny",
                            },
                        ]
                    }
                }
            },
            "blue1": {
                "prefix_lists": {
                    addr_type: {
                        "pflist_blue1_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": NETWORK1_1[addr_type],
                                "action": "permit",
                            },
                            {
                                "seqid": 11,
                                "network": NETWORK2_1[addr_type],
                                "action": "permit",
                            },
                            {
                                "seqid": 12,
                                "network": NETWORK1_2[addr_type],
                                "action": "deny",
                            },
                            {
                                "seqid": 13,
                                "network": NETWORK2_2[addr_type],
                                "action": "deny",
                            },
                        ]
                    }
                }
            },
            "r1": {
                "prefix_lists": {
                    addr_type: {
                        "pflist_r1_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": NETWORK1_1[addr_type],
                                "action": "permit",
                            },
                            {
                                "seqid": 11,
                                "network": NETWORK2_1[addr_type],
                                "action": "deny",
                            },
                        ]
                    }
                }
            },
        }
        result = create_prefix_lists(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    input_dict_5 = {
        "red1": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_red1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_red1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_red1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_red1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
        "blue1": {
            "bgp": [
                {
                    "local_as": "800",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "blue1-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_blue1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "blue1-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_blue1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "800",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "blue1-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_blue1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "blue1-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_blue1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that within vrf instances, each BGP neighbor receives 1"
        " prefixes in routing table and drops (x.x.x.2)."
    )

    for addr_type in ADDR_TYPES:
        dut = "r1"
        permitted_routes = {
            "red1": {
                "static_routes": [
                    {"network": [NETWORK1_1[addr_type]], "vrf": "RED_A"},
                    {"network": [NETWORK2_1[addr_type]], "vrf": "RED_B"},
                ]
            }
        }

        denied_routes = {
            "red1": {
                "static_routes": [
                    {"network": [NETWORK1_2[addr_type]], "vrf": "RED_A"},
                    {"network": [NETWORK2_2[addr_type]], "vrf": "RED_B"},
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, permitted_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, denied_routes, expected=False)
        assert result is not True, "Testcase {} : Failed \n"
        "{}:Expected behaviour: Routes are denied by prefix-list \nError {}".format(
            tc_name, result
        )

    step(
        "On router R1, configure prefix-lists to permit 2 "
        "prefixes(x.x.x.1-2) and deny 2 prefix(x.x.x.3-4). Apply"
        " these in inbound direction for each neighbour."
    )

    input_dict_6 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_r1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "prefix_lists": [
                                                    {
                                                        "name": "pflist_r1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_6)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that within vrf instances, each BGP neighbor installs"
        " only 1 prefix (x.x.x.1)."
    )
    for addr_type in ADDR_TYPES:
        dut = "r2"
        permitted_routes = {
            "red1": {
                "static_routes": [{"network": [NETWORK1_1[addr_type]], "vrf": "RED_A"}]
            }
        }

        denied_routes = {
            "red1": {
                "static_routes": [{"network": [NETWORK2_1[addr_type]], "vrf": "RED_A"}]
            }
        }

        result = verify_rib(tgen, addr_type, dut, permitted_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, denied_routes, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \nExpected behaviour: Routes are denied by prefix-list \nError {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_route_map_set_and_match_tag_p0(request):
    """
    FUNC_16_1:
    Configure a route-map on DUT to match traffic based various
    match/set causes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from RED_1"
        " in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "tag": 4001,
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise same set of BGP prefixes(IPv4+IPv6) from BLUE_1 and"
        "BLUE_2 in vrf instances(BLUE_A and BLUE_B)"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "tag": 4001,
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure a route-maps to match tag")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "red1": {
                "route_maps": {
                    "rmap1_{}".format(addr_type): [
                        {"action": "permit", "match": {addr_type: {"tag": "4001"}}}
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure neighbor for route map")
    input_dict_4 = {
        "red1": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that within vrf instances, BGP best path selection"
        " algorithm remains intact and doesn't affect any other VRFs"
        " routing decision."
    )

    dut = "r1"
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "tag": 4001,
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Expected Behavior: Routes are denied \nError {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_route_map_set_and_match_metric_p0(request):
    """
    FUNC_16_2:
    Configure a route-map on DUT to match traffic based various
    match/set causes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from RED_1"
        " in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise same set of BGP prefixes(IPv4+IPv6) from BLUE_1 and"
        "BLUE_2 in vrf instances(BLUE_A and BLUE_B)"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {
        "red1": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"metric": 123},
                                    }
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"metric": 123},
                                    }
                                ]
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                },
            ]
        },
        "blue1": {
            "bgp": [
                {
                    "local_as": "800",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"metric": 123},
                                    }
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"metric": 123},
                                    }
                                ]
                            }
                        },
                    },
                },
                {
                    "local_as": "800",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure a route-maps to match tag")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "route_maps": {
                    "rmap1_{}".format(addr_type): [
                        {"action": "permit", "match": {"metric": 123}}
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure neighbor for route map")
    input_dict_4 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that within vrf instances, BGP best path selection"
        " algorithm remains intact and doesn't affect any other VRFs"
        " routing decision."
    )

    dut = "r1"
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert (
            result is not True
        ), "Testcase {} : Failed \n Expected Behavior: Routes are denied \nError {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_route_map_set_and_match_community_p0(request):
    """
    FUNC_16_3:
    Configure a route-map on DUT to match traffic based various
    match/set causes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from RED_1"
        " in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise same set of BGP prefixes(IPv4+IPv6) from BLUE_1 and"
        "BLUE_2 in vrf instances(BLUE_A and BLUE_B)"
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Create community-list")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "bgp_community_lists": [
                    {
                        "community_type": "standard",
                        "action": "permit",
                        "name": "rmap_lcomm_{}".format(addr_type),
                        "value": "1:1 1:2 1:3 1:4 1:5",
                    }
                ]
            }
        }
        result = create_bgp_community_lists(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure a route-maps to match tag")

    step("Create route-maps in red1 and r1")

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "red1": {
                "route_maps": {
                    "rmap_red1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "set": {"community": {"num": "1:1 1:2 1:3 1:4 1:5"}},
                        }
                    ]
                }
            },
            "r1": {
                "route_maps": {
                    "rmap1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "match": {
                                "community_list": {"id": "rmap_lcomm_" + addr_type}
                            },
                        }
                    ]
                }
            },
        }
        result = create_route_maps(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure neighbor for route map")
    input_dict_4 = {
        "red1": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_red1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_red1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_red1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "red1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_red1_ipv6",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "red1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv4",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "blue1": {
                                        "dest_link": {
                                            "r1-link2": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap1_ipv6",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "All the prefixes advertised from RED_1 and BLUE_1 should carry"
        " attributes set by outbound route-maps within specific vrfs. "
        "Router R1 should be able to match and permit/deny those "
        "prefixes based on received attributes. Please use below "
        "commands to verify."
    )

    input_dict = {
        "community": "1:1 1:2 1:3 1:4 1:5",
    }

    for addr_type in ADDR_TYPES:
        vrf = "RED_A"
        routes = [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]]
        result = verify_bgp_community(tgen, addr_type, "r1", routes, input_dict, vrf)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        vrf = "RED_B"
        routes = [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]]
        result = verify_bgp_community(tgen, addr_type, "r1", routes, input_dict, vrf)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
