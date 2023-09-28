#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test EVPN-Type5 functionality:
1. In absence of an overlay index all IP-Prefixes(RT-5)
    are advertised with default values for below parameters:
        --> Ethernet Tag ID = GW IP address = ESI=0
2. EVPN CLI output and JSON format validation.
3. RT verification(auto)
"""

import os
import sys
import time
import pytest
import platform
from copy import deepcopy


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topotest import version_cmp
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    create_static_routes,
    create_vrf_cfg,
    check_router_status,
    configure_vxlan,
    configure_brctl,
    verify_vrf_vni,
    verify_cli_json,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_attributes_for_evpn_routes,
)
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Reading the data from JSON File for topology creation
# Global variables
TCPDUMP_FILE = "evpn_log.txt"
NETWORK1_1 = {"ipv4": "10.1.1.1/32", "ipv6": "10::1/128"}
NETWORK1_2 = {"ipv4": "40.1.1.1/32", "ipv6": "40::1/128"}
NETWORK1_3 = {"ipv4": "40.1.1.2/32", "ipv6": "40::2/128"}
NETWORK1_4 = {"ipv4": "40.1.1.3/32", "ipv6": "40::3/128"}
NETWORK2_1 = {"ipv4": "20.1.1.1/32", "ipv6": "20::1/128"}
NETWORK3_1 = {"ipv4": "30.1.1.1/32", "ipv6": "30::1/128"}
NETWORK4_1 = {"ipv4": "100.1.1.1/32 ", "ipv6": "100::100/128"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}
VNI_1 = 75100
VNI_2 = 75200
VNI_3 = 75300
MAC_1 = "00:80:48:ba:d1:00"
MAC_2 = "00:80:48:ba:d1:01"
MAC_3 = "00:80:48:ba:d1:02"
BRCTL_1 = "br100"
BRCTL_2 = "br200"
BRCTL_3 = "br300"
VXLAN_1 = "vxlan75100"
VXLAN_2 = "vxlan75200"
VXLAN_3 = "vxlan75300"
BRIDGE_INTF1 = "120.0.0.1"
BRIDGE_INTF2 = "120.0.0.2"
BRIDGE_INTF3 = "120.0.0.3"
MULTICAST_MAC1 = "01:00:5e:00:52:02"

VXLAN = {
    "vxlan_name": [VXLAN_1, VXLAN_2, VXLAN_3],
    "vxlan_id": [75100, 75200, 75300],
    "dstport": 4789,
    "local_addr": {"e1": BRIDGE_INTF1, "d1": BRIDGE_INTF2, "d2": BRIDGE_INTF3},
    "learning": "no",
}
BRCTL = {
    "brctl_name": [BRCTL_1, BRCTL_2, BRCTL_3],
    "addvxlan": [VXLAN_1, VXLAN_2, VXLAN_3],
    "vrf": ["RED", "BLUE", "GREEN"],
    "stp": [0, 0, 0],
}


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
    json_file = "{}/evpn_type5_chaos_topo1.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    if version_cmp(platform.release(), "4.19") < 0:
        error_msg = (
            'EVPN tests will not run (have kernel "{}", '
            "but it requires >= 4.19)".format(platform.release())
        )
        pytest.skip(error_msg)

    global BGP_CONVERGENCE
    global ADDR_TYPES
    ADDR_TYPES = check_address_types()

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Pre-requisite config for testsuite")
    prerequisite_config_for_test_suite(tgen)

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


def prerequisite_config_for_test_suite(tgen):
    """
    API to do prerequisite config for testsuite

    parameters:
    -----------
    * `tgen`: topogen object
    """

    step("Configure vxlan, bridge interface")
    for dut in ["e1", "d1", "d2"]:
        step("[DUT: ]Configure vxlan")
        vxlan_input = {
            dut: {
                "vxlan": [
                    {
                        "vxlan_name": VXLAN["vxlan_name"],
                        "vxlan_id": VXLAN["vxlan_id"],
                        "dstport": VXLAN["dstport"],
                        "local_addr": VXLAN["local_addr"][dut],
                        "learning": VXLAN["learning"],
                    }
                ]
            }
        }

        result = configure_vxlan(tgen, vxlan_input)
        assert result is True, "Testcase :Failed \n Error: {}".format(result)

        step("Configure bridge interface")
        brctl_input = {
            dut: {
                "brctl": [
                    {
                        "brctl_name": BRCTL["brctl_name"],
                        "addvxlan": BRCTL["addvxlan"],
                        "vrf": BRCTL["vrf"],
                        "stp": BRCTL["stp"],
                    }
                ]
            }
        }
        result = configure_brctl(tgen, topo, brctl_input)
        assert result is True, "Testcase :Failed \n Error: {}".format(result)

    step("Configure default routes")
    add_default_routes(tgen)


def add_default_routes(tgen):
    """
    API to do prerequisite config for testsuite

    parameters:
    -----------
    * `tgen`: topogen object
    """

    step("Add default routes..")

    default_routes = {
        "e1": {
            "static_routes": [
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["d1"]),
                    "next_hop": topo["routers"]["d1"]["links"]["e1-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["d2"]),
                    "next_hop": topo["routers"]["d2"]["links"]["e1-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
            ]
        },
        "d1": {
            "static_routes": [
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["e1"]),
                    "next_hop": topo["routers"]["e1"]["links"]["d1-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["d2"]),
                    "next_hop": topo["routers"]["e1"]["links"]["d1-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
            ]
        },
        "d2": {
            "static_routes": [
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["d1"]),
                    "next_hop": topo["routers"]["e1"]["links"]["d2-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["e1"]),
                    "next_hop": topo["routers"]["e1"]["links"]["d2-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
            ]
        },
    }

    result = create_static_routes(tgen, default_routes)
    assert result is True, "Testcase :Failed \n Error: {}".format(result)


def test_verify_overlay_index_p1(request):
    """
    In absence of an overlay index all IP-Prefixes(RT-5)
    are advertised with default values for below parameters:
        --> Ethernet Tag ID = GW IP address = ESI=0
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Following steps are taken care in base config:")
    step(
        "Configure BGP neighborship for both address families"
        "(IPv4 & IPv6) between Edge-1 and VFN routers(R1 and R2)"
    )
    step(
        "Advertise prefixes from VNF routers R1 and R2 in associated "
        "VRFs for both address-family."
    )
    step("Advertise VRF routes as in EVPN address family from Edge-1 " "router.")

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK3_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify: Prefixes are received in all VRFs on Edge-1 router.")

    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_rib(tgen, addr_type, "e1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_rib(tgen, addr_type, "e1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that EVPN routes, received on DCG-1 and DCG-2 do not "
        "carry any overlay index and these indexes are set to default "
        "value=0. "
    )

    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "d1", input_routes, ethTag=0
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "d2", input_routes, ethTag=0
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_evpn_cli_json_available_p1(request):
    """
    EVPN CLI output and JSON format validation.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Need to verify below CLIs and associated JSON format " "outputs:")

    input_dict = {
        "e1": {
            "cli": [
                "show evpn vni detail",
                "show bgp l2vpn evpn all overlay",
                "show bgp l2vpn evpn vni",
            ]
        }
    }

    result = verify_cli_json(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_RT_verification_auto_p0(request):
    """
    RT verification(auto)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Advertise overlapping prefixes from VNFs R1 and R2 in all VRFs "
        "RED, GREEN and BLUE 100.1.1.1/32 and 100::100/128"
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that Edge-1 receives same prefixes in all 3 VRFs via "
        "corresponding next-hop in associated VRF sh bgp vrf all"
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = verify_rib(tgen, addr_type, "e1", input_routes)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure 4-byte local AS number on Edge-1 and establish EVPN "
        "neighborship with DCG-1 & DCG-2."
    )

    topo_local = deepcopy(topo)

    step("Delete BGP config for vrf RED.")

    input_dict_vni = {
        "e1": {
            "vrfs": [
                {"name": "RED", "no_vni": VNI_1},
                {"name": "BLUE", "no_vni": VNI_2},
                {"name": "GREEN", "no_vni": VNI_3},
            ]
        }
    }
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_2 = {}
    for dut in ["e1"]:
        temp = {dut: {"bgp": []}}
        input_dict_2.update(temp)

        INDEX = [0, 1, 2, 3]
        VRFS = ["RED", "BLUE", "GREEN", None]
        AS_NUM = [100, 100, 100, 100]

        for index, vrf, as_num in zip(INDEX, VRFS, AS_NUM):
            topo_local["routers"][dut]["bgp"][index]["local_as"] = 4294967293
            if vrf:
                temp[dut]["bgp"].append(
                    {"local_as": as_num, "vrf": vrf, "delete": True}
                )
            else:
                temp[dut]["bgp"].append({"local_as": as_num, "delete": True})

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = create_router_bgp(tgen, topo_local["routers"])
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_vni = {
        "e1": {
            "vrfs": [
                {"name": "RED", "vni": VNI_1},
                {"name": "BLUE", "vni": VNI_2},
                {"name": "GREEN", "vni": VNI_3},
            ]
        }
    }
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that all overlapping prefixes across different VRFs are "
        "advertised in EVPN with unique RD value(auto derived)."
    )
    step(
        "Verify that FRR uses only the lower 2 bytes of ASN+VNI for auto "
        "derived RT value."
    )

    for addr_type in ADDR_TYPES:
        input_routes_1 = {
            "r1": {"static_routes": [{"network": NETWORK4_1[addr_type], "vrf": "RED"}]}
        }
        input_routes_2 = {
            "r2": {"static_routes": [{"network": NETWORK4_1[addr_type], "vrf": "BLUE"}]}
        }
        input_routes_3 = {
            "r2": {
                "static_routes": [{"network": NETWORK4_1[addr_type], "vrf": "GREEN"}]
            }
        }

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "e1", input_routes_1, rd="auto", rd_peer="e1"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "e1", input_routes_1, rt="auto", rt_peer="e1"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "e1", input_routes_2, rd="auto", rd_peer="e1"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "e1", input_routes_2, rt="auto", rt_peer="e1"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "e1", input_routes_3, rd="auto", rd_peer="e1"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "e1", input_routes_3, rt="auto", rt_peer="e1"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that DCG-1(iBGP peer) automatically imports the prefixes"
        " from EVPN address-family to respective VRFs."
    )
    step(
        "Verify if DCG-2(eBGP peer) automatically imports the prefixes "
        "from EVPN address-family to respective VRFs or not."
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK4_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = verify_rib(tgen, addr_type, "d1", input_routes)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Change the VNI number for all 3 VRFs on Edge-1 as:"
        "RED : 75400, GREEN: 75500, BLUE: 75600"
    )

    input_dict_vni = {
        "e1": {
            "vrfs": [
                {"name": "RED", "no_vni": VNI_1},
                {"name": "BLUE", "no_vni": VNI_2},
                {"name": "GREEN", "no_vni": VNI_3},
            ]
        }
    }
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_vni = {
        "e1": {
            "vrfs": [
                {"name": "RED", "vni": 75400},
                {"name": "BLUE", "vni": 75500},
                {"name": "GREEN", "vni": 75600},
            ]
        }
    }
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Delete configured vxlan")
    dut = "e1"
    vxlan_input = {
        dut: {
            "vxlan": [
                {
                    "vxlan_name": VXLAN["vxlan_name"],
                    "vxlan_id": VXLAN["vxlan_id"],
                    "dstport": VXLAN["dstport"],
                    "local_addr": VXLAN["local_addr"][dut],
                    "learning": VXLAN["learning"],
                    "delete": True,
                }
            ]
        }
    }

    result = configure_vxlan(tgen, vxlan_input)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configured vxlan")
    VXLAN["vxlan_id"] = [75400, 75500, 75600]
    vxlan_input = {
        dut: {
            "vxlan": [
                {
                    "vxlan_name": VXLAN["vxlan_name"],
                    "vxlan_id": VXLAN["vxlan_id"],
                    "dstport": VXLAN["dstport"],
                    "local_addr": VXLAN["local_addr"][dut],
                    "learning": VXLAN["learning"],
                }
            ]
        }
    }

    result = configure_vxlan(tgen, vxlan_input)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure bridge interface")
    brctl_input = {
        dut: {
            "brctl": [
                {
                    "brctl_name": BRCTL["brctl_name"],
                    "addvxlan": BRCTL["addvxlan"],
                    "vrf": BRCTL["vrf"],
                    "stp": BRCTL["stp"],
                }
            ]
        }
    }
    result = configure_brctl(tgen, topo, brctl_input)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on Edge-1 that auto derived RT value has changed for "
        "each VRF based on VNI number.."
    )

    input_dict = {
        "e1": {
            "vrfs": [
                {"RED": {"vni": 75400}},
                {"BLUE": {"vni": 75500}},
                {"GREEN": {"vni": 75600}},
            ]
        }
    }

    result = verify_vrf_vni(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on Edge-1 that auto derived RT value has changed for "
        "each VRF based on VNI number."
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r1": {"static_routes": [{"network": NETWORK4_1[addr_type], "vrf": "RED"}]}
        }

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "e1", input_routes, rt="auto", rt_peer="e1"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify on DCG-2 that prefixes are not imported from EVPN "
        "address-family to VRFs as RT values are different on sending("
        "edge-1) and receiving(DCG-2) end."
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r1": {"static_routes": [{"network": NETWORK4_1[addr_type], "vrf": "RED"}]}
        }

        result = verify_rib(tgen, addr_type, "d2", input_routes, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, "d2", result)
        )

    step(
        "Revert back to original VNI number for all 3 VRFs on Edge-1 "
        "as: RED : 75100, GREEN: 75200, BLUE: 75300"
    )

    input_dict_vni = {
        "e1": {
            "vrfs": [
                {"name": "RED", "no_vni": 75400},
                {"name": "BLUE", "no_vni": 75500},
                {"name": "GREEN", "no_vni": 75600},
            ]
        }
    }
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_vni = {
        "e1": {
            "vrfs": [
                {"name": "RED", "vni": VNI_1},
                {"name": "BLUE", "vni": VNI_2},
                {"name": "GREEN", "vni": VNI_3},
            ]
        }
    }
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Delete configured vxlan")
    dut = "e1"
    vxlan_input = {
        dut: {
            "vxlan": [
                {
                    "vxlan_name": VXLAN["vxlan_name"],
                    "vxlan_id": VXLAN["vxlan_id"],
                    "dstport": VXLAN["dstport"],
                    "local_addr": VXLAN["local_addr"][dut],
                    "learning": VXLAN["learning"],
                    "delete": True,
                }
            ]
        }
    }
    result = configure_vxlan(tgen, vxlan_input)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configured vxlan")
    VXLAN["vxlan_id"] = [75100, 75200, 75300]
    vxlan_input = {
        dut: {
            "vxlan": [
                {
                    "vxlan_name": VXLAN["vxlan_name"],
                    "vxlan_id": VXLAN["vxlan_id"],
                    "dstport": VXLAN["dstport"],
                    "local_addr": VXLAN["local_addr"][dut],
                    "learning": VXLAN["learning"],
                }
            ]
        }
    }
    result = configure_vxlan(tgen, vxlan_input)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure bridge interface")
    brctl_input = {
        dut: {
            "brctl": [
                {
                    "brctl_name": BRCTL["brctl_name"],
                    "addvxlan": BRCTL["addvxlan"],
                    "vrf": BRCTL["vrf"],
                    "stp": BRCTL["stp"],
                }
            ]
        }
    }
    result = configure_brctl(tgen, topo, brctl_input)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on Edge-1 that auto derived RT value has changed for "
        "each VRF based on VNI number."
    )
    step(
        "Verify that DCG-1(iBGP peer) automatically imports the prefixes"
        " from EVPN address-family to respective VRFs."
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r1": {"static_routes": [{"network": NETWORK4_1[addr_type], "vrf": "RED"}]}
        }

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "e1", input_routes, rt="auto", rt_peer="e1"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "d1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Test with smaller VNI numbers (1-75000)")

    input_dict_vni = {"e1": {"vrfs": [{"name": "RED", "no_vni": VNI_1}]}}
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_vni = {"e1": {"vrfs": [{"name": "RED", "vni": 111}]}}
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that DCG-2 receives EVPN prefixes along with auto "
        "derived RT values(based on smaller VNI numbers)"
    )

    for addr_type in ADDR_TYPES:
        input_routes_1 = {
            "r1": {"static_routes": [{"network": NETWORK4_1[addr_type], "vrf": "RED"}]}
        }

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "d2", input_routes_1, rt="auto", rt_peer="e1", expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Malformed Auto-RT value should not be accepted in {} \n "
            "Found: {}".format(tc_name, "d2", result)
        )

    step("Configure VNI number more than boundary limit (16777215)")

    input_dict_vni = {"e1": {"vrfs": [{"name": "RED", "no_vni": 111}]}}
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_vni = {"e1": {"vrfs": [{"name": "RED", "vni": 16777215}]}}
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("CLI error for malformed VNI.")
    input_dict = {
        "e1": {
            "vrfs": [{"RED": {"vni": 16777215, "routerMac": "None", "state": "Down"}}]
        }
    }

    result = verify_vrf_vni(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_routes_1 = {
            "r1": {"static_routes": [{"network": NETWORK4_1[addr_type], "vrf": "RED"}]}
        }

        result = verify_attributes_for_evpn_routes(
            tgen, topo, "d2", input_routes_1, rt="auto", rt_peer="e1", expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Malformed Auto-RT value should not be accepted in {} \n "
            "Found: {}".format(tc_name, "d2", result)
        )

    step("Un-configure VNI number more than boundary limit (16777215)")

    input_dict_vni = {"e1": {"vrfs": [{"name": "RED", "no_vni": 16777215}]}}
    result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
