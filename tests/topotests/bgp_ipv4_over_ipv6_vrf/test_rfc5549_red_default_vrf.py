#!/usr/bin/env python
#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
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


"""RFC5549 Automation."""
import os
import sys
import time
import json
import pytest
import random
import ipaddr
from copy import deepcopy
from re import search as re_search

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo

from lib.common_config import (
    start_topology,
    write_test_header,
    stop_router,
    start_router,
    write_test_footer,
    get_frr_ipv6_linklocal,
    create_vrf_cfg,
    verify_rib,
    create_static_routes,
    check_address_types,
    reset_config_on_routers,
    step,
    create_route_maps,
    create_prefix_lists,
    shutdown_bringup_interface,
    create_interfaces_cfg,
    create_interface_in_kernel,
)
from lib.topolog import logger
from lib.bgp import (
    clear_bgp_and_verify,
    clear_bgp,
    modify_as_number,
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
)
from lib.topojson import build_topo_from_json, build_config_from_json
from rfc5549_common_lib import *

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/rfc5549_red_default_vrf.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)


# Global variables
NO_OF_RTES = 2
NETWORK = {
    "ipv4": [
        "11.0.20.1/32",
        "11.0.20.2/32",
        "11.0.20.3/32",
        "11.0.20.4/32",
        "11.0.20.5/32",
    ],
    "ipv6": ["1::1/128", "1::2/128", "1::3/128", "1::4/128", "1::5/128"],
}
NETWORK2 = {
    "ipv4": [
        "12.0.20.1/32",
        "12.0.20.2/32",
        "12.0.20.3/32",
        "12.0.20.4/32",
        "12.0.20.5/32",
    ],
    "ipv6": ["1::1/128", "1::2/128", "1::3/128", "1::4/128", "1::5/128"],
}
MASK = {"ipv4": "32", "ipv6": "128"}
NEXT_HOP = {
    "ipv4": ["10.0.0.1", "10.0.1.1", "10.0.2.1", "10.0.3.1", "10.0.4.1"],
    "ipv6": ["Null0", "Null0", "Null0", "Null0", "Null0"],
}
intf_list = [
    "r2-link0",
    "r2-link1",
    "r2-link2",
    "r2-link3",
    "r2-link4",
    "r2-link5",
    "r2-link6",
    "r2-link7",
]
ADDR_TYPES = check_address_types()
NETWORK_CMD_IP = ""
LOOPBACK_1 = {
    "ipv4": "10.10.10.10/32",
    "ipv6": "10::10:10/128",
    "ipv4_mask": "255.255.255.255",
    "ipv6_mask": None,
}
LOOPBACK_2 = {
    "ipv4": "20.20.20.20/32",
    "ipv6": "20::20:20/128",
    "ipv4_mask": "255.255.255.255",
    "ipv6_mask": None,
}
LOOPBACK_3 = {
    "ipv4": "30.30.30.30/32",
    "ipv6": "30::30:30/128",
    "ipv4_mask": "255.255.255.255",
    "ipv6_mask": None,
}
"""
Test cases:

TC45. Verify 5549 IPv4 route from non-default VRF advertised to another
      IPv4 EBGP default VRF.
TC47. Verify 5549 IPv4 route from non-default VRF advertised to default VRF.
TC50. Verify 5549 IPv4 routes are intact after stop and start the FRR services.
TC36. Verify 5549 IPv4 routes from non-default to default VRF over
      IPv6 loopback EBGP session
 """


class CreateTopo(Topo):
    """
    Test topology builder.

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        """Build function."""
        tgen = get_topogen(self)

        # Building topology from json file
        build_topo_from_json(tgen, topo)


def setup_module(mod):
    """Set up the pytest environment."""
    global ADDR_TYPES
    global topo
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(CreateTopo, mod.__name__)

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error:" " {}".format(
        BGP_CONVERGENCE
    )
    global NETWORK_CMD_IP
    NETWORK_CMD_IP = topo["routers"]["r1"]["links"]["lo"]["ipv4"]
    logger.info("Running setup_module() done")


def teardown_module(mod):
    """
    Teardown the pytest environment.

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


# ##################################
# Test cases start here.
# ##################################


@pytest.mark.precommit
def test_rfc5549_vrf_tc47_p0(request):
    """

    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 route from non-default VRF advertised to default VRF.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    protocol = "bgp"

    step(
        "Configure IPv6 EBGP session inside VRF RED with capability   "
        "enabled in between R1 and R2"
    )
    step("Enable same IPv6 session for address family IPv4 also")
    step(
        "Configure IPv6 IBGP session in default VRF between R2 and R3,"
        " enable same IPv6 session for address family IPv4 also"
    )
    step(
        "Advertise static routes using redistribute static from R1 and"
        " R3 ipv4 address family"
    )

    reset_config_on_routers(tgen)

    step("Configure 5 static on R1 RED VRF")

    # Create Static routes
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "RED",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure 5 different static route on R3 default VRF")
    # Create Static routes
    input_dict_r3 = {
        "r3": {
            "static_routes": [
                {
                    "network": NETWORK2["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import from RED to default VRF on R2 form R2 " "to R3 neighbor")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes advertised from R1 RED vrf are reaching to R3 default"
        " VRF with IPv6 link-local address of R2 (R2-R3) link , show ip "
        "route  show ip bgp"
    )

    llip = get_llip(topo, "r2", "r3")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r3"
    input_dict = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES,}]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes installed on R2 RED and default VRF using R1 ( R1-R2)"
        " link-local address show ip route show ip route vrf RED"
    )

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import from default to RED on R1 to R2 session")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "default"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    step(
        "IPv4 routes advertised from R3 deafult VRF are reaching to R1 RED"
        "VRF with IPv6 link-local address of R2 (R2-R1) , show ip route vrf"
        "RED show ip bgp vrf RED"
    )

    dut = "r1"
    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK2["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes installed on R2 RED and default VRF table using R3"
        " ( R3-R2) link-local address show ip route vrf RED show ip "
        "bgp vrf RED"
    )

    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Remove and add static from R1 and R3")

    # Create Static routes
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "RED",
                    "delete": True,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    step(
        "After removing static route from R1 , those route got removed"
        " from R3 default VRF and after adding route got added "
        "show ip route show ip bgp "
    )

    input_dict = {
        "r3": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES}]
        }
    }
    dut = "r3"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    input_dict_r3 = {
        "r3": {
            "static_routes": [
                {
                    "network": NETWORK2["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "delete": True,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    step(
        "After removing static routes from R3 , route got removed from R1"
        " RED VRF and after adding route got added show ip route vrf RED "
        "show ip bgp vrf RED "
    )

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK2["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }

    dut = "r1"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    step("adding back the previously deleted static routes.")
    # Create Static routes
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "RED",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Create Static routes
    input_dict_r3 = {
        "r3": {
            "static_routes": [
                {
                    "network": NETWORK2["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete RED VRF from R1 from Kernel")

    input_dict = {"r1": {"vrfs": [{"name": "RED", "id": "1", "delete": True}]}}

    result = create_vrf_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step(
        "After deleting VRF from R1 verify R1 advertised route got delete"
        " from R2 RED VRF show ip route vrf RED  and R3 default VRF "
        "show ip route "
    )

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    step(
        "Router advertised from R3 still present on R2 default VRF "
        "verify using show ip route  show ip bgp"
    )

    input_dict = {
        "r3": {
            "static_routes": [{"network": NETWORK2["ipv4"][0], "no_of_ip": NO_OF_RTES,}]
        }
    }
    dut = "r2"

    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


@pytest.mark.precommit
def test_rfc5549_vrf_tc45_p0(request):
    """

    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 route from non-default VRF advertised to another
    IPv4 EBGP default VRF.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    protocol = "bgp"
    global topo
    topo1 = deepcopy(topo)

    step(
        "Configure IPv6 EBGP session inside VRF RED with capability   "
        "enabled in between R1 and R2"
    )
    step("Enable same IPv6 session for address family IPv4 also")
    step(
        "Advertise static routes using redistribute static from R1"
        " ipv4 address family"
    )

    reset_config_on_routers(tgen)

    logger.info(
        "Base topo modify: topo modify from R2 --- R3 ipv6 iBGP "
        "session to ipv4 eBGP session."
    )

    topo1["routers"]["r3"]["bgp"][0]["address_family"]["ipv4"]["unicast"][
        "neighbor"
    ] = topo1["routers"]["r3"]["bgp"][0]["address_family"]["ipv6"]["unicast"].pop(
        "neighbor"
    )

    topo1["routers"]["r2"]["bgp"][1]["address_family"]["ipv4"]["unicast"][
        "neighbor"
    ] = topo1["routers"]["r2"]["bgp"][1]["address_family"]["ipv6"]["unicast"].pop(
        "neighbor"
    )

    topo1["routers"]["r2"]["bgp"][1]["address_family"].pop("ipv6")
    topo1["routers"]["r3"]["bgp"][0]["address_family"].pop("ipv6")

    input_dict = {"r2": {"bgp": [{"local_as": "200", "delete": True}]}}

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    input_dict = {"r3": {"bgp": [{"local_as": "200", "delete": True}]}}

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    build_config_from_json(tgen, topo1, save_bkup=False)
    input_dict = {"r3": {"bgp": {"local_as": "300"}}}
    modify_as_number(tgen, topo1, input_dict)
    for rtr in ["r1", "r2"]:
        clear_bgp(tgen, "ipv4", rtr, vrf="RED")
        clear_bgp(tgen, "ipv6", rtr, vrf="RED")
    result = verify_bgp_convergence(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure 5 static on R1 RED VRF")

    # Create Static routes
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "RED",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 Routes received on R2 VRF RED with R1 (R1-R2) IPv6 link-local"
        "address , installed in the RIB and BGP table using show ip route"
        " vrf RED show ip bgp vrf RED"
    )

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)
    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import from RED to default VRF on R2 form R2 " "to R3 neighbor")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 Route present in R2 default VRF with same link-local address"
        " as VRF RED (R1 link-local) show ip route show ip bgp"
    )

    input_dict_r1 = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES}]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 Route received on R3 default VRF with next hop as IPv4"
        " address of R2 to R3 interfacs show ip route  show ip bgp "
    )

    llip = get_glipv6(topo, "r2", "r3", addr_type="ipv4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r3"

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete static route from R1 RED VRF")
    # Create Static routes
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "RED",
                    "delete": True,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After delete static route from R1 RED VRF , verify router got removed"
        " from R2 and R3 default VRF show ip route show ip bgp "
    )

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        input_dict_r1,
        next_hop=llip,
        protocol=protocol,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    llip = get_glipv6(topo, "r2", "r3", addr_type="ipv4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r3"
    input_dict_r1 = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES}]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        input_dict_r1,
        next_hop=llip,
        protocol=protocol,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "RED",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    step("Verify before shutdown of the interface")

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Shut and No shut static route nexthop from R1 RED VRF")

    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2-link0"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "After shut nexthop from R1 RED VRF verify router got removed"
        "from R2 and R3 default VRF show ip route  show ip bgp"
    )

    dut = "r2"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        input_dict_r1,
        next_hop=llip,
        protocol=protocol,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )
    dut = "r1"
    # Bringup interface
    shutdown_bringup_interface(tgen, dut, intf, True)

    for rtr in ["r1", "r2"]:
        clear_bgp(tgen, "ipv4", rtr, vrf="RED")
        clear_bgp(tgen, "ipv6", rtr, vrf="RED")
    result = verify_bgp_convergence(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip1 = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip1 is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip1)

    step(
        "After no shut nexthop verify route got relearn on R2 and R3 default"
        " VRF show ip route  show ip bgp "
    )

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("On R3 , route present with IPv4 nexthop address on R2 ( R2-R3) link")

    llip = get_glipv6(topo, "r2", "r3", addr_type="ipv4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)
    dut = "r3"
    input_dict_r1 = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES}]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Shut and No shut BGP neighbor")
    shut_bgp_peer = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {"r1-link0": {"shutdown": True}}
                                    }
                                }
                            }
                        }
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo1, shut_bgp_peer)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "After neighbor shut from R1 RED VRF verify router got removed "
        "from R2 RED VRF show ip route vrf RED  and R3 default VRF "
        "show ip route"
    )

    dut = "r2"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        input_dict_r1,
        next_hop=llip,
        protocol=protocol,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    step(
        "After neighbor not shut from R1 RED VRF verify route got relearn"
        " on R2 RED VRF show ip route vrf RED & R3 default VRF show ip route"
    )
    shut_bgp_peer = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {"r1-link0": {"shutdown": False}}
                                    }
                                }
                            }
                        }
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo1, shut_bgp_peer)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_bgp_convergence(tgen, topo1, dut="r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }

    dut = "r2"

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("On R3 ,route present with IPv4 nexthop address on R2 ( R2-R3) link")

    llip = get_glipv6(topo, "r2", "r3", addr_type="ipv4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r3"
    input_dict_r1 = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES}]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_rfc5549_vrf_tc36_p0(request):
    """

    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 routes from non-default to default VRF over
    IPv6 loopback EBGP session
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    protocol = "bgp"
    global topo
    topo1 = deepcopy(topo)

    step("Configure IPv6 global address between R1 and R2 inside VRF RED")
    step("Configure IPv6 global address between R2 and R3 inside default VRF")
    step(
        "Configure loopback on R1, R2 VRF RED and R2, R3 default VRF "
        "with /128 subnet"
    )
    step(
        "Establish EBGP session inside VRF RED between R1 and R2 "
        "over loopback global ip"
    )
    step(
        "Establish IBGP session inside VRF RED between R2 and R3 over"
        " loopback global ip"
    )
    step(
        "Configure static route on R1 VRF RED and R2 VRF RED for "
        "loopback reachability"
    )

    step(
        "Configure static route on R2 default VRF and R3 default VRF "
        "for loopback reachability"
    )

    step("Enable capability extended-nexthop on the neighbor from both " "the routers")

    step("Activate same IPv6 nbr from IPv4 unicast family")

    step("Configure 5 link between R0 and R1 in VRF RED")

    step(
        "Configure 5 IPv4 static routes on R1 inside VRF RED (nexthop for "
        "static route exists on different links of R0)"
    )

    reset_config_on_routers(tgen)
    for rtr in ["r1", "r2"]:
        clear_bgp(tgen, "ipv4", rtr, vrf="RED")
        clear_bgp(tgen, "ipv6", rtr, vrf="RED")
    for rtr in ["r2", "r3"]:
        clear_bgp(tgen, "ipv4", rtr)
        clear_bgp(tgen, "ipv6", rtr)
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for rte in range(0, NO_OF_RTES):
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][rte],
                        "no_of_ip": 1,
                        "next_hop": NEXT_HOP["ipv4"][rte],
                        "vrf": "RED",
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise network from IPv4 unicast family using network command "
        "from R1 and R3"
    )
    step(
        "Advertise static route from IPv4 unicast family using "
        "redistribute static command from R1"
    )
    step("Advertise static routes from IPv4 unicast family unicast family")
    step("Configure interface network on R1 inside VRF RED with IPv4 address")
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [{"redist_type": "static"}],
                                "advertise_networks": [
                                    {"network": LOOPBACK_1["ipv4"], "no_of_network": 1}
                                ],
                            }
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure interface network on R3 inside default VRF with " "IPv4 address")
    configure_bgp_on_r1 = {
        "r3": {
            "bgp": [
                {
                    "local_as": "200",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [{"redist_type": "static"}],
                                "advertise_networks": [
                                    {"network": LOOPBACK_3["ipv4"], "no_of_network": 1}
                                ],
                            }
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure import VRF on R2 from RED to default VRF")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure import VRF on R2 from default to RED VRF")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "default"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes advertised using static and network command from R1 "
        "are received on R2 RED VRF BGP and routing table , verify using "
        "show ip bgp vrf RED show ip route vrf RED and installed with R1 "
        " (R1-R2) global nexthop"
    )

    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Routes installed on R2 default VRF after configuring VRF import"
        " with R1 (R1-R2) global nexthop verify using show ip route"
    )

    input_dict_r1 = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES,}]
        }
    }

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Route installed on R3 default VRF with R2 ( R2-R3) global nexthop"
        ", verify using show ip route show ip bgp"
    )

    llip = None
    llip = get_llip(topo, "r2", "r3")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r3"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes advertised using network command from R3 are received "
        "on R2 default BGP and routing table , verify using show ip bgp "
        "show ip route  and installed with R3(R3-R2) global nexthop"
    )

    input_dict_r3 = {
        "r1": {"static_routes": [{"network": LOOPBACK_3["ipv4"], "no_of_ip": 1,}]}
    }

    llip = None
    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r3, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r3, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Routes installed on R2 RED VRF after configuring VRF import with R3"
        " (R3-R2) global nexthop verify using show ip route vrf RED"
    )

    step(
        "Route installed on R1 RED VRF with R2 ( R2-R1) global nexthop, "
        "verify using show ip route vrf RED show ip bgp vrf RED"
    )

    input_dict_r3 = {
        "r1": {
            "static_routes": [
                {"network": LOOPBACK_3["ipv4"], "no_of_ip": 1, "vrf": "RED"}
            ]
        }
    }

    llip = None
    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r3, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r3, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = None
    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r1"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r3, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r3, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Remove IPv4 routes advertised using network command from R1 "
        "and advertise again"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": LOOPBACK_1["ipv4"],
                                        "no_of_network": 1,
                                        "delete": True,
                                    }
                                ]
                            }
                        }
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After removing IPv4 routes from network command , routes which are "
        "advertised using redistribute static are still present in the on R2,"
        " verify using show ip bgp vrf RED show ip route vrf RED"
        " and R3 verif"
    )

    input_dict_r3 = {
        "r1": {"static_routes": [{"network": LOOPBACK_1["ipv4"], "no_of_ip": 1,}]}
    }

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict_r3, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Routes still present"
        "Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        input_dict_r3,
        next_hop=llip,
        protocol=protocol,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n Routes still present" "Error: {}".format(
        tc_name, result
    )

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After removing IPv4 routes from redistribute static , routes "
        "which are advertised using network are still present in the on"
        " R2 and installed with global nexthop , verify using show ip bgp"
        " vrf RED and show ip route vrf RED and R3 verify using show ip route"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static", "delete": True}
                                ]
                            }
                        }
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_rfc5549_vrf_tc50_p2(request):
    """

    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 routes are intact after stop and start the FRR services.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    protocol = "bgp"

    step(
        "Configure IPv6 EBGP session inside VRF RED with capability   "
        "enabled in between R1 and R2"
    )
    step("Enable same IPv6 session for address family IPv4 also")
    step(
        "Configure IPv6 IBGP session in default VRF between R2 and R3,"
        " enable same IPv6 session for address family IPv4 also"
    )
    step(
        "Advertise static routes using redistribute static from R1 and"
        " R3 ipv4 address family"
    )

    reset_config_on_routers(tgen)

    step("Configure 5 static on R1 RED VRF")

    # Create Static routes
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "RED",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure 5 different static route on R3 default VRF")
    # Create Static routes
    input_dict_r3 = {
        "r3": {
            "static_routes": [
                {
                    "network": NETWORK2["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import from RED to default VRF on R2 form R2 " "to R3 neighbor")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes advertised from R1 RED vrf are reaching to R3 default"
        " VRF with IPv6 link-local address of R2 (R2-R3) link , show ip "
        "route  show ip bgp"
    )

    llip = get_llip(topo, "r2", "r3")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r3"
    input_dict = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES,}]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes installed on R2 RED and default VRF using R1 ( R1-R2)"
        " link-local address show ip route show ip route vrf RED"
    )

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import from default to RED on R1 to R2 session")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "default"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    step(
        "IPv4 routes advertised from R3 deafult VRF are reaching to R1 RED"
        "VRF with IPv6 link-local address of R2 (R2-R1) , show ip route vrf"
        "RED show ip bgp vrf RED"
    )

    dut = "r1"
    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK2["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes installed on R2 RED and default VRF table using R3"
        " ( R3-R2) link-local address show ip route vrf RED show ip "
        "bgp vrf RED"
    )

    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Stop and start the FRR services on R1 , R2 , and R3 one by one")
    for rtr in ["r1", "r2", "r3"]:
        stop_router(tgen, rtr)
        start_router(tgen, rtr)

    # link local racecondition issue is observed in mininet interfaces
    # added clear command to handle it after restart of frr.

    for rtr in ["r1", "r2"]:
        clear_bgp(tgen, "ipv4", rtr, vrf="RED")
        clear_bgp(tgen, "ipv6", rtr, vrf="RED")

    for rtr in ["r2", "r3"]:
        clear_bgp(tgen, "ipv4", rtr)
        clear_bgp(tgen, "ipv6", rtr)

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After start FRR daemons are started "
        "IPv4 routes advertised from R1 RED vrf are reaching to R3 default"
        " VRF with IPv6 link-local address of R2 (R2-R3) link , show ip "
        "route  show ip bgp"
    )

    llip = get_llip(topo, "r2", "r3")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r3"
    input_dict = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES,}]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After start FRR daemons are started "
        "IPv4 routes installed on R2 RED and default VRF using R1 ( R1-R2)"
        " link-local address show ip route show ip route vrf RED"
    )

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    step(
        "IPv4 routes advertised from R3 deafult VRF are reaching to R1 RED"
        "VRF with IPv6 link-local address of R2 (R2-R1) , show ip route vrf"
        "RED show ip bgp vrf RED"
    )

    dut = "r1"
    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK2["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After start FRR daemons are started"
        "IPv4 routes installed on R2 RED and default VRF table using R3"
        " ( R3-R2) link-local address show ip route vrf RED show ip "
        "bgp vrf RED"
    )

    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
