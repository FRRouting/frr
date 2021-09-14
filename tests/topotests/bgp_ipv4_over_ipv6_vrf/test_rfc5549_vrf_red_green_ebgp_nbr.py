#!/usr/bin/env python
#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
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
from copy import deepcopy
import os
import sys
import time
import json
import pytest

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
    write_test_footer,
    get_frr_ipv6_linklocal,
    kill_router_daemons,
    verify_rib,
    create_static_routes,
    check_address_types,
    reset_config_on_routers,
    step,
    start_router_daemons,
    create_prefix_lists,
    check_router_status,
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, create_router_bgp, verify_bgp_rib
from lib.topojson import build_config_from_json
from rfc5549_common_lib import *

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


"""
      Please view in a fixed-width font such as Courier.
          no bgp           ebgp/ibgp
                                               ebgp/ibgp
    +----+ 5links   +----+  8links    +--+-+             +----+
    |R0  +----------+ R1 +------------+ R2 |    ipv6 nbr |R3  |
    |    +----------+    +------------+    +-------------+    |
    +----+          +----+   ipv6 nbr +----+             +----+

TC49. Verify 5549 IPv4 routes are intact after BGPd process restart.
TC48. Verify 5549 IPv4 route after deleting routing BGP instance.
TC46. Verify 5549 IPv4 route from non-default VRF advertised to another
        non-default VRF.
TC43. Verify 5549 IPv4 route configured with non-default VRF can be advertised
    to another IPv4 IBGP non-default VRF peer.
 """


def setup_module(mod):
    """Set up the pytest environment."""
    global topo, ADDR_TYPES

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/rfc5549_vrf_red_green_ebgp_nbr.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

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
    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment."""
    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()


def get_glipv6_loc(onrouter, intf, addr_type="ipv6"):
    """
    API to get the global ipv6 address of a perticular interface

    Parameters
    ----------
    * `onrouter`: Source node
    * `intf` : interface for which link local ip needs to be returned.

    Usage
    -----
    result = get_glipv6('r1', 'r2-link0')

    Returns
    -------
    1) global ipv6 address from the interface.
    2) errormsg - when link local ip not found.
    """
    glipv6 = (topo["routers"][onrouter]["links"][intf][addr_type]).split("/")[0]
    if glipv6:
        logger.info("Global %s address to be set as NH is %s", addr_type, glipv6)
        return glipv6
    return None


# ##################################
# Test cases start here.
# ##################################

# As per our internal discussion, currently these test cases are not supported.
# Removing these from execution.
def rfc5549_vrf_tc49_p2(request):
    """

    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 routes are intact after BGPd process restart.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)
    protocol = "bgp"
    step(
        "Configure one IPv6 EBGP session inside VRF RED with capability "
        "enabled in between R1 and R2"
    )
    step("Enable same IPv6 session for address family IPv4 also")

    step(
        "Configure IPv6 EBGP session inside VRF GREEN with "
        "capability enable between R2 and R3, enable same IPv6 "
        "session for address family IPv4 also"
    )

    step(
        "Advertise static routes using redistribute static"
        " and network command from R1 and R3 ipv4 address family"
    )

    reset_config_on_routers(tgen)

    step("Configure 5 same static route from R1 RED and R3 GREEN VRF")

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
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "GREEN",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import on GREEN VRF to import the routes from RED" "VRF on R2")

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "GREEN",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 GREEN VRF are received from RED VRF , "
        "nexthop is R1 ( R1-R2) link-local address show ip bgp vrf "
        "GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 GREEN VRF are showing preferred routes"
        " received from GREEN VRF , nexthop is R3 ( R2-R3) link-local "
        "nexthop show ip route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import on RED VRF to import the routes" " from GREEN VRF on R2")

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "GREEN"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 RED VRF are showing router are received from"
        " GREEN VRF, nexthop R3 (R2-R3) ) link-local address show ip bgp"
        " vrf GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 RED VRF are showing preferred routes received"
        " from RED m nexthop is R1 (R1-R2) link-local address show ip "
        "route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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

    step("Kill BGPD from R1 , R2 and R3 using kill- 9 <bgpd pid>")

    for rtr in ["r1", "r2", "r3"]:
        kill_router_daemons(tgen, rtr, ["bgpd"])
        start_router_daemons(tgen, rtr, ["bgpd"])

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 GREEN VRF are received from RED VRF , "
        "nexthop is R1 ( R1-R2) link-local address show ip bgp vrf "
        "GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 GREEN VRF are showing preferred routes"
        " received from GREEN VRF , nexthop is R3 ( R2-R3) link-local "
        "nexthop show ip route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 RED VRF are showing router are received from"
        " GREEN VRF, nexthop R3 (R2-R3) ) link-local address show ip bgp"
        " vrf GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 RED VRF are showing preferred routes received"
        " from RED m nexthop is R1 (R1-R2) link-local address show ip "
        "route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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

    write_test_footer(tc_name)


# As per our internal discussion, currently these test cases are not supported.
# Removing these from execution.
def rfc5549_vrf_tc48_p0(request):
    """

    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 route after deleting routing BGP instance.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)
    protocol = "bgp"
    step(
        "Configure one IPv6 EBGP session inside VRF RED with capability "
        "enabled in between R1 and R2"
    )
    step("Enable same IPv6 session for address family IPv4 also")

    step(
        "Configure IPv6 EBGP session inside VRF GREEN with "
        "capability enable between R2 and R3, enable same IPv6 "
        "session for address family IPv4 also"
    )

    step(
        "Advertise static routes using redistribute static"
        " and network command from R1 and R3 ipv4 address family"
    )

    reset_config_on_routers(tgen)

    step("Configure 5 same static route from R1 RED and R3 GREEN VRF")

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
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "GREEN",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import on GREEN VRF to import the routes from RED" "VRF on R2")

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "GREEN",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 GREEN VRF are received from RED VRF , "
        "nexthop is R1 ( R1-R2) link-local address show ip bgp vrf "
        "GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 GREEN VRF are showing preferred routes"
        " received from GREEN VRF , nexthop is R3 ( R2-R3) link-local "
        "nexthop show ip route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import on RED VRF to import the routes" " from GREEN VRF on R2")

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "GREEN"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 RED VRF are showing router are received from"
        " GREEN VRF, nexthop R3 (R2-R3) ) link-local address show ip bgp"
        " vrf GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 RED VRF are showing preferred routes received"
        " from RED m nexthop is R1 (R1-R2) link-local address show ip "
        "route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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

    step("Delete BGP routing instance from R1 RED VRF no router bgp vrf RED")

    input_dict = {"r1": {"bgp": [{"local_as": "100", "vrf": "RED", "delete": True}]}}

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "After deleting routing instance from R1 RED VRF , verify BGP session"
        " from RED VRF went down and route got removed from R3 GREEN VRF "
        "using show ip route vrf GREEN and BGP table using show ip bgp vrf "
        "GREEN"
    )

    result = verify_bgp_convergence(tgen, topo, dut="r1", expected=False)
    assert result is not True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, result
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_rib
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step("Delete routing instance from R2 GREEN VRF no router bgp vrf GREEN")

    input_dict = {"r3": {"bgp": [{"local_as": "300", "vrf": "GREEN", "delete": True}]}}

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "After deleting routing instance from GREEN VRF, verify BGP "
        "session from GREEN VRF went down and route removed from R2 "
        "GREEN VRF show ip route vrf GREEN and BGP table using "
        "show ip bgp vrf GREEN"
    )

    result = verify_bgp_convergence(tgen, topo, dut="r1", expected=False)
    assert result is not True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, result
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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
    assert bgp_rib is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_rib
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)


# @pytest.mark.precommit
# As per our internal discussion, currently these test cases are not supported.
# Removing these from execution.
def rfc5549_vrf_tc46_p0(request):
    """

    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 route from non-default VRF advertised to another
    non-default VRF.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)
    protocol = "bgp"
    step(
        "Configure one IPv6 EBGP session inside VRF RED with capability "
        "enabled in between R1 and R2"
    )

    step("Enable same IPv6 session for address family IPv4 also")

    step(
        "Configure IPv6 EBGP session inside VRF GREEN with "
        "capability enable between R2 and R3, enable same IPv6 "
        "session for address family IPv4 also"
    )

    step(
        "Advertise static routes using redistribute static"
        " and network command from R1 and R3 ipv4 address family"
    )

    reset_config_on_routers(tgen)

    step("Configure 5 same static route from R1 RED and R3 GREEN VRF")

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
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "GREEN",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import on GREEN VRF to import the routes from RED" "VRF on R2")

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "GREEN",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 GREEN VRF are received from RED VRF , "
        "nexthop is R1 ( R1-R2) link-local address show ip bgp vrf "
        "GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 GREEN VRF are showing preferred routes"
        " received from GREEN VRF , nexthop is R3 ( R2-R3) link-local "
        "nexthop show ip route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure VRF import on RED VRF to import the routes" " from GREEN VRF on R2")

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "GREEN"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 RED VRF are showing router are received from"
        " GREEN VRF, nexthop R3 (R2-R3) ) link-local address show ip bgp"
        " vrf GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 RED VRF are showing preferred routes received"
        " from RED m nexthop is R1 (R1-R2) link-local address show ip "
        "route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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

    step("Delete and Add routes from R1 RED VRF")
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
        "After deleting routes from R1 RED VRF , verify route R2 RED VRF"
        " has installed routes received from GREEN VRF nexthop is R3 "
        "( R2 to R3) link-local address"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
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

    step("R1 RED VRF routes installed with R2 ( R2-R1) link-local nexthop")

    llip = None
    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Add routes from R1 RED VRF")
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
        "After adding verify route installed "
        "IPv4 routes on R2 GREEN VRF are received from RED VRF , "
        "nexthop is R1 ( R1-R2) link-local address show ip bgp vrf "
        "GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 GREEN VRF are showing preferred routes"
        " received from GREEN VRF , nexthop is R3 ( R2-R3) link-local "
        "nexthop show ip route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete and Add routes from R3 GREEN VRF")

    # Create Static routes
    input_dict_r3 = {
        "r3": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "GREEN",
                    "delete": True,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After deleting routes from R3 GREEN VRF , verify route R2 GREEN"
        " VRF has installed routes received from RED VRF nexthop is R1 "
        "( R1 to R2) link-local address"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("R3 GREEN VRF routes installed with R2 ( R2-R2) link-local nexthop")

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Add routes from R3 GREEN VRF")

    # Create Static routes
    input_dict_r3 = {
        "r3": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "vrf": "GREEN",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes on R2 RED VRF are showing router are received from"
        " GREEN VRF, nexthop R3 (R2-R3) ) link-local address show ip bgp"
        " vrf GREEN  but not active"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "IPv4 routes on R2 RED VRF are showing preferred routes received"
        " from RED m nexthop is R1 (R1-R2) link-local address show ip "
        "route vrf GREEN"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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

    step("Remove and Add VRF import from GREEN to RED")

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {
                    "ipv4": {"unicast": {"import": {"vrf": "GREEN", "delete": True}}}
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After remove of import VRF RED from GREEN VRF , verify RED VRF "
        "routes are removed R2 and R3 GREEN VRF"
    )

    llip = None
    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }

    dut = "r1"

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_rib
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "GREEN"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After adding import VRF RED from GREEN VRF , verify RED VRF routes"
        " are re-learn R2 and R3 GREEN VRF"
    )

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Remove and Add VRF import from GREEN to RED ")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "GREEN",
                "address_family": {
                    "ipv4": {"unicast": {"import": {"vrf": "RED", "delete": True}}}
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After remove of import VRF GREEN from RED VRF , verify GREEN VRF"
        " routes are removed R2 and R1 RED VRF"
    )

    llip = None
    llip = get_llip(topo, "r2", "r3", vrf="GREEN")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r3": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }

    dut = "r3"

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_rib
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "GREEN",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After adding import VRF GREEN from RED VRF , verify GREEN VRF "
        "routes are re-learn R2 and R1 RED VRF"
    )

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_rfc5549_vrf_tc43_p1(request):
    """
    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 route configured with non-default VRF can be advertised
    to another IPv4 IBGP non-default VRF peer.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)
    protocol = "bgp"
    global topo
    topo1 = deepcopy(topo)

    reset_config_on_routers(tgen)

    step(
        "Configure IPv6 EBGP session inside VRF RED between R1 "
        "and R2 using IPv6 link-local address"
    )
    step("Configure IPv4 IBGP session inside VRF GREEN between R2 and R3")
    step("Enable capability extended-nexthop on IPv6 session")
    step("Activate same IPv6 nbr from IPv4 unicast family")
    step("Advertise IPv4 route to BGP using redistribute static")

    logger.info(
        "topo modify from R2 --- R3 ipv6 eBGP session "
        "to ipv4 iBGP session & Remove capability"
    )
    topo1["routers"]["r3"]["bgp"][0]["address_family"]["ipv6"]["unicast"]["neighbor"][
        "r2"
    ]["dest_link"]["r3"].pop("capability")
    topo1["routers"]["r2"]["bgp"][1]["address_family"]["ipv6"]["unicast"]["neighbor"][
        "r3"
    ]["dest_link"]["r2"].pop("capability")

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
    topo1["routers"]["r3"]["bgp"][0]["local_as"] = "200"

    # delete current bgp processes
    input_dict = {"r2": {"bgp": {"local_as": 200, "vrf": "GREEN", "delete": True}}}
    create_router_bgp(tgen, topo, input_dict)
    input_dict = {"r3": {"bgp": {"local_as": 300, "vrf": "GREEN", "delete": True}}}
    create_router_bgp(tgen, topo, input_dict)
    build_config_from_json(tgen, topo1, save_bkup=False)
    result = verify_bgp_convergence(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure prefix-list having 5 IPv4 routes on R1 inside VRF"
        " RED which has nexthop present on R0"
    )

    for rte in range(0, NO_OF_RTES):
        # Create Static routes
        input_dict_r1 = {
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
        result = create_static_routes(tgen, input_dict_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    # Create ip prefix list
    input_dict_2 = {
        "r1": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": 10,
                            "network": NETWORK["ipv4"][0],
                            "action": "permit",
                        },
                        {
                            "seqid": 11,
                            "network": NETWORK["ipv4"][1],
                            "action": "permit",
                        },
                        {
                            "seqid": 12,
                            "network": NETWORK["ipv4"][2],
                            "action": "permit",
                        },
                        {
                            "seqid": 13,
                            "network": NETWORK["ipv4"][3],
                            "action": "permit",
                        },
                        {
                            "seqid": 14,
                            "network": NETWORK["ipv4"][4],
                            "action": "permit",
                        },
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 route received on R2 RED VRF are installed with link-local"
        " address of R1 ( R1 to R2 connected link) verify using show ip"
        " route vrf RED"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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

    step(
        "IPv4 route not present on R2 and R3 GREEN VRF verify using "
        "show ip bgp vrf RED"
    )

    dut = "r3"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_rib
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step("Import RED VRF route inside GREEN VRF")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "GREEN",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 route received on R2 RED VRF are installed with link-local"
        " address of R1 ( R1 to R2 connected link) verify using "
        "show ip route vrf RED"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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

    step(
        "IPv4 route received on R3 with IPv4 nexthop address of R2 "
        "( R2 to R3 connected link) show ip route"
    )

    llip = None
    llip = get_glipv6_loc("r2", "r3", addr_type="ipv4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "GREEN"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(tgen, "ipv4", dut, input_dict, next_hop=llip, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
