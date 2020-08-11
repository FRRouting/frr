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
from time import sleep
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
jsonFile = "{}/rfc5549_default_red_vrf.json".format(CWD)
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
# iterate  through steps
numberoftimes = 2
"""
      Please view in a fixed-width font such as Courier.

                                      +----+
                                      | R4 |
                                      |    |
                                      +--+-+
                                         | ipv4 nbr
          no bgp           ebgp/ibgp     |
                                         |     ebgp/ibgp
    +----+ 5links   +----+  8links    +--+-+             +----+
    |R0  +----------+ R1 +------------+ R2 |    ipv6 nbr |R3  |
    |    +----------+    +------------+    +-------------+    |
    +----+          +----+   ipv6 nbr +----+             +----+

TC44. Verify 5549 IPv4 route form default VRF are advertised to IPv4
    EBGP non-default VRF peer.
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


def test_rfc5549_vrf_tc44_p0(request):
    """
    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 route form default VRF are advertised to IPv4
    EBGP non-default VRF peer.
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
        "Configure one IPv6 EBGP session in default VRF with capability"
        " enabled in between R1 and R2"
    )
    step("Enable same IPv6 session for address family IPv4 also")
    step("Configure IPv4 EBGP session inside VRF RED between R2 and R3")
    step(
        "Advertise static routes using redistribute static from R1 ipv4"
        "address family"
    )
    reset_config_on_routers(tgen)

    step("Configure 5 Static route on R1 default VRF")

    # Create Static routes
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 Routes received on R2 default VRF with IPv6 link-local address,"
        " installed in the RIB & BGP table using show ip route show ip bgp"
    )

    llip = get_llip(topo, "r1", "r2-link0")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure import VRF from default  on R2 IPv4 session between R2 " "and R3")
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

    step(
        "IPv4 Route present in R2 VRF RED with same link-local address as"
        " global VRF (R1 link-local) show ip route vrf RED  show ip bgp vrf "
        "RED"
    )

    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 Route received on R3 VRF RED with next hop as IPv4 address"
        " of R2 to R3 interfacs show ip route vrf RED  show ip bgp vrf RED"
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

    step("Delete static route from R1 default VRF")
    # Create Static routes
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": "blackhole",
                    "delete": True,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After delete static route from R1 , verify route got removed"
        " from R2 and R3 RED VRF show ip route vrf RED show ip bgp vrf RED"
    )

    llip = get_llip(topo, "r1", "r2-link0")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    step("Verifying route got revmoed from R2")
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

    step("Verifying route got revmoed from R3 vrf RED table")

    dut = "r3"
    input_dict_r1 = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
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
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Shut static route nexthop from R1 default VRF")

    dut = "r1"
    intf = "r2-link0"
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

    step("No shut static route nexthop from R1 default VRF")

    # Bringup interface
    shutdown_bringup_interface(tgen, dut, intf, True)

    llip = get_llip(topo, "r1", "r2-link0")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    step(
        "After no shut nexthop verify route got relearn on R2 and R3 RED VRF"
        "show ip route vrf RED show ip bgp vrf RED"
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
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Add/remove VRF import multiple times of R2")
    for number in range(0, numberoftimes):
        step("Remove VRF import - Iteration number {}".format(number))
        configure_bgp_on_r2 = {
            "r2": {
                "bgp": {
                    "local_as": "200",
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"import": {"vrf": "default", "delete": True}}
                        }
                    },
                }
            }
        }
        result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "After removing import VRF from default , verify route got removed"
            "from R3 using show ip route and show ip bgp"
        )

        dut = "r3"
        bgp_rib = verify_bgp_rib(
            tgen, "ipv4", dut, input_dict_r1, next_hop=llip, expected=False
        )
        assert bgp_rib is not True, (
            "Testcase {} : Failed \n Route still "
            "present in BGP RIB. Error: {}".format(tc_name, bgp_rib)
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
            "Testcase {} : Failed \n Route still "
            "present in RIB. Error: {}".format(tc_name, result)
        )

        step(
            "After adding import VRF from default , verify route got relearn of"
            " R3 using show ip route and show ip bgp"
        )
        step("Add VRF import - Iteration number {}".format(number))
        configure_bgp_on_r2 = {
            "r2": {
                "bgp": {
                    "local_as": "200",
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {"unicast": {"import": {"vrf": "default"}}}
                    },
                }
            }
        }
        result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        dut = "r3"

        bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, input_dict_r1, next_hop=llip)
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )

        result = verify_rib(
            tgen, "ipv4", dut, input_dict_r1, next_hop=llip, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
