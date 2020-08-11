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
from lib.bgp import (
    clear_bgp_and_verify,
    clear_bgp,
    modify_as_number,
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
    verify_bgp_convergence_from_running_config,
)
from lib.topolog import logger
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
from mininet.topo import Topo
from lib.topogen import Topogen, get_topogen
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
from lib.topojson import build_topo_from_json, build_config_from_json
from rfc5549_common_lib import *


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../../"))

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/rfc5549_ecmp_vrf.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)


# pylint: disable=C0413
# Import topogen and topotest helpers


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
INTF_LIST = [
    "r2-link0",
    "r2-link1",
    "r2-link2",
    "r2-link3",
    "r2-link4",
    "r2-link5",
    "r2-link6",
    "r2-link7",
]
INTF_LIST2 = [
    "r3-link0",
    "r3-link1",
    "r3-link2",
    "r3-link3",
    "r3-link4",
    "r3-link5",
    "r3-link6",
    "r3-link7",
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

TC44. Verify IPv4 routes are installed with correct nexthop after
      clearing the BGP session
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


def test_rfc5549_clear_bgp_vrf_tc38_p1(request):
    """
    Verify extended capability next hop with clear bgp.

    Verify IPv4 routes are installed with correct
    nexthop after clearing the BGP session
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure 8 IPv6 EBGP ECMP session inside VRF RED between R1 and "
        "R2 with global IPv6 address"
    )
    step(
        "Configure 8 IPv6 EBGP ECMP session inside default VRF between R2 "
        "and R3 with global IPv6 address"
    )
    step("Enable capability extended-nexthop on the neighbor from both the " "routers")
    step("Activate same IPv6 nbr from IPv4 unicast family")
    step("Configure 5 link between R0 and R1 inside VRF RED")
    step("Configure loopback on R1 RED VRF with IPv4 address")

    reset_config_on_routers(tgen)

    step(
        "configure 5 IPv4 static routes on R1 inside VRF RED(nexthop"
        " for static route exists on different links of R0)"
    )

    for addr_type in ["ipv4"]:
        for rte in range(0, NO_OF_RTES):
            # Create Static routes
            input_dict = {
                "r1": {
                    "static_routes": [
                        {
                            "network": NETWORK[addr_type][rte],
                            "no_of_ip": 1,
                            "next_hop": NEXT_HOP[addr_type][rte],
                            "vrf": "RED",
                        }
                    ]
                }
            }
            result = create_static_routes(tgen, input_dict)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step("Advertise static routes from IPv4 unicast family")
    step(
        "Advertise network from IPv4 unicast family using "
        "network command and configure max-ecmp path 8"
    )
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "local_as": 100,
                "vrf": "RED",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static"}],
                            "advertise_networks": [
                                {"network": NETWORK_CMD_IP, "no_of_network": 1}
                            ],
                        }
                    }
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("configure max-ecmp path 8")

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "local_as": 100,
                "vrf": "RED",
                "address_family": {
                    "ipv4": {"unicast": {"maximum_paths": {"ibgp": 8}}},
                    "ipv6": {"unicast": {"maximum_paths": {"ibgp": 8}}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": [
                {
                    "local_as": 200,
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {"unicast": {"maximum_paths": {"ibgp": 8}}},
                        "ipv6": {"unicast": {"maximum_paths": {"ibgp": 8}}},
                    },
                },
                {
                    "local_as": 200,
                    "address_family": {
                        "ipv4": {"unicast": {"maximum_paths": {"ibgp": 8}}},
                        "ipv6": {"unicast": {"maximum_paths": {"ibgp": 8}}},
                    },
                },
            ]
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Import RED VRF route to default VRF on R2")
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
        "IPv4 routes present in R2 RED VRF BGP table and in RIB using "
        "show ip bgp vrf RED, show ip route vrf RED Nexthop address on R2 "
        "should be R1 link-local address ( R1 to R2 connected link)"
    )

    llip = []
    for lnk in INTF_LIST:
        llip.append(get_llip(topo, "r1", lnk, vrf="RED"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    protocol = "bgp"
    # verify the routes with nh as ext_nh
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": llip,
                    "vrf": "RED",
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes present in R3 default VRF BGP table and RIB using "
        "show ip bgp show ip route  Nexthop address as R2 link-local "
        "address(R2 to R3)"
    )
    llip = []
    for lnk in INTF_LIST2:
        llip.append(get_llip(topo, "r2", lnk))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": llip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Clear BGP neighbor from R1 from VRF RED")
    dut = "r1"
    # Clear bgp
    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, dut, vrf="RED")

    result = verify_bgp_convergence(tgen, topo, dut=dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After clear bgp from R1 RED VRF , verify route got relearn R3 "
        "default VRF using show ip bgp , show ip route, verify uptime for"
        " routes on all the nodes"
    )

    dut = "r3"
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": llip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Clear BGP neighbor from R2 default VRF")

    dur = "r2"
    # Clear bgp
    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, dut)

    result = verify_bgp_convergence(tgen, topo, dut=dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After clear BGP from R2 default VRF , verify no impact seen on R2"
        "RED VRF routes , verify up-time using show ip route VRF RED"
    )

    llip = []
    for lnk in INTF_LIST:
        llip.append(get_llip(topo, "r1", lnk, vrf="RED"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    protocol = "bgp"
    # verify the routes with nh as ext_nh
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": llip,
                    "vrf": "RED",
                }
            ]
        }
    }
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes,
        next_hop=llip,
        protocol=protocol,
        uptime="00:00:05",
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_bgp_convergence(tgen, topo, dut=dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "On R3 default VRF routes got re-lean uptime is reset using using "
        "show ip bgp, show ip route "
    )

    llip = []
    for lnk in INTF_LIST2:
        llip.append(get_llip(topo, "r2", lnk))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": llip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
