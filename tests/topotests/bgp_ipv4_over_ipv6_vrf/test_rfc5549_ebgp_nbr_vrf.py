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
    verify_rib,
    create_static_routes,
    check_address_types,
    reset_config_on_routers,
    step,
    create_route_maps,
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, create_router_bgp, verify_bgp_rib
from lib.topojson import build_topo_from_json, build_config_from_json
from rfc5549_common_lib import *

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/rfc5549_ebgp_nbr_vrf.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)


# Global variables
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
MASK = {"ipv4": "32", "ipv6": "128"}
NEXT_HOP = {
    "ipv4": ["10.0.0.1", "10.0.1.1", "10.0.2.1", "10.0.3.1", "10.0.4.1"],
    "ipv6": ["Null0", "Null0", "Null0", "Null0", "Null0"],
}
NO_OF_RTES = 2
NETWORK_CMD_IP = "1.0.1.17/32"
ADDR_TYPES = check_address_types()
BGP_CONVERGENCE_TIMEOUT = 10

"""
      Please view in a fixed-width font such as Courier.
                                      +----+
                                      | R4 |
                                      |    |
                                      +--+-+
                                         | ipv4 nbr
          no bgp           ebgp          |
                                         |     ebgp/ibgp
    +----+ 5links   +----+            +--+-+             +----+
    |R0  +----------+ R1 |            | R2 |    ipv6 nbr |R3  |
    |    +----------+    +------------+    +-------------+    |
    +----+          +----+   ipv6 nbr +----+             +----+


VRF Test cases:
TC33:   Verify 5549 ipv4 route's nexthop updated dynamically when in route-map
        is applied on receiving BGP peer
TC35:   Verify 5549 IPv4 routes are deleted after un-configuring of
    "network command" and "redistribute static knob"
TC39:   Verify 5549 IPv4 route ping is working fine and nexhop
        installed in kernel as IPv4 link-local address
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


def test_rfc5549_routemap_tc33_vrf_p0(request):
    """
    Test exted capability nexthop with route map for VRF neighbors of BGP.

    Verify 5549 ipv4 route's nexthop updated dynamically when in route-map
    is applied on receiving BGP peer
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure IPv6 EBGP session inside VRF RED between R1 and R2 using"
        " global ipv6 address"
    )
    step("Enable capability extended-nexthop on the neighbor from both the " "routers")
    step("Activate same IPv6 nbr from IPv4 unicast family")
    step("Configure 5 link between R0 and R1 inside VRF RED")

    reset_config_on_routers(tgen)
    step(
        "Configure 5 IPv4 static routes on R1 VRF RED (nexthop for static "
        "route exists on different link of R0"
    )
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

    step("Advertise static routes using redistribute static")
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "default_ipv4_unicast": "True",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    },
                }
            ]
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure route-map on R2 IN direction to set nexthop as " "prefered global")

    # Create route map
    route_map_on_r2 = {
        "r2": {
            "route_maps": {
                "rmap_set_nexthop_preference": [
                    {"action": "permit", "set": {"ipv6": {"nexthop": "prefer-global"}}}
                ]
            }
        }
    }
    result = create_route_maps(tgen, route_map_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Routes are received on R2 VRF RED with link-local address in BGP "
        "show ip bgp vrf RED and RIB show ip route vrf RED command"
    )

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    protocol = "bgp"
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

    # Configure neighbor for route map
    route_map_to_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "vrf": "RED",
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link0": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, route_map_to_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After applying the route-map nexthop is, global ip address is "
        "showing in show ip bgp vrf RED & RIB show ip route vrf RED command"
    )

    glipv6 = get_glipv6(topo, "r1", "r2-link0")
    assert glipv6 is not None, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": glipv6,
                    "vrf": "RED",
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glipv6
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glipv6, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    write_test_footer(tc_name)


def test_rfc5549_remove_red_static_network_ebgp_peer_tc35_vrf_p0(request):
    """
    Test exted capability nexthop with ebgp.

    Verify 5549 IPv4 routes are deleted after un-configuring of
    "network command" and "redistribute static knob"
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step(
        "Configure IPv6 EBGP session inside VRF RED between R1 and R2 "
        " with global IPv6 address Enable capability extended-nexthop "
        "on the nbr from both the routers , Activate same IPv6 nbr "
        "from IPv4 unicast family"
    )

    step("Configure 5 link between R0 and R1 inside VRF RED")
    step("Configure loopback on R1 with IPv4 and IPv6 address")
    reset_config_on_routers(tgen)

    step(
        " Configure 5 IPv4 static routes in VRF RED"
        " on R1 nexthop for static route exists on different link of R0"
    )
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
        "Advertise static routes from IPv4 unicast family"
        "from R1 address, Advertise loobak from IPv4 unicast family using "
        "network command from R1"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "default_ipv4_unicast": "True",
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
            ]
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes advertised using static and network command are"
        "received on R2 BGP & routing table, verify using show ip bgp vrf RED"
        " show ip route vrf RED for IPv4 routes "
    )
    step("Verify IPv4 routes are installed with IPv6 link-local nexthop")

    glipv6 = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert glipv6 is not None, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    dut = "r2"
    protocol = "bgp"
    verify_nh_for_static_rtes = {
        "r1": {
            "advertise_networks": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": get_glipv6,
                    "vrf": "RED",
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=get_glipv6
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes,
        next_hop=get_glipv6,
        protocol=protocol,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "advertise_networks": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": glipv6,
                    "vrf": "RED",
                }
            ]
        }
    }
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=glipv6, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Remove IPv4 loopback network advertised using network cmd from R1")
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "vrf": "RED",
                "local_as": "100",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": NETWORK_CMD_IP,
                                    "no_of_network": 1,
                                    "delete": True,
                                }
                            ]
                        }
                    }
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After removing IPv4 routes from network command those routes are "
        "not present in R2 , but routes which are advertised using "
        "redistribute static are still present in the on R2 with "
        "IPv6 link-local nexthop, verify using show ip bgp vrf RED "
        " & show ip route vrf RED"
    )

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": glipv6,
                    "vrf": "RED",
                }
            ]
        }
    }

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_nw_cmd_rtes,
        next_hop=glipv6,
        protocol=protocol,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed \n "
    "Error: Routes still present in BGP rib".format(tc_name)

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=get_glipv6
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes,
        next_hop=get_glipv6,
        protocol=protocol,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Advertise same IPv4 loopback network using network command from R1")
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "vrf": "RED",
                "local_as": "100",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": NETWORK_CMD_IP, "no_of_network": 1}
                            ]
                        }
                    }
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After re-advertising using network command , verify same "
        "routes are installed in RIB and FIB"
    )
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=glipv6, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n "
    "Error: Routes still present in BGP rib".format(tc_name)

    step("Remove IPv4 routes advertised using redistribute " "static command from R1")
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "vrf": "RED",
                "local_as": "100",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}]
                        }
                    }
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After removing IPv4 routes from redistribute static those routes"
        " are removed from R2, after re-advertising routes which are "
        "advertised using network are still present in the on R2 with "
        "IPv6 link-local nexthop, verify using show ip bgp vrf RED"
        "show ip route vrf RED"
    )
    # verify the routes with nh as ext_nh
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": glipv6,
                    "vrf": "RED",
                }
            ]
        }
    }

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glipv6
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Error: Routes still"
        " present in BGP rib".format(tc_name)
    )
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glipv6, protocol=protocol
    )
    assert result is not True, "Testcase {} : Failed \n Error: Routes "
    "still present in RIB".format(tc_name)

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": glipv6,
                    "vrf": "RED",
                }
            ]
        }
    }

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=glipv6, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
