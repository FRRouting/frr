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
    write_test_footer,
    get_frr_ipv6_linklocal,
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
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
)
from lib.topojson import build_topo_from_json, build_config_from_json
from rfc5549_common_lib import *

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/rfc5549_red_default_vrf_topo2.json".format(CWD)
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

1. Verify IPv4 routes received from 8 ECMP Unnumbered EBGP session
get advertised to IBGP peer with single nexthop
2. Verify IPv4 routes received from 8 ECMP EBGP session gets advertised
 to IBGP peer after changing the nexthop via route-map

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


def test_rfc5549_vrf_tc40_p1(request):
    """

    Test extended capability nexthop with VRF.

    Verify 5549 IPv4 routes are configured with non-default VRF, are installed
    with correct nexthop on default VRF after shut / no shut neighbor
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure IPv6 EBGP session inside VRF RED over global IP " "between R1 and R2"
    )
    step(
        "Configure IPv6 IBGP session inside default VRF over global "
        "IP between R2 and R3"
    )
    step("Enable capability extended-nexthop on the neighbor from" " both the routers")
    step("Activate same IPv6 nbr from IPv4 unicast family")
    step("Configure one static route from R1 and one from R3")
    step(
        "Advertise static routes from IPv4 address family of R1 RED VRF"
        " and R3 default VRF"
    )

    reset_config_on_routers(tgen)

    for addr_type in ADDR_TYPES:
        for rte in range(0, NO_OF_RTES):
            # Create Static routes
            input_dict = {
                "r1": {
                    "static_routes": [
                        {
                            "network": NETWORK[addr_type][rte],
                            "no_of_ip": NO_OF_RTES,
                            "next_hop": "blackhole",
                            "vrf": "RED",
                        }
                    ]
                }
            }
            result = create_static_routes(tgen, input_dict)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    for addr_type in ADDR_TYPES:
        for rte in range(0, NO_OF_RTES):
            # Create Static routes
            input_dict = {
                "r3": {
                    "static_routes": [
                        {
                            "network": NETWORK2[addr_type][rte],
                            "no_of_ip": NO_OF_RTES,
                            "next_hop": "blackhole",
                        }
                    ]
                }
            }
            result = create_static_routes(tgen, input_dict)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Advertise loopback network from IPv4 address family of R1 "
        "RED VRF and R3 default VRF"
    )
    lp_ip_r1 = topo["routers"]["r1"]["links"]["lo"]["ipv4"]
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "local_as": "100",
                "vrf": "RED",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": lp_ip_r1, "no_of_network": 1}
                            ],
                            "redistribute": [{"redist_type": "static"}],
                        }
                    }
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    lp_ip_r3 = topo["routers"]["r3"]["links"]["lo"]["ipv4"]
    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "local_as": "200",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": lp_ip_r3, "no_of_network": 1}
                            ],
                            "redistribute": [{"redist_type": "static"}],
                        }
                    }
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 Route (static and loopback network) received on R2 RED VRF"
        " with R1 (R1-R2) link-local address using show ip bgp vrf RED"
        "show ip route vrf RED"
    )

    llip_vrf_red = None
    llip_vrf_red = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip_vrf_red is not None, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    llip = None
    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    protocol = "bgp"
    verify_nh_for_static_rtes_vrf_red = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES, "vrf": "RED"}
            ]
        }
    }
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [{"network": NETWORK["ipv4"][0], "no_of_ip": NO_OF_RTES}]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes_vrf_red,
        next_hop=llip_vrf_red,
        multi_nh=True,
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes_vrf_red,
        next_hop=llip_vrf_red,
        protocol=protocol,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 Route (static and loopback network) received on R3 default"
        " VRF with R2 (R2-R3) link-local address using show ip bgp "
        "show ip route"
    )

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

    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "local_as": "200",
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
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = None
    llip = get_llip(topo, "r2", "r3")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "local_as": "200",
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}}
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Import default VRF route to RED VRF on R2")

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

    llip = None
    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes_vrf_red, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    step("Shut IPv6 neighbor from IPv4 address family from R1 node")
    shut_bgp_peer = {
        "r1": {
            "bgp": {
                "local_as": 100,
                "vrf": "RED",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r1-link0": {"shutdown": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r1-link0": {"shutdown": True}}}
                            }
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, shut_bgp_peer)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "After shut of neighbor from IPv4 address family from R1 , verify "
        "R1 static and loopback routes are removed from R2 RED VRF and "
        "R3 default VRF"
    )

    dut = "r2"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes_vrf_red, next_hop=llip
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes_vrf_red,
        next_hop=llip,
        protocol=protocol,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    dut = "r3"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    step("Shut IPv6 neighbor from IPv4 address family from R1 node")
    shut_bgp_peer = {
        "r1": {
            "bgp": {
                "local_as": 100,
                "vrf": "RED",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r1-link0": {"shutdown": False}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link0": {
                                            "shutdown": False,
                                            "activate": "ipv4",
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, shut_bgp_peer)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_bgp_convergence(tgen, topo)
    assert (
        result is True
    ), "Testcase {} : Failed \n BGP is converged" "Error: {}".format(tc_name, result)

    step(
        "After No shut of neighbor from IPv4 address family from R1 ,"
        " verify R1 static and loopback routes are re-learn on R2 RED "
        "VRF and R3 default VRF"
    )

    llip = None
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes_vrf_red, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes_vrf_red,
        next_hop=llip,
        protocol=protocol,
    )
    # this has been commented for vrf bug id 2552674, once fixed, will be
    # un commented
    # assert result is True, "Testcase {} : Failed \n Error: {}".format(
    #    tc_name, result)

    llip = None
    llip = get_llip(topo, "r2", "r3")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    # this has been commented for vrf bug id 2552674, once fixed, will be
    # un commented
    # assert bgp_rib is  True, "Testcase {} : Failed \n Error: {}".format(
    #     tc_name, bgp_rib)

    step("shut IPv6 neighbor from IPv4 address family from R3 node")
    shut_bgp_peer = {
        "r3": {
            "bgp": {
                "local_as": 200,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r3": {"shutdown": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r3": {"shutdown": True}}}
                            }
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, shut_bgp_peer)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "After shut of neighbor from IPv4 address family from R3 , "
        "verify R3 static and loopback routes are removed from R2 "
        "default VRF and R1 RED VRF"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    llip = None
    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes_vrf_red, next_hop=llip
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes_vrf_red,
        next_hop=llip,
        protocol=protocol,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    step("No shut IPv6 neighbor from IPv4 address family from R3 node")
    shut_bgp_peer = {
        "r3": {
            "bgp": {
                "local_as": 200,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {"dest_link": {"r3": {"shutdown": False}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3": {"shutdown": False, "activate": "ipv4"}
                                    }
                                }
                            }
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, shut_bgp_peer)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_bgp_convergence(tgen, topo)
    assert (
        result is True
    ), "Testcase {} : Failed \n BGP is not converged" "Error: {}".format(
        tc_name, result
    )

    step(
        "After No shut of neighbor from IPv4 address family from R1 , "
        "verify R1 static and loopback routes are re-learn on R2 default"
        "VRF and R1 RED VRF"
    )

    llip = None
    llip = get_llip(topo, "r3", "r2")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    llip = None
    llip = get_llip(topo, "r2", "r1-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    dut = "r1"
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes_vrf_red, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
