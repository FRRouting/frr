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
jsonFile = "{}/rfc5549_ibgp_ebgp_ecmp_vrf.json".format(CWD)
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

TC37. Verify 5549 IPv4 routes advertised from non-default to default
    VRF when 8 ECMP IBGP session configured inside non-default VRF
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


def test_rfc5549_vrf_tc37_p1(request):
    """

    Test extended capability nexthop ecmp.

    Verify 5549 IPv4 routes advertised from non-default to default
    VRF when 8 ECMP IBGP session configured inside non-default VRF
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure 8 IPv6 IBGP session inside VRF RED between"
        "R1 and R2 global IPv6 address"
    )
    step("Configured IPv6 EBGP session between R2 to R3 with default VRF")

    step(
        "Enable capability extended-nexthop on all the neighbors"
        "from both the routers"
    )

    step("Activate same ipv6 nbr from ipv4 unicast family")

    step("Configure 5 link between R0 and R1 VRF RED")

    reset_config_on_routers(tgen)

    step(
        "configure 5 IPv4 static routes on R1 inside VRF RED "
        "(nexthop for static route exists on different links of R0)"
    )

    step("Configure loopback on R1 inside VRF RED with IPv4 address")

    for addr_type in ADDR_TYPES:
        for rte in range(0, 5):
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
    step("Advertise network from IPv4 unicast family using network command")

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "local_as": "100",
                "vrf": "RED",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static"}],
                            "advertise_networks": [
                                {"network": NETWORK_CMD_IP, "no_of_network": 1}
                            ],
                        }
                    },
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes advertised using static and network command are received"
        " on R2 BGP and routing table , verify using show ip bgp vrf RED show"
        " ip route vrf RED for IPv4 routes ."
    )

    llip = []
    for lnk in intf_list:
        llip.append(get_llip(topo, "r1", lnk, vrf="RED"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "advertise_networks": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": llip,
                    "vrf": "RED",
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    step(
        "Configure max ECMP path 1 and than change to 8 "
        "( max-ibgp path 1 , max-ibgp -path 8)"
    )

    step("configure max-ecmp path 1")

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "vrf": "RED",
                "local_as": 100,
                "address_family": {
                    "ipv4": {"unicast": {"maximum_paths": {"ibgp": 1}}},
                    "ipv6": {"unicast": {"maximum_paths": {"ibgp": 1}}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "vrf": "RED",
                "local_as": 100,
                "address_family": {
                    "ipv4": {"unicast": {"maximum_paths": {"ibgp": 1}}},
                    "ipv6": {"unicast": {"maximum_paths": {"ibgp": 1}}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes installed on R2 VRF red with 8 IPv6 link-local nexthop"
        " in BGP table , and with one nexthop in RIB"
    )

    llip = []
    for lnk in intf_list:
        llip.append(get_llip(topo, "r1", lnk, vrf="RED"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, multi_nh=True
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = False
    for nh in llip:
        result = verify_rib(
            tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=nh, protocol=protocol
        )
        if result is True:
            break
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("configure max-ecmp path 8")

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "vrf": "RED",
                "local_as": 100,
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
            "bgp": {
                "vrf": "RED",
                "local_as": 100,
                "address_family": {
                    "ipv4": {"unicast": {"maximum_paths": {"ibgp": 8}}},
                    "ipv6": {"unicast": {"maximum_paths": {"ibgp": 8}}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, multi_nh=True
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=nh, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": 100,
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "RED"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    llip = []
    llip.append(get_llip(topo, "r2", "r3"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes received on R3 with R2 (R2-R3) link-local address verify"
        " using show ip bgp show ip route "
    )

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
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, multi_nh=True
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Random shut /no shut of ECMP links")

    randnum = random.randint(0, 5)
    # Shutdown interface
    dut = "r2"

    intf = topo["routers"]["r2"]["links"]["r1-link{}".format(randnum)]["interface"]
    step(
        " interface which is about to be shut no shut between r1 and r2 is "
        "{}".format(intf)
    )
    shutdown_bringup_interface(tgen, dut, intf, False)

    nhop = get_llip(topo, "r1", "r2-link{}".format(randnum), vrf="RED")
    assert nhop is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=nhop, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )

    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes,
        next_hop=nhop,
        protocol=protocol,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    step("No shut of the nexthop interfaces")
    # Bringup interface
    shutdown_bringup_interface(tgen, dut, intf, True)

    for rtr in ["r1", "r2"]:
        clear_bgp(tgen, "ipv4", rtr, vrf="RED")
        clear_bgp(tgen, "ipv6", rtr, vrf="RED")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After no shut of link nexthop is updated in R2 RED VRF and default "
        "VRF table show ip route vrf RED , show ip route "
    )
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=nhop, multi_nh=True
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=nhop, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Remove IPv4 routes advertised using network and redistribute "
        "static command from R1"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "local_as": "100",
                "vrf": "RED",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}],
                            "advertise_networks": [
                                {
                                    "network": NETWORK_CMD_IP,
                                    "no_of_network": 1,
                                    "delete": True,
                                }
                            ],
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}]
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After removing IPv4 routes verify route got removed from R2 VRF "
        "and default VRF using show ip route vrf RED and R3 show ip route "
    )

    llip = []
    for lnk in intf_list:
        llip.append(get_llip(topo, "r1", lnk, vrf="RED"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes,
        next_hop=llip,
        protocol=protocol,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still present"
        "in RIB. Error: {}".format(tc_name, result)
    )

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "advertise_networks": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": llip,
                    "vrf": "RED",
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=llip, expected=False
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_nw_cmd_rtes,
        next_hop=llip,
        protocol=protocol,
        expected=False,
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    step("Advertised IPv4 routes again from R1")

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "local_as": "100",
                "vrf": "RED",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static"}],
                            "advertise_networks": [
                                {"network": NETWORK_CMD_IP, "no_of_network": 1}
                            ],
                        }
                    },
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After advertising IPv4 routes verify route got re-lean on R2 VRF"
        " with R1 (R1-R2) link-local address show ip route vrf RED and R3"
        " with R2 (R2-R3) link-local address show ip route"
    )

    llip = []
    for lnk in intf_list:
        llip.append(get_llip(topo, "r1", lnk, vrf="RED"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "advertise_networks": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": llip,
                    "vrf": "RED",
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    step(
        "Configure IN route - map to set ipv6 next hop as global on R2 "
        "R3 for (R2-to R3) link."
    )

    # Create route map
    route_map_on_r3 = {
        "r3": {
            "route_maps": {
                "rmap_set_nexthop_preference": [
                    {"action": "permit", "set": {"ipv6": {"nexthop": "prefer-global"}}}
                ]
            }
        }
    }
    result = create_route_maps(tgen, route_map_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure neighbor for route map
    route_map_to_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "local_as": "200",
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3": {
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
    result = create_router_bgp(tgen, topo, route_map_to_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After setting next hop as global , verify IPv4 routes installed on"
        " R3 with global address of R2 (R2-R3) link show ip route"
    )

    dut = "r3"
    llip = []
    llip.append(get_glipv6(topo, "r2", "r3"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, multi_nh=True
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
