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
jsonFile = "{}/rfc5549_ecmp_vrf_topo2.json".format(CWD)
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


def test_rfc5549_ebgp_ecmp_ibgp_vrf_tc42_p1(request):
    """
    Verify extended capability next hop with ecmp.

    Verify 5549 IPv4 routes received from 8 ECMP EBGP session gets
    advertised to IBGP peer after changing it to global via route-map
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure 8 IPv6 EBGP session inside default VRF between R1"
        "and R2 with global IPv6 address"
    )
    step(
        "Configure IPv6 IBGP session inside VRF RED between R2 and R3 "
        "with global IPv6 address"
    )
    step(
        "Enable capability extended-nexthop on all the neighbors " "from both the peers"
    )
    step("Activate IPv6 neighbors from IPv4 unicast family")
    step("Configure 5 link between R0 and R1 inside default VRF")

    reset_config_on_routers(tgen)

    step(
        "Advertise static routes from IPv4 unicast family and IPv6 "
        "unicast family respectively"
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

    step("Configure route-map prefer global on R2 IN direction")

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

    # Configure neighbor for route map
    route_map_to_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "default_ipv4_unicast": "False",
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
                                        },
                                        "r2-link1": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                }
                                            ]
                                        },
                                        "r2-link2": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                }
                                            ]
                                        },
                                        "r2-link3": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                }
                                            ]
                                        },
                                        "r2-link4": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                }
                                            ]
                                        },
                                        "r2-link5": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                }
                                            ]
                                        },
                                        "r2-link6": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                }
                                            ]
                                        },
                                        "r2-link7": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                }
                                            ]
                                        },
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

    step("Import default VRF inside RED VRF")
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": 200,
                "vrf": "RED",
                "address_family": {"ipv4": {"unicast": {"import": {"vrf": "default"}}}},
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 route received on R2 default VRF with 8 global IPv6 nexthop"
        "address of R1 (R1-R2) link using show ip route"
    )

    dut = "r2"
    protocol = "bgp"
    llip = []
    for lnk in intf_list:
        llip.append(get_glipv6(topo, "r1", lnk))
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
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 route received on R2 RED VRF with 8 global IPv6 nexthop "
        "address of R1 (R1-R2) link using show ip route vrf RED"
    )

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

    step("Add rechability for R3 routes.")

    nh = topo["routers"]["r2"]["links"]["r3-link0"]["ipv6"].split("/")[0]
    for rte in range(0, 8):
        r1tor2intf = topo["routers"]["r1"]["links"]["r2-link{}".format(rte)][
            "ipv6"
        ].split("/")[0]
        # Create Static routes
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": "{}/128".format(r1tor2intf),
                        "no_of_ip": 1,
                        "next_hop": nh,
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
        "IPv4 route received on R3 RED VRF with link-local address"
        " of R2 (R2-R3 link) show ip route vrf RED"
    )

    dut = "r3"
    llip = []
    llip.append(get_llip(topo, "r2", "r3-link0", vrf="RED"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Remove route-map prefer global on R2 IN direction")

    # Configure neighbor for route map
    route_map_to_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "default_ipv4_unicast": "False",
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
                                                    "delete": True,
                                                }
                                            ]
                                        },
                                        "r2-link1": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                    "delete": True,
                                                }
                                            ]
                                        },
                                        "r2-link2": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                    "delete": True,
                                                }
                                            ]
                                        },
                                        "r2-link3": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                    "delete": True,
                                                }
                                            ]
                                        },
                                        "r2-link4": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                    "delete": True,
                                                }
                                            ]
                                        },
                                        "r2-link5": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                    "delete": True,
                                                }
                                            ]
                                        },
                                        "r2-link6": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                    "delete": True,
                                                }
                                            ]
                                        },
                                        "r2-link7": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_set_nexthop_preference",
                                                    "direction": "in",
                                                    "activate": "ipv4",
                                                    "delete": True,
                                                }
                                            ]
                                        },
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
        "IPv4 route received on R2 default VRF with 8 link-local IPv6"
        " nexthop address of R1 (R1-R2) link using show ip route"
    )

    dut = "r2"

    llip = []
    for lnk in intf_list:
        llip.append(get_llip(topo, "r1", lnk))
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
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 route received on R2 RED VRF with 8 link-local IPv6 "
        "nexthop address of R1 (R1-R2) link using show ip route vrf RED"
    )

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
        "verify route uptime to check that after removing route-map "
        "prefer global no impact seen on R3 RED VRF table"
    )

    dut = "r3"
    llip = []
    llip.append(get_llip(topo, "r2", "r3-link0", vrf="RED"))
    assert llip is not [], "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
