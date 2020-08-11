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
from copy import deepcopy
import ipaddr
from re import search as re_search
from time import sleep

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
    addKernelRoute,
    write_test_footer,
    create_prefix_lists,
    verify_rib,
    create_static_routes,
    check_address_types,
    reset_config_on_routers,
    step,
    create_route_maps,
    create_interfaces_cfg,
    get_frr_ipv6_linklocal,
)
from lib.topolog import logger
from lib.bgp import (
    clear_bgp_and_verify,
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
)
from lib.topojson import build_topo_from_json, build_config_from_json
from rfc5549_common_lib import *

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/rfc5549_ibgp_nbr_vrf.json".format(CWD)
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
NETWORK_CMD_IP = "1.0.1.17/32"
NO_OF_RTES = 2
ADDR_TYPE = check_address_types()

"""
      Please view in a fixed-width font such as Courier.

                                      +----+
                                      | R4 |
                                      |    |
                                      +--+-+
                                         | ipv4 nbr
          no bgp           ebgp/ibgp     |
                                         |     ebgp/ibgp
    +----+ 5links   +----+            +--+-+             +----+
    |R0  +----------+ R1 |            | R2 |    ipv6 nbr |R3  |
    |    +----------+    +------------+    +-------------+    |
    +----+          +----+   ipv6 nbr +----+             +----+
           VRF RED         VRF RED
VRF Test cases:
TC34. Verify 5549 IPv4 and IPv6 routes advertise using "redistribute static"
    and "network command" are received on IBGP peer with IPv6 nexthop

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
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)
    global topo

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


def test_rfc5549_red_static_network_ibgp_peer_tc34_p0(request):
    """

    Test extended capability nexthop with ibgp peer.

    Verify 5549 IPv4 and IPv6 routes advertise using "redistribute static"
    and "network command" are received on IBGP peer with IPv6 nexthop

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure IPv6 IBGP session inside VRF RED between R1 and R2 with"
        " global IPv6 address Enable capability extended-nexthop on the"
        "  nbr from both the routers"
    )
    step("Configure 5 link between R0 and R1 inside VRF RED")
    step("Configure loopback on R1 with IPv4 and IPv6 address")

    reset_config_on_routers(tgen)

    step(
        " Configure 5 IPv4/IPv6 static routes in VRF RED"
        " on R1 nexthop for static route exists on different link of R0"
    )
    for addr_type in ADDR_TYPE:
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

    step(
        "Advertise static routes from IPv4 unicast family and IPv6 unicast"
        " family respectively from R1.Configure loopback on R1 with IPv4 addr"
        " & Advertise loopback from IPv4 unicast family using network cmd "
        " from R1"
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
                                "redistribute": [{"redist_type": "static"}],
                                "advertise_networks": [
                                    {"network": NETWORK_CMD_IP, "no_of_network": 1}
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

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 and IPv6 routes advertised using static & network command are"
        "received on R2 BGP and routing table , verify using show ip bgp vrf"
        "RED, show ip route vrf RED for IPv4 routes and show bgp vrf RED"
        " show ipv6 routes vrf RED for IPv6 routes ."
    )

    step("Verify IPv6 routes are installed with IPv6 link-local nexthop")

    dut = "r2"
    protocol = "bgp"
    # verify the routes with nh as ext_nh
    for addr_type in ADDR_TYPE:
        verify_nh_for_static_rtes = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type][0],
                        "no_of_ip": NO_OF_RTES,
                        "next_hop": llip,
                        "vrf": "RED",
                    }
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_static_rtes, next_hop=llip
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_nh_for_static_rtes,
            next_hop=llip,
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify IPv4 routes are installed with IPv6 link local nexthop of R1"
        "R1 to R2 connected link"
    )
    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "static_routes": [
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
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
