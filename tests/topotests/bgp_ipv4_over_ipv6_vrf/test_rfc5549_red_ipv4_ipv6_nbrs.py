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
from lib.bgp import verify_bgp_convergence, create_router_bgp, verify_bgp_rib
from lib.topolog import logger
from lib.common_config import (
    start_topology,
    write_test_header,
    create_interfaces_cfg,
    write_test_footer,
    get_frr_ipv6_linklocal,
    verify_rib,
    create_static_routes,
    check_address_types,
    reset_config_on_routers,
    step,
    create_route_maps,
)
from mininet.topo import Topo
from lib.topogen import Topogen, get_topogen
from copy import deepcopy
import os
import sys
import time
import json
import pytest
from lib.topojson import build_topo_from_json, build_config_from_json
from rfc5549_common_lib import *


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
# Import topogen and topotest helpers

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/rfc5549_red_ipv4_ipv6_nbrs.json".format(CWD)
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
TC41:   Verify 5549 Ipv4 route configured in non-default VRF, installed with
    correct next hop when same route is advertised via IPV4 and IPv6 BGP peers.
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


def test_rfc5549_ipv4_ipv6_nbr_adv_same_rte_tc41_p1(request):
    """

    Test exted capability nexthop with route map in.

    Verify 5549 Ipv4 route configured in non-default VRF, installed with
    correct next hop when same route is advertised via IPV4 and IPv6 BGP peers.
    """

    global topo
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Configure IPv6 EBGP session inside VRF RED between R1 and R2 "
        "with global address"
    )
    step("Configure IPv4 EBGP session inside default between R2 and R3")
    step(
        "Configure IPv6 IBGP session inside default between R2 and R4 with"
        " global address"
    )
    step("Enable capability extended-nexthop on both the IPv6 BGP peers")
    step("Configure multipath as path relax inside VRF BGP session " "on all the nodes")

    step("Activate same IPv6 nbr from IPv4 unicast family")
    reset_config_on_routers(tgen)
    global NETWORK_CMD_IP

    NETWORK_CMD_IP = topo["routers"]["r3"]["links"]["lo"]["ipv4"]

    step(
        "Configure loopback on R1 inside VRF RED and R3 default VRF"
        " with Same IPv4 address"
    )

    intf = topo["routers"]["r3"]["links"]["lo"]["interface"]
    topo1 = {
        "r3": {
            "links": {"lo": {"ipv4": NETWORK_CMD_IP, "interface": intf, "delete": True}}
        }
    }
    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    intf = topo["routers"]["r1"]["links"]["lo"]["interface"]
    NETWORK_CMD_IP = topo["routers"]["r1"]["links"]["lo"]["ipv4"]
    topo1 = {"r3": {"links": {"lo": {"ipv4": NETWORK_CMD_IP, "interface": intf}}}}
    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure loopback on R1 inside VRF RED and R3 default"
        "VRF with Same IPv4 address"
    )

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

    step("Advertise loopback address from R3 using network command")

    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": NETWORK_CMD_IP, "no_of_network": 1}
                            ]
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes installed on R2 BGP table with IPv6 R1 ( R1-R2) "
        "link-local nexthop , verify using show ip bgp vrd RED "
        "show ip route vrf RED"
    )

    protocol = "bgp"
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    verify_nh_for_prefix = {
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

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Same IPv4 installed on R2 default VRF with IPv4 nexthop of" " R3 ( R3-R2) link"
    )

    llip = get_glipv6(topo, "r3", "r2", addr_type="ipv4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    verify_nh_for_prefix = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip,}
            ]
        }
    }

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Import VRF red into default VRF on R2")

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

    step("IPv4 routes advertised to R4 with IPv6 global address" "of R2 ( R2-R4) link")

    llip = get_glipv6(topo, "r2", "r4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r4"
    verify_nh_for_prefix = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip,}
            ]
        }
    }

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "After import verify IPv4 routes present on R2 default VRF with"
        " IPv4 and IPv6 link-local of R1 (R1-R2) using show ip bgp "
        "show ip route "
    )

    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    verify_nh_for_prefix = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip,}
            ]
        }
    }

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("IPv4 routes advertised to R4 with IPv6 global address of " "R2 ( R2-R4) link")

    llip = get_glipv6(topo, "r2", "r4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r4"

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Remove advertised route from R1")

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

    protocol = "bgp"
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    verify_nh_for_prefix = {
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
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, expected=False
    )
    assert bgp_rib is not True, (
        "Testcase {} : Failed \n Route still present"
        "in BGP RIB. Error: {}".format(tc_name, bgp_rib)
    )
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_prefix,
        next_hop=llip,
        protocol=protocol,
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n Route still "
        "present in RIB. Error: {}".format(tc_name, result)
    )

    step("On R2 global table route route installed with IPv4 nexthop ")

    llip = get_glipv6(topo, "r3", "r2", addr_type="ipv4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    verify_nh_for_prefix = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip,}
            ]
        }
    }

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("IPv4 routes advertised to R4 with IPv6 global address of " "R2 ( R2-R4) link")

    llip = get_glipv6(topo, "r2", "r4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r4"

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Re advertise the same prefix again from r1")
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

    step("Remove advertised route from R3")

    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
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
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes installed on R2 BGP table with IPv6 R1 ( R1-R2) "
        "link-local nexthop , verify using show ip bgp vrd RED "
        "show ip route vrf RED"
    )

    protocol = "bgp"
    llip = get_llip(topo, "r1", "r2-link0", vrf="RED")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r2"
    verify_nh_for_prefix = {
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

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes advertised to R4 with IPv6 link-local "
        "address of R2 ( R2-R4) link "
    )

    llip = get_llip(topo, "r2", "r4")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    verify_nh_for_prefix = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip}
            ]
        }
    }

    dut = "r4"

    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_prefix, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
