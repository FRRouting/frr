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
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, create_router_bgp, verify_bgp_rib
from lib.topojson import build_topo_from_json, build_config_from_json
from rfc5549_common_lib import *

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/rfc5549_vrf_red_green_ebgp_nbr.json".format(CWD)
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
        pytest.skip(tgen.errors)
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
    llip = get_glipv6(topo, "r2", "r3", addr_type="ipv4")
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
