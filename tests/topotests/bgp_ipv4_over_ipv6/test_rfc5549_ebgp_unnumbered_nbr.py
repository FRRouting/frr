#!/usr/bin/env python

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
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
import ipaddr
from copy import deepcopy
from re import search as re_search

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../../"))

from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo

from lib.common_config import (
    write_test_header,
    start_topology,
    create_route_maps,
    write_test_footer,
    start_router,
    stop_router,
    verify_rib,
    create_static_routes,
    check_address_types,
    reset_config_on_routers,
    step,
    shutdown_bringup_interface,
    create_interfaces_cfg,
    get_frr_ipv6_linklocal,
)
from lib.topolog import logger
from lib.bgp import clear_bgp, verify_bgp_convergence, create_router_bgp, verify_bgp_rib

from lib.topojson import build_topo_from_json, build_config_from_json

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/rfc5549_ebgp_unnumbered_nbr.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

# Global variables
NO_OF_RTES = 2
NETWORK_CMD_IP = "1.0.1.17/32"
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
ADDR_TYPES = check_address_types()
TOPOOLOGY = """
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
"""

TESTCASES = """
1. Verify IPv4 routes are advertised when IPv6 EBGP loopback session
 established using Unnumbered interface
2. Verify IPv4 routes are installed with correct nexthop after
shut / no shut of nexthop and BGP peer interfaces
3. Verify IPv4 routes are intact after stop and start the FRR services
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
    global topo, ADDR_TYPES

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


def teardown_module():
    """Teardown the pytest environment."""
    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()


def get_llip(onrouter, intf):
    """
    API to get the link local ipv6 address of a perticular interface

    Parameters
    ----------
    * `fromnode`: Source node
    * `tonode` : interface for which link local ip needs to be returned.

    Usage
    -----
    result = get_llip('r1', 'r2-link0')

    Returns
    -------
    1) link local ipv6 address from the interface.
    2) errormsg - when link local ip not found.
    """
    tgen = get_topogen()
    intf = topo["routers"][onrouter]["links"][intf]["interface"]
    llip = get_frr_ipv6_linklocal(tgen, onrouter, intf)
    if llip:
        logger.info("llip ipv6 address to be set as NH is %s", llip)
        return llip
    return None


def get_glipv6(onrouter, intf):
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
    glipv6 = (topo["routers"][onrouter]["links"][intf]["ipv6"]).split("/")[0]
    if glipv6:
        logger.info("Global ipv6 address to be set as NH is %s", glipv6)
        return glipv6
    return None


# ##################################
# Test cases start here.
# ##################################


def test_unnumbered_loopback_ebgp_nbr_p0(request):
    """

    Test extended capability nexthop with un numbered ebgp.

    Verify IPv4 routes are advertised when IPv6 EBGP loopback
    session established using Unnumbered interface
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    reset_config_on_routers(tgen)

    step("Configure IPv6 EBGP Unnumbered session between R1 and R2")
    step("Enable capability extended-nexthop on both the IPv6 BGP peers")
    step("Activate same IPv6 nbr from IPv4 unicast family")
    step("Enable cap ext nh on r1 and r2 and activate in ipv4 addr family")
    step("Verify bgp convergence as ipv6 nbr is enabled on ipv4 addr family.")

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step(" Configure 5 IPv4 static" " routes on R1, Nexthop as different links of R0")
    for rte in range(0, NO_OF_RTES):
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][rte],
                        "no_of_ip": 1,
                        "next_hop": NEXT_HOP["ipv4"][rte],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise static routes from IPv4 unicast family and IPv6 "
        "unicast family respectively from R1 using red static cmd "
        "Advertise loopback from IPv4 unicast family using network command "
        "from R1"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
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
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "IPv4 routes advertised using static and network command are "
        " received on R2 BGP and routing table , "
        "verify using show ip bgp, show ip route for IPv4 routes ."
    )

    llip = get_llip("r1", "r2-link0")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    dut = "r2"
    protocol = "bgp"
    for rte in range(0, NO_OF_RTES):
        # verify the routes with nh as ext_nh
        verify_nh_for_static_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK["ipv4"][rte], "no_of_ip": 1, "next_hop": llip}
                ]
            }
        }
        """         interface_list = ['r1-link0','r1-link1']
        nh_list =[]
        for i in range(NO_OF_RTES):
            nh_list.append(topo['routers']['r2']['links'][i][
                'interface']) """
        bgp_rib = verify_rib(
            tgen,
            "ipv4",
            dut,
            # verify_nh_for_static_rtes, next_hop='r2-r1-eth0')
            verify_nh_for_static_rtes,
            next_hop=llip,
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen,
            "ipv4",
            dut,
            verify_nh_for_static_rtes,
            next_hop=llip,
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    # verify the routes with nh as ext_nh
    verify_nh_for_nw_rtes = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip}
            ]
        }
    }

    bgp_rib = verify_rib(
        tgen,
        "ipv4",
        dut,
        # verify_nh_for_nw_rtes, next_hop='r2-r1-eth0')
        verify_nh_for_nw_rtes,
        next_hop=llip,
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r1")
    stop_router(tgen, "r2")
    start_router(tgen, "r1")
    start_router(tgen, "r2")
    step(
        "After stop/start of FRR services , verify session up and routes "
        "came up fine ,nh is proper using show bgp & show ipv6 route on R2 "
    )
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    llip = get_llip("r1", "r2-link0")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # verify the routes with nh as ext_nh
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
        tgen,
        "ipv4",
        dut,
        # verify_nh_for_static_rtes, next_hop='r2-r1-eth0')
        verify_nh_for_static_rtes,
        next_hop=llip,
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    verify_nh_for_nw_rtes = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip}
            ]
        }
    }
    bgp_rib = verify_rib(
        tgen,
        "ipv4",
        dut,
        # verify_nh_for_nw_rtes, next_hop='r2-r1-eth0')
        verify_nh_for_nw_rtes,
        next_hop=llip,
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    write_test_footer(tc_name)


def test_restart_frr_p2(request):
    """

    Test extended capability nexthop , restart frr.

    Verify IPv4 routes are intact after stop and start the FRR services
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    reset_config_on_routers(tgen)
    step("Configure IPv6 EBGP Unnumbered session between R1 and R2")
    step("Enable capability extended-nexthop on both the IPv6 BGP peers")
    step("Activate same IPv6 nbr from IPv4 unicast family")
    step("Enable cap ext nh on r1 and r2 and activate in ipv4 addr family")
    step("Verify bgp convergence as ipv6 nbr is enabled on ipv4 addr family.")
    reset_config_on_routers(tgen)
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step(" Configure 5 IPv4 static" " routes on R1, Nexthop as different links of R0")
    for rte in range(0, NO_OF_RTES):
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][rte],
                        "no_of_ip": 1,
                        "next_hop": NEXT_HOP["ipv4"][rte],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise static routes from IPv4 unicast family and IPv6 "
        "unicast family respectively from R1 using red static cmd "
        "Advertise loopback from IPv4 unicast family using network command "
        "from R1"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
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
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "IPv4 routes advertised using static and network command are "
        " received on R2 BGP and routing table , "
        "verify using show ip bgp, show ip route for IPv4 routes ."
    )

    llip = get_llip("r1", "r2-link0")
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
                }
            ]
        }
    }
    bgp_rib = verify_rib(tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    verify_nh_for_nw_rtes = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip}
            ]
        }
    }

    bgp_rib = verify_rib(tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r1")
    stop_router(tgen, "r2")
    start_router(tgen, "r1")
    start_router(tgen, "r2")

    step(
        "After stop/start of FRR services , verify session up and routes "
        "came up fine ,nh is proper using show bgp & show ipv6 route on R2 "
    )
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    llip = get_llip("r1", "r2-link0")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # verify the routes with nh as ext_nh
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": 1, "next_hop": llip}
            ]
        }
    }
    bgp_rib = verify_rib(tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # verify the routes with nh as ext_nh
    verify_nh_for_nw_rtes = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": llip}
            ]
        }
    }
    bgp_rib = verify_rib(tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=llip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=llip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
