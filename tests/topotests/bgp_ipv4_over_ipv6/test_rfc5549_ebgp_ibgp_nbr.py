#!/usr/bin/env python

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
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
import pytest
from copy import deepcopy

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    get_frr_ipv6_linklocal,
    write_test_footer,
    verify_rib,
    create_static_routes,
    check_address_types,
    reset_config_on_routers,
    step,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
)
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
topo = None

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
1. Verify Ipv4 route next hop is changed when advertised using
next hop -self command
2. Verify IPv4 route advertised to peer when IPv6 BGP session established
 using peer-group
3. Verify IPv4 routes received with IPv6 nexthop are getting advertised
 to another IBGP peer without changing the nexthop
4. Verify IPv4 routes advertised with correct nexthop when nexthop
unchange is configure on EBGP peers
 """


def setup_module(mod):
    """Set up the pytest environment."""

    global topo
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/rfc5549_ebgp_ibgp_nbr.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
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
    """
    Teardown the pytest environment.

    * `mod`: module name
    """
    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()


def get_llip(onrouter, intf):
    """
    API to get the link local ipv6 address of a particular interface

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
    API to get the global ipv6 address of a particular interface

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
def test_ibgp_to_ibgp_p1(request):
    """

    Test Capability extended nexthop.

    Verify IPv4 routes received with IPv6 nexthop are getting advertised to
    another IBGP peer without changing the nexthop
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    reset_config_on_routers(tgen)
    global topo
    topo23 = deepcopy(topo)
    build_config_from_json(tgen, topo23, save_bkup=False)

    step("Configure IPv6 EBGP session between R1 and R2 with " "global IPv6 address")
    step("Configure IPv6 IBGP session betn R2 & R3 using IPv6 global address")
    step("Enable capability extended-nexthop on both the IPv6 BGP peers")
    step("Activate same IPv6 nbr from IPv4 unicast family")
    step("Enable cap ext nh on r1 and r2 and activate in ipv4 addr family")
    step("Verify bgp convergence as ipv6 nbr is enabled on ipv4 addr family.")

    # verify bgp convergence as ipv6 nbr is enabled on ipv4 addr family.
    bgp_convergence = verify_bgp_convergence(tgen, topo23)
    assert bgp_convergence is True, "Testcase  :Failed \n Error:" " {}".format(
        bgp_convergence
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
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo23, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "IPv4 routes advertised using static and network command are "
        " received on R2 BGP and routing table , "
        "verify using show ip bgp, show ip route for IPv4 routes ."
    )

    gllip = get_llip("r1", "r2-link0")
    assert gllip is not None, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    dut = "r2"
    protocol = "bgp"
    # verify the routes with nh as ext_nh
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": gllip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gllip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r2": {
                                            "activate": "ipv4",
                                            "capability": "extended-nexthop",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3": {
                                            "activate": "ipv4",
                                            "capability": "extended-nexthop",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes installed on R3 with global address without "
        "changing the nexthop ( nexthop should IPv6 link local which is"
        " received from R1)"
    )
    gipv6 = get_glipv6("r1", "r2-link0")
    dut = "r3"
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": gipv6,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gipv6
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    write_test_footer(tc_name)


def test_ext_nh_cap_red_static_network_ibgp_peer_p1(request):
    """

    Test Extended capability next hop, with ibgp peer.

    Verify IPv4 routes advertise using "redistribute static" and
    "network command" are received on EBGP peer with IPv6 nexthop
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    reset_config_on_routers(tgen)
    step(
        " Configure IPv6 EBGP session between R1 & R2 with global IPv6 address"
        " Enable capability extended-nexthop on the nbr from both the routers"
        " Activate same IPv6 nbr from IPv4 unicast family"
    )
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "default_ipv4_unicast": "False",
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r2": {
                                            "capability": "extended-nexthop",
                                            "activate": "ipv4",
                                            "next_hop_self": True,
                                            "activate": "ipv4",
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
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r3": {
                                            "capability": "extended-nexthop",
                                            "activate": "ipv4",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
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

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "default_ipv4_unicast": "False",
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

    gllip = get_llip("r1", "r2-link0")
    assert gllip is not None, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    dut = "r2"
    protocol = "bgp"
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": gllip,
                }
            ]
        }
    }
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": gllip,
                }
            ]
        }
    }

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    gllip = get_glipv6("r2", "r3")
    assert gllip is not None, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    dut = "r3"
    protocol = "bgp"
    # verify the routes with nh as ext_nh
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": gllip,
                }
            ]
        }
    }
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": gllip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=gllip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_peer_group_p1(request):
    """
    Test extended capability next hop with peer groups.

    Verify IPv4 routes received with IPv6 nexthop are getting advertised to
    another IBGP peer without changing the nexthop
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    reset_config_on_routers(tgen)
    global topo
    topo1 = deepcopy(topo)
    step("Configure IPv6 EBGP session between R1 and R2 with " "global IPv6 address")
    step("Configure IPv6 IBGP session betn R2 & R3 using IPv6 global address")
    step("Enable capability extended-nexthop on both the IPv6 BGP peers")
    step("Activate same IPv6 nbr from IPv4 unicast family")
    step("Enable cap ext nh on r1 and r2 and activate in ipv4 addr family")
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "default_ipv4_unicast": "False",
                "peer-group": {
                    "rfc5549": {"capability": "extended-nexthop", "remote-as": "200"}
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link0": {
                                            "activate": "ipv4",
                                            "capability": "extended-nexthop",
                                            "peer-group": "rfc5549",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "default_ipv4_unicast": "False",
                "peer-group": {
                    "rfc5549": {"capability": "extended-nexthop", "remote-as": "100"}
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link0": {
                                            "capability": "extended-nexthop",
                                            "activate": "ipv4",
                                            "peer-group": "rfc5549",
                                        }
                                    }
                                },
                                "r3": {"dest_link": {"r2": {}}},
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"neighbor": {"r2": {"dest_link": {"r3": {}}}}}}
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp convergence as ipv6 nbr is enabled on ipv4 addr family.")
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase  :Failed \n Error:" " {}".format(
        bgp_convergence
    )

    step(" Configure 2 IPv4 static" " routes on R1, Nexthop as different links of R0")
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
                    }
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

    gllip = get_llip("r1", "r2-link0")
    assert gllip is not None, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    dut = "r2"
    protocol = "bgp"
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": gllip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gllip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Enable cap ext nh on r1 and r2 and activate in ipv4 addr family")
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "default_ipv4_unicast": "False",
                "peer-group": {
                    "rfc5549": {"capability": "extended-nexthop", "remote-as": "200"}
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link0": {
                                            "activate": "ipv4",
                                            "capability": "extended-nexthop",
                                            "peer-group": "rfc5549",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "default_ipv4_unicast": "False",
                "peer-group": {
                    "rfc5549": {"capability": "extended-nexthop", "remote-as": "100"}
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link0": {
                                            "capability": "extended-nexthop",
                                            "activate": "ipv4",
                                            "peer-group": "rfc5549",
                                        }
                                    }
                                },
                                "r3": {"dest_link": {"r2": {}}},
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r3 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"neighbor": {"r2": {"dest_link": {"r3": {}}}}}}
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp convergence as ipv6 nbr is enabled on ipv4 addr family.")
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase  :Failed \n Error:" " {}".format(
        bgp_convergence
    )

    step(" Configure 2 IPv4 static" " routes on R1, Nexthop as different links of R0")
    for rte in range(0, NO_OF_RTES):
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
                    }
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

    gllip = get_llip("r1", "r2-link0")
    assert gllip is not None, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    dut = "r2"
    protocol = "bgp"
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": gllip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gllip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
