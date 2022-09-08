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
    write_test_footer,
    get_frr_ipv6_linklocal,
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
BGP_CONVERGENCE_TIMEOUT = 10
TOPOOLOGY = """
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
"""

TESTCASES = """
TC6. Verify BGP speaker advertise IPv4 route to peer only if "extended
 nexthop capability" is negotiated
TC7. Verify ipv4 route nexthop updated dynamically when in route-map is
 applied on receiving BGP peer
TC8. Verify IPv4 routes advertise using "redistribute static" and "network
 command" are received on EBGP peer with IPv6 nexthop
TC10. Verify IPv4 routes are deleted after un-configuring of "network
command" and "redistribute static knob"
TC18. Verify IPv4 routes installed with correct nexthop after deactivate
 and activate neighbor from address family
TC19. Verify IPv4 route ping is working fine and nexhop installed in kernel
 as IPv4 link-local address
TC24. Verify IPv4 prefix-list routes advertised to peer when prefix -list
 applied in out direction
TC27. Verify IPv4 routes are intact after BGPd process restart
TC30. Verify Ipv4 route installed with correct next hop when same route
 is advertised via IPV4 and IPv6 BGP peers
TC32. Verify IPv4 route received with IPv6 nexthop can be advertised to
 another IPv4 BGP peers
 """


def setup_module(mod):
    """Set up the pytest environment."""
    global topo, ADDR_TYPES

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/rfc5549_ebgp_nbr.json".format(CWD)
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
    """Teardown the pytest environment."""
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


def test_ext_nh_cap_red_static_network_ebgp_peer_tc8_p0(request):
    """

    Test exted capability nexthop with route map in.

    Verify IPv4 routes advertise using "redistribute static" and
    "network command" are received on EBGP peer with IPv6 nexthop
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step("Configure IPv6 EBGP session between R1 and R2 with global" " IPv6 address")
    reset_config_on_routers(tgen)

    step(
        "Enable capability extended-nexthop on the nbr from both the  "
        " routers Activate same IPv6 nbr from IPv4 unicast family"
    )
    step(
        " Configure 2 IPv4 static  "
        "routes on R1 (nexthop for static route exists on different  "
        "link of R0"
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
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for rte in range(0, NO_OF_RTES):
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"][rte],
                        "no_of_ip": 1,
                        "next_hop": NEXT_HOP["ipv6"][rte],
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
                "local_as": "100",
                "default_ipv4_unicast": "True",
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

    glip = get_llip("r1", "r2-link0")
    assert glip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 and IPv6 routes advertised using static and network command "
        "are received on R2 BGP & routing table , verify using show ip bgp "
        "show ip route for IPv4 routes and show bgp ipv6,show ipv6 routes "
        "for IPv6 routes ."
    )

    dut = "r2"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        # verify the routes with nh as ext_nh
        verify_nh_for_static_rtes = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type][0],
                        "no_of_ip": 2,
                        "next_hop": glip,
                    }
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_static_rtes, next_hop=glip
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_nh_for_static_rtes,
            next_hop=glip,
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify IPv4 routes are installed with IPv6 global nexthop of R1"
        " R1 to R2 connected link"
    )

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": glip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=glip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=glip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)


def test_ext_nh_cap_remove_red_static_network_ebgp_peer_tc10_p1(request):
    """

    Test exted capability nexthop with route map in.

    Verify IPv4 routes are deleted after un-configuring of
    network command and redistribute static knob
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step(
        "Configure IPv6 EBGP session between R1 and R2 with global IPv6"
        " address Enable capability extended-nexthop on the nbr from both"
        " the routers , Activate same IPv6 nbr from IPv4 unicast family"
    )
    step(
        " Configure 2 IPv4 static routes "
        " on R1 nexthop for static route exists on different link of R0"
    )
    reset_config_on_routers(tgen)

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
        "Advertise static routes from IPv4 unicast family and IPv6 unicast"
        " family respectively from R1. Configure loopback on R1 with IPv4 "
        "address Advertise loobak from IPv4 unicast family using network "
        "command from R1"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "local_as": "100",
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
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 and IPv6 routes advertised using static and network command are"
        " received on R2 BGP and routing table , verify using show ip bgp"
        " show ip route for IPv4 routes and show bgp, show ipv6 routes"
        " for IPv6 routes ."
    )

    glipv6 = get_llip("r1", "r2-link0")
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

    step(
        "Verify IPv4 routes are installed with IPv6 global nexthop of R1 "
        " R1 to R2 connected link"
    )
    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "advertise_networks": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": glipv6,
                }
            ]
        }
    }
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=glipv6, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}]
                        }
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # verify the routes with nh as ext_nh
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": glipv6,
                }
            ]
        }
    }

    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glipv6, expected=False
    )
    assert (
        bgp_rib is not True
    ), "Testcase {} : Failed \n Error: Routes still" " present in BGP rib".format(
        tc_name
    )
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_static_rtes,
        next_hop=glipv6,
        protocol=protocol,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error: Routes " "still present in RIB".format(tc_name)

    step(
        "After removing IPv4 routes from redistribute static those routes"
        " are removed from R2, after re-advertising routes which are "
        " advertised using network are still present in the on R2 with "
        " IPv6 global nexthop, verify using show ip bgp and show ip routes"
    )

    verify_nh_for_nw_cmd_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK_CMD_IP,
                    "no_of_ip": 1,
                    "next_hop": glipv6,
                }
            ]
        }
    }

    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_cmd_rtes, next_hop=glipv6, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r1 = {
        "r1": {
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
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(
        tgen,
        "ipv4",
        dut,
        verify_nh_for_nw_cmd_rtes,
        next_hop=glipv6,
        protocol=protocol,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "Error: Routes still present in BGP rib".format(
        tc_name
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
